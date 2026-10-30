//! Real paused-child rollbacks with synthetic selected-account material.

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use coding_agent_manager_lib::account_authority::StoredAccountRegistry;
use coding_agent_manager_lib::model::{AuthKind, StoredAccountMaterial};
use coding_agent_manager_lib::paths::stored_accounts_path;
use coding_agent_manager_lib::providers::launch_lifecycle::{LaunchFinalization, LaunchPhase};

use crate::account_authority::authority_socket_config::CamAuthoritySocketTestGuard;
use crate::external_agent::{
    run_codex_batch_process, run_codex_interactive_process, run_cursor_managed_process,
    CursorManagedStart, GrokAcpLimits, GrokAcpTurn, ValidatedCodexAuth,
};
use crate::process_runner::{
    with_unproven_start_gate_wait_for_test, ContainmentPolicy, EnvironmentMode,
    ProcessCancellation, ProcessRunError, ProcessSpec,
};

fn fixture(provider: &str) -> Result<(tempfile::TempDir, StoredAccountRegistry)> {
    // Source trust checks require ancestry below the isolated runner's private HOME.
    let root = tempfile::Builder::new()
        .prefix("maco-gate-rollback-")
        .tempdir_in(std::env::var_os("HOME").context("isolated runner HOME")?)?;
    let data = root.path().join("data");
    fs::create_dir(&data)?;
    let registry = StoredAccountRegistry::new(stored_accounts_path(&data));
    for account in ["work", "personal"] {
        registry.begin_add(
            provider,
            account,
            account,
            AuthKind::OAuth,
            StoredAccountMaterial::VendorHome,
        )?;
        registry.complete_add(provider, account)?;
    }
    registry.select_complete(provider, "work")?;
    Ok((root, registry))
}

fn target(directory: &Path) -> ProcessSpec {
    ProcessSpec::direct(
        "synthetic unreleased target",
        "/bin/sh",
        ["-c", "printf released > target-ran"],
        directory,
        1024,
    )
    .with_environment(EnvironmentMode::ClearAndSet(BTreeMap::from([
        (
            "PATH".into(),
            "/usr/bin:/bin:/run/current-system/sw/bin".into(),
        ),
        ("LANG".into(), "C.UTF-8".into()),
    ])))
    .with_containment(ContainmentPolicy::Required)
    .with_timeout(Some(Duration::from_secs(60)))
}

fn assert_rollback(error: &ProcessRunError, unproven: bool) {
    let evidence = error.pre_release_rollback_evidence().unwrap_or_else(|| {
        panic!("the actual start-gate callback must refuse after child attachment: {error:?}")
    });
    assert_eq!(evidence.process_tree.is_verified_empty(), !unproven);
}

fn codex_gate(interactive: bool) -> Result<()> {
    let _socket = CamAuthoritySocketTestGuard::install(None);
    for unproven in [false, true] {
        let (root, registry) = fixture("codex-cli")?;
        let authority = crate::account_authority::codex::acquire_from_registry_for_test(&registry)?;
        let home = authority.managed_codex_home().to_path_buf();
        fs::create_dir_all(&home)?;
        fs::set_permissions(&home, fs::Permissions::from_mode(0o700))?;
        let path = home.join("auth.json");
        fs::write(&path, b"synthetic-selected-auth")?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        let auth = ValidatedCodexAuth::load_for_managed_authority(authority)?;
        let handle = auth
            .managed_authority
            .as_ref()
            .unwrap()
            .launch
            .custody()
            .lifecycle();
        fs::write(path, b"synthetic-selected-auth-changed-before-gate")?;
        let cancellation = ProcessCancellation::new();
        let run = || {
            if interactive {
                run_codex_interactive_process(
                    target(root.path()),
                    &cancellation,
                    Some(&auth),
                    |_| -> Result<(), String> { panic!("refused target reached its protocol") },
                )
                .map(|_| ())
            } else {
                run_codex_batch_process(target(root.path()), &cancellation, Some(&auth)).map(|_| ())
            }
        };
        let error = crate::process_runner::start_gate_fixture_tests::with_paused_child(|| {
            if unproven {
                with_unproven_start_gate_wait_for_test(run)
            } else {
                run()
            }
        })
        .expect_err("selected Codex auth drift must refuse its paused child");
        assert_rollback(&error, unproven);
        assert!(error
            .to_string()
            .contains("selected Codex auth source or CAM identity changed before release"));
        assert!(!root.path().join("target-ran").exists());
        assert_eq!(
            handle.snapshot().phase,
            if unproven {
                LaunchPhase::ExitUnknown
            } else {
                LaunchPhase::Finalized(LaunchFinalization::Refused)
            }
        );
        registry.select_complete("codex-cli", "personal")?;
        assert!(registry.begin_delete("codex-cli", "work").is_err());
        drop(auth); // Confirmed refusal releases only after the outer authority drains.
        assert_eq!(
            registry.begin_delete("codex-cli", "work").is_err(),
            unproven
        );
    }
    Ok(())
}

#[test]
fn codex_batch_gate_refusal_releases_reaped_custody_and_retains_unproven_wait() -> Result<()> {
    codex_gate(false)
}

#[test]
fn codex_interactive_gate_refusal_releases_reaped_custody_and_retains_unproven_wait() -> Result<()>
{
    codex_gate(true)
}

#[test]
fn cursor_parent_gate_refusal_releases_reaped_custody_and_retains_unproven_wait() -> Result<()> {
    use coding_agent_manager_lib::providers::cursor::CursorAdapter;
    let _socket = CamAuthoritySocketTestGuard::install(None);
    for unproven in [false, true] {
        let (root, registry) = fixture("cursor")?;
        let data = registry.metadata_path().parent().unwrap();
        let home = data.join("accounts/cursor/work");
        let config = home.join(".cursor");
        fs::create_dir_all(&config)?;
        for directory in [&home, &config] {
            fs::set_permissions(directory, fs::Permissions::from_mode(0o700))?;
        }
        let auth = config.join("auth.json");
        fs::write(&auth, b"synthetic-cursor-auth")?;
        fs::set_permissions(auth, fs::Permissions::from_mode(0o600))?;
        let adapter = CursorAdapter::with_home(root.path())
            .with_data_dir(data)
            .with_working_directory(root.path());
        let authority =
            crate::account_authority::cursor::acquire_from_registry_for_test(&registry, &adapter)?;
        let handle = authority.launch.custody().lifecycle();
        let cancellation = ProcessCancellation::new();
        let turn = GrokAcpTurn {
            cwd: root.path().display().to_string(),
            prompt: "synthetic".into(),
            requested_model: None,
            requested_effort: None,
            output_schema: None,
        };
        let limits = GrokAcpLimits::from_parent_operation_timeout(Duration::from_secs(60))?;
        let mut parent = None;
        let invalid_workspace = root.path().join("missing-workspace");
        let mut run = || {
            run_cursor_managed_process(
                target(root.path()),
                &cancellation,
                CursorManagedStart {
                    workspace: &invalid_workspace,
                    assigned_paths: Vec::new(),
                    deadline: Instant::now() + Duration::from_secs(60),
                    parent: &mut parent,
                },
                &turn,
                limits,
                Some(&mut authority.launch.custody()),
            )
        };
        let error = crate::process_runner::start_gate_fixture_tests::with_paused_child(|| {
            if unproven {
                with_unproven_start_gate_wait_for_test(run)
            } else {
                run()
            }
        })
        .expect_err("managed parent setup must refuse its paused child");
        assert_rollback(&error, unproven);
        assert!(error
            .to_string()
            .contains("managed Cursor parent setup failed"));
        assert!(parent.is_none());
        assert!(!root.path().join("target-ran").exists());
        assert_eq!(
            handle.snapshot().phase,
            if unproven {
                LaunchPhase::ExitUnknown
            } else {
                LaunchPhase::Finalized(LaunchFinalization::Refused)
            }
        );
        registry.select_complete("cursor", "personal")?;
        assert!(registry.begin_delete("cursor", "work").is_err());
        drop(authority);
        assert_eq!(registry.begin_delete("cursor", "work").is_err(), unproven);
    }
    Ok(())
}
