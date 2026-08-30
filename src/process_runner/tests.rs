use super::*;

#[cfg(target_os = "linux")]
fn program_visibility_sandbox(workspace_root: &Path) -> ResolvedSystemdSandbox {
    ResolvedSystemdSandbox {
        kind: SideEffectConfinementProfileKind::ExternalCodex,
        workspace_root: workspace_root.to_path_buf(),
        current_dir: workspace_root.to_path_buf(),
        workspace_access: WorkspaceAccess::ReadWrite,
        visible_read_only_roots: Vec::new(),
        visible_read_only_files: Vec::new(),
        visible_read_write_roots: Vec::new(),
        visible_read_write_files: Vec::new(),
        external_codex_writable_file_capabilities: Vec::new(),
        external_grok_read_only_file_capabilities: Vec::new(),
        writable_artifact_roots: Vec::new(),
        hidden_roots: Vec::new(),
        isolated_host_view: false,
        resource_limits: ProcessResourceLimits::default(),
        path_identities: Vec::new(),
        mount_checks: Vec::new(),
    }
}

#[cfg(target_os = "linux")]
#[test]
fn sandbox_program_visibility_rejects_private_tmp_and_hidden_roots() {
    let mut sandbox = program_visibility_sandbox(Path::new("/opt/maco/workspace"));
    sandbox.hidden_roots = vec![PathBuf::from("/srv/private")];
    for program in [
        Path::new("/tmp/target/debug/probe"),
        Path::new("/var/tmp/target/debug/probe"),
        Path::new("/srv/private/bin/probe"),
    ] {
        let error = sandbox
            .validate_program_visibility(program)
            .expect_err("hidden program path must be rejected");
        let (failure, target_process_started) =
            environment_failure_from_source(&error).expect("typed environment failure");
        assert_eq!(
            failure.category,
            crate::external_agent::EnvironmentFailureCategory::SandboxUnavailable
        );
        assert!(!target_process_started);
        assert!(failure.summary.contains(&program.display().to_string()));
    }

    assert!(sandbox
        .validate_program_visibility(Path::new("/opt/maco/bin/probe"))
        .is_ok());
    assert!(sandbox
        .validate_program_visibility(Path::new("/tmp-adjacent/bin/probe"))
        .is_ok());
}

#[cfg(target_os = "linux")]
#[test]
fn sandbox_program_visibility_accepts_explicit_private_tmp_bindings() {
    let workspace_program = Path::new("/tmp/workspace/bin/probe");
    let mut sandbox = program_visibility_sandbox(Path::new("/tmp/workspace"));
    assert!(sandbox
        .validate_program_visibility(workspace_program)
        .is_ok());

    sandbox.workspace_root = PathBuf::from("/opt/maco/workspace");
    sandbox.current_dir = sandbox.workspace_root.clone();
    let read_only_root_program = Path::new("/tmp/read-only-tools/bin/probe");
    sandbox
        .visible_read_only_roots
        .push(PathBuf::from("/tmp/read-only-tools"));
    assert!(sandbox
        .validate_program_visibility(read_only_root_program)
        .is_ok());

    let read_write_root_program = Path::new("/var/tmp/read-write-tools/bin/probe");
    sandbox
        .visible_read_write_roots
        .push(PathBuf::from("/var/tmp/read-write-tools"));
    assert!(sandbox
        .validate_program_visibility(read_write_root_program)
        .is_ok());

    let artifact_program = Path::new("/tmp/artifacts/bin/probe");
    sandbox
        .writable_artifact_roots
        .push(PathBuf::from("/tmp/artifacts"));
    assert!(sandbox
        .validate_program_visibility(artifact_program)
        .is_ok());

    let read_only_file = PathBuf::from("/var/tmp/exact-read-only-probe");
    sandbox.visible_read_only_files.push(read_only_file.clone());
    assert!(sandbox.validate_program_visibility(&read_only_file).is_ok());

    let read_write_file = PathBuf::from("/tmp/exact-read-write-probe");
    sandbox
        .visible_read_write_files
        .push(read_write_file.clone());
    assert!(sandbox
        .validate_program_visibility(&read_write_file)
        .is_ok());

    let hidden_program = Path::new("/tmp/workspace/hidden/probe");
    sandbox.workspace_root = PathBuf::from("/tmp/workspace");
    sandbox
        .hidden_roots
        .push(PathBuf::from("/tmp/workspace/hidden"));
    let hidden_error = sandbox
        .validate_program_visibility(hidden_program)
        .expect_err("hidden roots must override an overlapping workspace bind");
    assert!(hidden_error.to_string().contains("sandbox.hidden_roots"));
}

#[cfg(target_os = "linux")]
#[test]
fn sandbox_program_visibility_checks_invocation_and_canonical_symlink_paths() {
    use std::os::unix::{fs::symlink, fs::PermissionsExt};

    let private_tmp = tempfile::Builder::new()
        .prefix("maco-private-tmp-link-")
        .tempdir_in("/tmp")
        .expect("private tmp symlink directory");
    let visible_target_root = tempfile::Builder::new()
        .prefix("maco-visible-target-")
        .tempdir_in("/dev/shm")
        .expect("visible target directory");
    let visible_target = visible_target_root.path().join("probe");
    fs::write(&visible_target, b"#!/bin/sh\nexit 0\n").expect("visible target");
    fs::set_permissions(&visible_target, fs::Permissions::from_mode(0o755))
        .expect("visible target permissions");
    let hidden_invocation = private_tmp.path().join("probe");
    symlink(&visible_target, &hidden_invocation).expect("symlink hidden invocation");
    let spec = ProcessSpec::direct(
        "hidden invocation",
        &hidden_invocation,
        Vec::<OsString>::new(),
        Path::new("/"),
        128,
    );
    let paths = resolved_direct_program_paths(&spec, Path::new("/"))
        .expect("resolve hidden invocation and target");
    assert_eq!(paths.first(), Some(&hidden_invocation));
    assert_eq!(paths.get(1), Some(&visible_target));
    let sandbox = program_visibility_sandbox(Path::new("/opt/maco/workspace"));
    assert!(sandbox.validate_program_visibility(&paths[0]).is_err());
    assert!(sandbox.validate_program_visibility(&paths[1]).is_ok());

    let hidden_target_root = tempfile::Builder::new()
        .prefix("maco-hidden-target-")
        .tempdir_in("/var/tmp")
        .expect("hidden target directory");
    let hidden_target = hidden_target_root.path().join("probe");
    fs::write(&hidden_target, b"#!/bin/sh\nexit 0\n").expect("hidden target");
    fs::set_permissions(&hidden_target, fs::Permissions::from_mode(0o755))
        .expect("hidden target permissions");
    let visible_invocation_root = tempfile::Builder::new()
        .prefix("maco-visible-link-")
        .tempdir_in("/dev/shm")
        .expect("visible symlink directory");
    let visible_invocation = visible_invocation_root.path().join("probe");
    symlink(&hidden_target, &visible_invocation).expect("symlink to hidden target");
    let spec = ProcessSpec::direct(
        "hidden target",
        &visible_invocation,
        Vec::<OsString>::new(),
        Path::new("/"),
        128,
    );
    let paths = resolved_direct_program_paths(&spec, Path::new("/"))
        .expect("resolve visible invocation and hidden target");
    assert!(sandbox.validate_program_visibility(&paths[0]).is_ok());
    assert_eq!(paths.get(1), Some(&hidden_target));
    assert!(sandbox.validate_program_visibility(&paths[1]).is_err());
}

#[cfg(target_os = "linux")]
#[test]
fn systemd_namespace_exit_classifier_is_typed_and_corroboration_aware() {
    use std::os::unix::process::ExitStatusExt;

    let program = Path::new("/tmp/maco-target/debug/probe");
    let corroborated = classify_systemd_namespace_failure(
        ExitStatus::from_raw(226 << 8),
        "Failed at step NAMESPACE spawning child",
        program,
    )
    .expect("226 with NAMESPACE must be typed");
    assert_eq!(
        corroborated.category,
        crate::external_agent::EnvironmentFailureCategory::SandboxUnavailable
    );
    assert!(corroborated.summary.contains("226/NAMESPACE"));
    assert!(corroborated.summary.contains("also reported NAMESPACE"));

    let uncorroborated = classify_systemd_namespace_failure(
        ExitStatus::from_raw(226 << 8),
        "transient unit failed",
        program,
    )
    .expect("226 without NAMESPACE output must still be typed");
    assert!(uncorroborated.summary.contains("did not repeat NAMESPACE"));
    assert!(classify_systemd_namespace_failure(
        ExitStatus::from_raw(17 << 8),
        "NAMESPACE",
        program,
    )
    .is_none());

    let typed = process_ownership_error(
        "sandbox probe".to_string(),
        program.display().to_string(),
        systemd_launcher_exit_error(
            ExitStatus::from_raw(226 << 8),
            "Failed at step NAMESPACE spawning child",
            Some(program),
            "before target PID publication",
        ),
    );
    assert!(matches!(
        &typed,
        ProcessRunError::EnvironmentFailure {
            failure,
            target_process_started: false,
            ..
        } if failure.category
            == crate::external_agent::EnvironmentFailureCategory::SandboxUnavailable
    ));
    assert!(typed.to_string().contains(&program.display().to_string()));

    let unrelated = process_ownership_error(
        "sandbox probe".to_string(),
        program.display().to_string(),
        systemd_launcher_exit_error(
            ExitStatus::from_raw(17 << 8),
            "NAMESPACE",
            Some(program),
            "before target PID publication",
        ),
    );
    assert!(matches!(
        unrelated,
        ProcessRunError::ProcessOwnership { .. }
    ));
}

#[cfg(target_os = "linux")]
#[test]
fn sandbox_environment_failure_message_names_cause_and_program_path() {
    let program = Path::new("/tmp/maco-target/debug/probe");
    let sandbox = program_visibility_sandbox(Path::new("/opt/maco/workspace"));
    let source = sandbox
        .validate_program_visibility(program)
        .expect_err("PrivateTmp-hidden program must fail preflight");
    let error = containment_setup_error(
        "hostile scope probe".to_string(),
        program.display().to_string(),
        source,
    );
    let rendered = error.to_string();
    assert!(rendered.contains("sandbox environment is unavailable"));
    assert!(rendered.contains("PrivateTmp=yes"));
    assert!(rendered.contains(&program.display().to_string()));
    assert!(!is_verified_backend_unavailable(&error));
}

#[cfg(target_os = "linux")]
#[test]
fn missing_delegated_user_manager_is_a_typed_pre_spawn_environment_failure() {
    let source =
        delegated_systemd_user_manager_cgroup("0::/system.slice/hosted-compute-agent.service\n")
            .expect_err("hosted-runner system cgroup must not satisfy strict containment");
    let error = containment_setup_error(
        "hosted runner containment probe".to_string(),
        "/usr/bin/true".to_string(),
        source,
    );

    assert!(matches!(
        &error,
        ProcessRunError::EnvironmentFailure {
            failure,
            target_process_started: false,
            ..
        } if failure.category
            == crate::external_agent::EnvironmentFailureCategory::SandboxUnavailable
            && failure.summary
                == "current cgroup /system.slice/hosted-compute-agent.service is not inside a delegated systemd user manager"
    ));
    assert!(error.is_missing_delegated_user_manager());
    assert!(is_verified_backend_unavailable(&error));
}

#[cfg(target_os = "linux")]
#[test]
fn delegated_user_manager_cgroup_detection_remains_exact() {
    assert_eq!(
        delegated_systemd_user_manager_cgroup(
            "0::/user.slice/user-1000.slice/user@1000.service/app.slice/maco.scope\n",
        )
        .expect("delegated user manager"),
        PathBuf::from("/user.slice/user-1000.slice/user@1000.service")
    );
    assert!(
        delegated_systemd_user_manager_cgroup("1:name=systemd:/user.slice\n")
            .expect_err("cgroup v1 must remain unsupported")
            .to_string()
            .contains("unified cgroup v2")
    );
}

#[cfg(unix)]
fn assert_process_not_executable(pid: &str, context: &str) {
    let process_state = Command::new("ps")
        .args(["-o", "stat=", "-p", pid.trim()])
        .output()
        .unwrap_or_else(|error| panic!("inspect {context} process state: {error}"));
    if process_state.status.success() {
        let state = String::from_utf8_lossy(&process_state.stdout);
        assert!(
            matches!(state.trim().as_bytes().first(), Some(b'Z' | b'X')),
            "{context} remained executable after owned lifecycle completion: {state:?}"
        );
    }
}

#[cfg(unix)]
fn assert_process_gone(pid: &str, context: &str) {
    let pid = pid
        .trim()
        .parse::<libc::pid_t>()
        .unwrap_or_else(|error| panic!("parse {context} pid: {error}"));
    // Reaping is the behavior under test, so this remains a real-time liveness fuse. Thirty
    // seconds is deliberately much wider than the three-second operation contract below;
    // expiry means the PID remained allocated, not that ordinary cleanup was slightly late.
    let deadline = Instant::now()
        .checked_add(Duration::from_secs(30))
        .expect("representable process-reaping deadline");
    loop {
        // SAFETY: signal 0 probes whether the captured PID still exists without delivering a
        // signal. A zombie must continue to return success here and therefore cannot pass.
        if unsafe { libc::kill(pid, 0) } == -1 {
            let error = std::io::Error::last_os_error();
            assert_eq!(
                error.raw_os_error(),
                Some(libc::ESRCH),
                "probe {context} existence: {error}"
            );
            break;
        }
        assert!(
            Instant::now() < deadline,
            "{context} PID still existed after the process-reaping liveness margin"
        );
        thread::sleep(POLL_INTERVAL);
    }
}

#[cfg(unix)]
#[test]
fn nonpublishable_trusted_compatibility_interactive_session_round_trips() {
    let temp = tempfile::tempdir().expect("tempdir");
    let spec = ProcessSpec::direct(
            "interactive JSONL child",
            PathBuf::from("/bin/sh"),
            [
                OsString::from("-c"),
                OsString::from(
                    "IFS= read -r request && test \"$request\" = '{\"request\":1}' && printf '%s\\n' '{\"response\":1}'",
                ),
            ],
            temp.path(),
            1024,
        )
        .with_stdin_limit(1024)
        .with_timeout(Some(Duration::from_secs(5)))
        .with_containment(ContainmentPolicy::TrustedBestEffort);
    let result = run_process_interactive(spec, &ProcessCancellation::new(), |session| {
        session.send_line(br#"{"request":1}"#)?;
        let mut response = Vec::new();
        let read = session.receive_line(Duration::from_secs(1), 1024, &mut response)?;
        Ok((read, response))
    })
    .expect("run contained interactive child");

    let (read, response) = result.interaction.expect("interactive exchange");
    assert_eq!(read, InteractiveProcessRead::Line);
    assert_eq!(response, br#"{"response":1}"#);
    assert!(result.process.status.is_some_and(|status| status.success()));
    assert!(matches!(
        result.process.process_tree,
        ProcessTreeEvidence::TrustedBestEffort(ContainmentBackend::UnixProcessGroup)
    ));
}

#[cfg(unix)]
#[test]
fn nonpublishable_trusted_compatibility_interactive_rejects_unframed_input() {
    let temp = tempfile::tempdir().expect("tempdir");
    let spec = ProcessSpec::direct(
        "interactive malformed input child",
        PathBuf::from("/bin/sh"),
        [OsString::from("-c"), OsString::from("read -r _ || true")],
        temp.path(),
        1024,
    )
    .with_stdin_limit(1024)
    .with_timeout(Some(Duration::from_secs(5)))
    .with_containment(ContainmentPolicy::TrustedBestEffort);
    let result = run_process_interactive(spec, &ProcessCancellation::new(), |session| {
        session.send_line(b"two\nframes")
    })
    .expect("run contained interactive child");

    assert!(result
        .interaction
        .is_err_and(|message| message.contains("raw newline")));
    assert!(matches!(
        result.process.process_tree,
        ProcessTreeEvidence::TrustedBestEffort(ContainmentBackend::UnixProcessGroup)
    ));
    assert!(result.process.stdin_error.is_some());
}

#[cfg(unix)]
#[test]
fn nonpublishable_trusted_compatibility_interactive_panic_is_redacted() {
    let temp = tempfile::tempdir().expect("tempdir");
    let spec = ProcessSpec::direct(
        "interactive panicking handler child",
        PathBuf::from("/bin/sh"),
        [OsString::from("-c"), OsString::from("read -r _ || true")],
        temp.path(),
        1024,
    )
    .with_stdin_limit(1024)
    .with_timeout(Some(Duration::from_secs(5)))
    .with_containment(ContainmentPolicy::TrustedBestEffort);
    let result = run_process_interactive::<(), _>(spec, &ProcessCancellation::new(), |_session| {
        panic!("sensitive panic details")
    })
    .expect("runner must preserve process evidence after handler panic");

    assert!(result.interaction.is_err_and(|message| {
        message.contains("handler panicked") && !message.contains("sensitive panic details")
    }));
    assert!(matches!(
        result.process.process_tree,
        ProcessTreeEvidence::TrustedBestEffort(ContainmentBackend::UnixProcessGroup)
    ));
    assert!(result.process.status.is_some());
}

#[cfg(target_os = "linux")]
#[test]
fn verified_contained_interactive_session_proves_tree_and_side_effects() {
    let temp = tempfile::tempdir().expect("tempdir");
    let spec = ProcessSpec::direct(
            "verified interactive JSONL child",
            PathBuf::from("/bin/sh"),
            [
                OsString::from("-c"),
                OsString::from(
                    "IFS= read -r request && test \"$request\" = '{\"request\":1}' && printf '%s\\n' '{\"response\":1}'",
                ),
            ],
            temp.path(),
            1024,
        )
        .with_stdin_limit(1024)
        .with_timeout(Some(CONTENTION_RESILIENT_PROCESS_TEST_TIMEOUT));
    let unit_capture = TestSystemdUnitNameCapture::start();
    let result = run_process_interactive(spec, &ProcessCancellation::new(), |session| {
        session.send_line(br#"{"request":1}"#)?;
        let mut response = Vec::new();
        let read = session.receive_line(Duration::from_secs(1), 1024, &mut response)?;
        Ok((read, response))
    });
    let unit_names = unit_capture.finish();
    let result = match result {
        Ok(result) => result,
        Err(error) if is_verified_backend_unavailable(&error) => {
            report_verified_backend_unavailable_skip(&error, &unit_names);
            return;
        }
        Err(error) => panic!("verified interactive runner failed: {error:?}"),
    };

    let (read, response) = result.interaction.expect("interactive exchange");
    assert_eq!(read, InteractiveProcessRead::Line);
    assert_eq!(response, br#"{"response":1}"#);
    assert!(result.process.status.is_some_and(|status| status.success()));
    assert!(result.process.process_tree.is_verified_empty());
    assert!(result.process.side_effects.is_verified());
    assert!(result.process.safety_evidence_verified());
}

#[test]
fn failed_host_capacity_measurement_falls_back_to_one_lane() {
    let capacity = HostProcessCapacity::from_measurement(Err(io::Error::other("injected failure")));

    assert_eq!(
        capacity.supervisor_children(),
        DEFAULT_NETWORK_BOUND_CHILDREN
    );
    #[cfg(target_os = "linux")]
    assert_eq!(
        capacity.systemd_unit_slots(),
        1 + RESERVED_EXPEDITED_SYSTEMD_SLOTS
    );
}

#[test]
fn measured_host_capacity_is_pinned_for_test_supervise_and_containment() {
    let capacity = HostProcessCapacity::measured();

    assert_eq!(
        capacity.supervisor_children(),
        DEFAULT_NETWORK_BOUND_CHILDREN
    );
    #[cfg(target_os = "linux")]
    assert_eq!(capacity.systemd_unit_slots(), 4);
}

#[test]
fn supervisor_resource_capacity_uses_the_strictest_explicit_host_bound() {
    let capacity = HostProcessCapacity::supervisor_resources(
        Path::new("."),
        HostResourceInputs {
            memory_available_mib: Some(8_192),
            memory_per_child_mib: 1_024,
            fd_available: Some(640),
            fds_per_child: 128,
            disk_available_mib: Some(9_000),
            disk_per_child_mib: 1_000,
            fallback_children: 1,
        },
    );

    assert_eq!(capacity.memory_bound, Some(8));
    assert_eq!(capacity.fd_bound, Some(5));
    assert_eq!(capacity.disk_bound, Some(9));
    assert_eq!(capacity.resolved_children, 5);
}

#[cfg(target_os = "linux")]
#[test]
fn containment_slot_bound_tracks_injected_host_capacity_without_a_fixed_ceiling() {
    for (parallelism, expected_slots) in [(1, 2), (4, 5), (17, 18)] {
        let parallelism = NonZeroUsize::new(parallelism).expect("test parallelism is non-zero");
        let capacity = HostProcessCapacity::from_parallelism(parallelism);
        assert_eq!(capacity.systemd_unit_slots(), expected_slots);
    }
}

#[cfg(target_os = "linux")]
#[test]
fn test_containment_slot_limit_constrains_real_permit_acquisition() {
    let runtime_root = tempfile::tempdir().expect("tempdir");
    let cancellation = ProcessCancellation::new();
    let test_slot_limit = HostProcessCapacity::measured().systemd_unit_slots();
    let mut ordinary_permits = Vec::new();
    for _ in RESERVED_EXPEDITED_SYSTEMD_SLOTS..test_slot_limit {
        ordinary_permits.push(
            SystemdUnitPermit::acquire(runtime_root.path(), None, &cancellation)
                .expect("acquire ordinary test containment permit"),
        );
    }
    assert_eq!(ordinary_permits.len(), 3);

    let expedited_permit = SystemdUnitPermit::acquire(
        runtime_root.path(),
        Some(Instant::now() + Duration::from_millis(500)),
        &cancellation,
    )
    .expect("acquire reserved expedited test containment permit");

    // Real deadline handling is the subject here: all real permit files are held, so the
    // overflow acquire must remain blocked until its caller-supplied deadline. The assertion
    // does not compare elapsed wall time; failure means acquisition escaped the fixed slot set
    // or did not return the required TimedOut result after the deadline became observable.
    let overflow_result = SystemdUnitPermit::acquire(
        runtime_root.path(),
        Some(Instant::now() + Duration::from_secs(2)),
        &cancellation,
    );
    let error = match overflow_result {
        Ok(_) => panic!("test containment limit must prevent acquisition beyond four slots"),
        Err(error) => error,
    };
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert!(
        !runtime_root
            .path()
            .join(format!("maco-process-runner-slot-{}.lock", test_slot_limit))
            .exists(),
        "real acquisition path must not probe a host-derived slot beyond the test limit"
    );

    drop(expedited_permit);
    drop(ordinary_permits);
}

#[test]
fn process_spec_bounds_reject_oversized_vectors_controls_and_streams() {
    let temp = tempfile::tempdir().expect("tempdir");
    let mut profile = StrictOfflineWorkspaceProfile::read_write(temp.path());
    for _ in 0..=MAX_SANDBOX_PATHS_PER_CLASS {
        profile = profile.with_hidden_root(temp.path());
    }
    let oversized_paths = ProcessSpec::direct(
        "bounded paths",
        PathBuf::from("/bin/true"),
        Vec::<OsString>::new(),
        temp.path(),
        128,
    )
    .with_side_effect_confinement(SideEffectConfinementProfile::StrictOfflineWorkspace(
        profile,
    ));
    assert!(validate_process_spec_bounds(&oversized_paths).is_err());

    let controlled_argument = ProcessSpec::direct(
        "bounded args",
        PathBuf::from("/bin/true"),
        vec![OsString::from("line\nfeed")],
        temp.path(),
        128,
    );
    assert!(validate_process_spec_bounds(&controlled_argument).is_err());

    let oversized_capture = ProcessSpec::direct(
        "bounded capture",
        PathBuf::from("/bin/true"),
        Vec::<OsString>::new(),
        temp.path(),
        MAX_REQUIRED_STREAM_BYTES + 1,
    );
    assert!(validate_process_spec_bounds(&oversized_capture).is_err());
}

#[cfg(unix)]
#[test]
fn process_spec_bounds_measure_non_utf8_arguments_without_lossy_shortening() {
    use std::os::unix::ffi::OsStringExt;

    let temp = tempfile::tempdir().expect("tempdir");
    let argument = OsString::from_vec(vec![0xff; MAX_PROCESS_ARGUMENT_BYTES + 1]);
    let spec = ProcessSpec::direct(
        "non UTF-8 bound",
        PathBuf::from("/bin/true"),
        vec![argument],
        temp.path(),
        128,
    );
    assert!(validate_process_spec_bounds(&spec).is_err());
}

#[cfg(target_os = "linux")]
#[test]
fn trusted_network_properties_require_exact_ip_families_without_private_network() {
    let mut properties = BTreeMap::from([
        (
            "RestrictAddressFamilies".to_string(),
            "AF_INET AF_INET6".to_string(),
        ),
        ("PrivateNetwork".to_string(), "no".to_string()),
    ]);
    for kind in [
        SideEffectConfinementProfileKind::TrustedFixedNetwork,
        SideEffectConfinementProfileKind::TrustedCompatibility,
    ] {
        verify_systemd_network_properties(kind, &properties)
            .unwrap_or_else(|error| panic!("exact {kind:?} network properties: {error}"));
    }

    properties.insert(
        "RestrictAddressFamilies".to_string(),
        "AF_INET AF_INET6 AF_NETLINK".to_string(),
    );
    for kind in [
        SideEffectConfinementProfileKind::TrustedFixedNetwork,
        SideEffectConfinementProfileKind::TrustedCompatibility,
    ] {
        assert!(verify_systemd_network_properties(kind, &properties).is_err());
    }
    properties.insert(
        "RestrictAddressFamilies".to_string(),
        "AF_INET AF_INET6".to_string(),
    );
    properties.insert("PrivateNetwork".to_string(), "yes".to_string());
    for kind in [
        SideEffectConfinementProfileKind::TrustedFixedNetwork,
        SideEffectConfinementProfileKind::TrustedCompatibility,
    ] {
        assert!(verify_systemd_network_properties(kind, &properties).is_err());
    }
}

#[cfg(target_os = "linux")]
#[test]
fn strict_offline_network_properties_reject_external_codex_netlink() {
    let mut properties = BTreeMap::from([
        ("RestrictAddressFamilies".to_string(), "AF_UNIX".to_string()),
        ("PrivateNetwork".to_string(), "yes".to_string()),
    ]);
    verify_systemd_network_properties(
        SideEffectConfinementProfileKind::StrictOfflineWorkspace,
        &properties,
    )
    .expect("exact strict offline network properties");

    properties.insert(
        "RestrictAddressFamilies".to_string(),
        "AF_UNIX AF_NETLINK".to_string(),
    );
    assert!(verify_systemd_network_properties(
        SideEffectConfinementProfileKind::StrictOfflineWorkspace,
        &properties,
    )
    .is_err());
}

#[cfg(target_os = "linux")]
#[test]
fn external_codex_network_properties_require_exact_netlink_family() {
    let mut properties = BTreeMap::from([
        (
            "RestrictAddressFamilies".to_string(),
            "AF_NETLINK AF_INET6 AF_INET".to_string(),
        ),
        ("PrivateNetwork".to_string(), "no".to_string()),
    ]);
    verify_systemd_network_properties(SideEffectConfinementProfileKind::ExternalCodex, &properties)
        .expect("exact ExternalCodex network properties");

    properties.insert(
        "RestrictAddressFamilies".to_string(),
        "AF_INET AF_INET6".to_string(),
    );
    assert!(verify_systemd_network_properties(
        SideEffectConfinementProfileKind::ExternalCodex,
        &properties,
    )
    .is_err());

    properties.insert(
        "RestrictAddressFamilies".to_string(),
        "AF_UNIX AF_INET AF_INET6 AF_NETLINK".to_string(),
    );
    assert!(verify_systemd_network_properties(
        SideEffectConfinementProfileKind::ExternalCodex,
        &properties,
    )
    .is_err());
}

#[cfg(target_os = "linux")]
#[test]
fn external_grok_network_properties_require_unix_without_netlink() {
    let mut properties = BTreeMap::from([
        (
            "RestrictAddressFamilies".to_string(),
            "AF_INET6 AF_UNIX AF_INET".to_string(),
        ),
        ("PrivateNetwork".to_string(), "no".to_string()),
    ]);
    verify_systemd_network_properties(SideEffectConfinementProfileKind::ExternalGrok, &properties)
        .expect("exact ExternalGrok network properties");

    properties.insert(
        "RestrictAddressFamilies".to_string(),
        "AF_INET AF_INET6".to_string(),
    );
    assert!(verify_systemd_network_properties(
        SideEffectConfinementProfileKind::ExternalGrok,
        &properties,
    )
    .is_err());

    properties.insert(
        "RestrictAddressFamilies".to_string(),
        "AF_UNIX AF_INET AF_INET6 AF_NETLINK".to_string(),
    );
    assert!(verify_systemd_network_properties(
        SideEffectConfinementProfileKind::ExternalGrok,
        &properties,
    )
    .is_err());
}

#[cfg(target_os = "linux")]
#[test]
fn external_grok_profile_resolves_only_declared_managed_paths() {
    let temp = tempfile::tempdir().expect("tempdir");
    let workspace = temp.path().join("worktree");
    let read_only_root = workspace.join(".maco");
    let read_only_file = workspace.join(".git");
    let read_write_root = workspace.join(".agents/docs");
    let read_write_file = workspace.join("AGENTS.md");
    let capability_root = temp.path().join("exact");
    let capability_file = capability_root.join("worker-report.json");
    let artifact_root = temp.path().join("incoming");
    let hidden_root = temp.path().join("primary");
    for directory in [
        &workspace,
        &read_only_root,
        &read_write_root,
        &capability_root,
        &artifact_root,
        &hidden_root,
    ] {
        fs::create_dir_all(directory).expect("sandbox fixture directory");
    }
    for file in [&read_only_file, &read_write_file, &capability_file] {
        fs::write(file, "fixture\n").expect("sandbox fixture file");
    }
    let held_capability = Arc::new(
        OpenOptions::new()
            .read(true)
            .write(true)
            .open(&capability_file)
            .expect("held writable capability"),
    );
    let held_read_only = Arc::new(
        OpenOptions::new()
            .read(true)
            .open(&read_only_file)
            .expect("held read-only capability"),
    );

    let read_only = ExternalGrokProfile::read_only(&workspace);
    assert_eq!(read_only.workspace_access(), WorkspaceAccess::ReadOnly);

    let profile = ExternalGrokProfile::read_write(&workspace)
        .with_visible_read_only_root(&read_only_root)
        .with_visible_read_only_file_capability(&read_only_file, held_read_only)
        .expect("ExternalGrok exact read-only capability")
        .with_visible_read_write_root(&read_write_root)
        .with_visible_read_write_file(&read_write_file)
        .with_writable_artifact_root(&artifact_root)
        .with_hidden_root(&hidden_root)
        .with_visible_read_write_file_capability(&capability_file, held_capability)
        .expect("ExternalGrok exact writable capability");
    assert_eq!(profile.workspace_access(), WorkspaceAccess::ReadWrite);
    assert_eq!(profile.visible_read_only_roots(), &[read_only_root.clone()]);
    assert_eq!(profile.visible_read_only_files(), &[read_only_file.clone()]);
    assert_eq!(
        profile.visible_read_write_roots(),
        &[read_write_root.clone()]
    );
    assert_eq!(
        profile.visible_read_write_files(),
        &[read_write_file.clone(), capability_file.clone()]
    );
    assert_eq!(profile.writable_artifact_roots(), &[artifact_root.clone()]);

    let spec = ProcessSpec::direct(
        "external Grok managed path projection",
        PathBuf::from("/bin/true"),
        Vec::<OsString>::new(),
        &workspace,
        128,
    )
    .with_side_effect_confinement(SideEffectConfinementProfile::ExternalGrok(profile));
    let sandbox = resolve_systemd_sandbox(&spec)
        .expect("resolve ExternalGrok sandbox")
        .expect("workspace sandbox");
    assert_eq!(sandbox.kind, SideEffectConfinementProfileKind::ExternalGrok);
    assert_eq!(sandbox.workspace_root, workspace);
    assert_eq!(sandbox.workspace_access, WorkspaceAccess::ReadWrite);
    assert_eq!(sandbox.visible_read_only_roots, vec![read_only_root]);
    assert_eq!(sandbox.visible_read_only_files, vec![read_only_file]);
    assert_eq!(sandbox.visible_read_write_roots, vec![read_write_root]);
    assert_eq!(
        sandbox.visible_read_write_files,
        vec![capability_file, read_write_file]
    );
    assert_eq!(sandbox.writable_artifact_roots, vec![artifact_root]);
    assert_eq!(sandbox.hidden_roots, vec![hidden_root]);
}

#[cfg(target_os = "linux")]
#[test]
fn external_grok_read_only_file_capability_rejects_replacement_before_resolution() {
    let temp = tempfile::tempdir().expect("tempdir");
    let workspace = temp.path().join("worktree");
    let state_root = temp.path().join("grok-home");
    let auth = state_root.join("auth.json");
    fs::create_dir(&workspace).expect("workspace");
    fs::create_dir(&state_root).expect("Grok state root");
    fs::write(&auth, "reviewed identity\n").expect("reviewed identity fixture");
    let held_auth = Arc::new(
        OpenOptions::new()
            .read(true)
            .open(&auth)
            .expect("held reviewed identity capability"),
    );
    let profile = ExternalGrokProfile::read_only(&workspace)
        .with_visible_read_only_file_capability(&auth, held_auth)
        .expect("ExternalGrok exact read-only capability");

    fs::remove_file(&auth).expect("remove reviewed identity fixture");
    fs::write(&auth, "replacement identity\n").expect("replacement identity fixture");

    let spec = ProcessSpec::direct(
        "replaced ExternalGrok identity",
        PathBuf::from("/bin/true"),
        Vec::<OsString>::new(),
        &workspace,
        128,
    )
    .with_side_effect_confinement(SideEffectConfinementProfile::ExternalGrok(profile));
    let error = match resolve_systemd_sandbox(&spec) {
        Err(error) => error,
        Ok(_) => panic!("replacement must not inherit the held read-only capability"),
    };
    assert!(
        error
            .to_string()
            .contains("read-only file capability identity changed"),
        "{error}"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn external_grok_read_only_file_capability_rejects_writable_descriptor() {
    let temp = tempfile::tempdir().expect("tempdir");
    let workspace = temp.path().join("worktree");
    let auth = temp.path().join("auth.json");
    fs::create_dir(&workspace).expect("workspace");
    fs::write(&auth, "reviewed identity\n").expect("reviewed identity fixture");
    let writable_auth = Arc::new(
        OpenOptions::new()
            .read(true)
            .write(true)
            .open(&auth)
            .expect("writable identity descriptor"),
    );

    let error = ExternalGrokProfile::read_only(&workspace)
        .with_visible_read_only_file_capability(&auth, writable_auth)
        .expect_err("a writable descriptor must not confer a read-only capability");
    assert!(
        error.to_string().contains("read-only held descriptor"),
        "{error}"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn external_codex_writable_workspace_resolves_nested_read_only_controls() {
    let temp = tempfile::tempdir().expect("tempdir");
    let workspace = temp.path().join("worktree");
    let control_root = workspace.join(".maco");
    let cache_root = workspace.join(".maco-cache");
    let control_file = workspace.join(".git");
    let policy_root = workspace.join(".agents");
    let exception_root = policy_root.join("docs");
    let exception_file = workspace.join("AGENTS.md");
    let runtime = temp.path().join("runtime");
    fs::create_dir(&workspace).expect("workspace");
    fs::create_dir(&control_root).expect("control root");
    fs::create_dir(&cache_root).expect("cache root");
    fs::create_dir(&policy_root).expect("policy root");
    fs::create_dir(&exception_root).expect("exception root");
    fs::write(&control_file, "gitdir: ../primary/.git/worktrees/child\n")
        .expect("linked-worktree marker");
    fs::write(&exception_file, "policy\n").expect("exception file");
    fs::create_dir(&runtime).expect("runtime");

    let profile = ExternalCodexProfile::read_write(&workspace)
        .with_visible_read_only_root(&control_root)
        .with_visible_read_only_root(&cache_root)
        .with_visible_read_only_root(&policy_root)
        .with_visible_read_only_file(&control_file)
        .with_visible_read_write_root(&exception_root)
        .with_visible_read_write_file(&exception_file);
    let spec = ProcessSpec::direct(
        "external Codex protected controls",
        PathBuf::from("/bin/true"),
        Vec::<OsString>::new(),
        &workspace,
        128,
    )
    .with_side_effect_confinement(SideEffectConfinementProfile::ExternalCodex(profile));
    let mut sandbox = resolve_systemd_sandbox(&spec)
        .expect("resolve ExternalCodex sandbox")
        .expect("workspace sandbox");
    sandbox
        .add_private_runtime_root(&runtime)
        .expect("private runtime mount");

    assert_eq!(
        sandbox.kind,
        SideEffectConfinementProfileKind::ExternalCodex
    );
    assert_eq!(sandbox.workspace_access, WorkspaceAccess::ReadWrite);
    assert_eq!(sandbox.workspace_root, workspace);
    assert_eq!(
        sandbox.visible_read_only_roots,
        vec![
            policy_root.clone(),
            control_root.clone(),
            cache_root.clone()
        ]
    );
    assert_eq!(sandbox.visible_read_only_files, vec![control_file.clone()]);
    assert_eq!(
        sandbox.visible_read_write_roots,
        vec![exception_root.clone()]
    );
    assert_eq!(
        sandbox.visible_read_write_files,
        vec![exception_file.clone()]
    );
    for (path, access) in [
        (&workspace, SandboxMountAccess::ReadWrite),
        (&control_root, SandboxMountAccess::ReadOnly),
        (&cache_root, SandboxMountAccess::ReadOnly),
        (&policy_root, SandboxMountAccess::ReadOnly),
        (&control_file, SandboxMountAccess::ReadOnly),
        (&exception_root, SandboxMountAccess::ReadWrite),
        (&exception_file, SandboxMountAccess::ReadWrite),
        (&runtime, SandboxMountAccess::PrivateRuntime),
    ] {
        assert!(
            sandbox
                .mount_checks
                .iter()
                .any(|check| check.path == *path && check.access == access && !check.optional),
            "missing {access:?} mount check for {}",
            path.display()
        );
    }

    let mut command = Command::new("systemd-run");
    apply_systemd_sandbox_properties(&mut command, &sandbox);
    command
        .arg(systemd_path_property("BindPaths=", &runtime, false))
        .arg(systemd_path_property("ReadWritePaths=", &runtime, false));
    let arguments = command
        .get_args()
        .map(|argument| argument.to_string_lossy().into_owned())
        .collect::<BTreeSet<_>>();
    for expected in [
        format!("--property=BindPaths={}", workspace.display()),
        format!("--property=ReadWritePaths={}", workspace.display()),
        format!("--property=BindReadOnlyPaths={}", control_root.display()),
        format!("--property=ReadOnlyPaths={}", control_root.display()),
        format!("--property=BindReadOnlyPaths={}", cache_root.display()),
        format!("--property=ReadOnlyPaths={}", cache_root.display()),
        format!("--property=BindReadOnlyPaths={}", policy_root.display()),
        format!("--property=ReadOnlyPaths={}", policy_root.display()),
        format!("--property=BindReadOnlyPaths={}", control_file.display()),
        format!("--property=ReadOnlyPaths={}", control_file.display()),
        format!("--property=BindPaths={}", exception_root.display()),
        format!("--property=ReadWritePaths={}", exception_root.display()),
        format!("--property=BindPaths={}", exception_file.display()),
        format!("--property=ReadWritePaths={}", exception_file.display()),
        format!("--property=BindPaths={}", runtime.display()),
        format!("--property=ReadWritePaths={}", runtime.display()),
    ] {
        assert!(
            arguments.contains(&expected),
            "missing appended systemd property {expected}"
        );
    }
    for permanently_read_only in [&control_root, &cache_root, &policy_root] {
        assert!(!arguments.contains(&format!(
            "--property=BindPaths={}",
            permanently_read_only.display()
        )));
        assert!(!arguments.contains(&format!(
            "--property=ReadWritePaths={}",
            permanently_read_only.display()
        )));
    }
}

#[cfg(target_os = "linux")]
#[test]
fn external_codex_exact_writable_root_rejects_hardlink_alias_outside_exception() {
    let temp = tempfile::tempdir().expect("tempdir");
    let workspace = temp.path().join("worktree");
    let policy_root = workspace.join(".agents");
    let exception_root = policy_root.join("docs");
    let exception_file = exception_root.join("policy.md");
    let outside_alias = workspace.join("AGENTS.md");
    fs::create_dir(&workspace).expect("workspace");
    fs::create_dir(&policy_root).expect("policy root");
    fs::create_dir(&exception_root).expect("exception root");
    fs::write(&exception_file, "policy\n").expect("exception file");
    fs::hard_link(&exception_file, &outside_alias).expect("outside hard-link alias");

    let profile = ExternalCodexProfile::read_write(&workspace)
        .with_visible_read_only_root(&policy_root)
        .with_visible_read_write_root(&exception_root);
    let spec = ProcessSpec::direct(
        "external Codex hard-link scope",
        PathBuf::from("/bin/true"),
        Vec::<OsString>::new(),
        &workspace,
        128,
    )
    .with_side_effect_confinement(SideEffectConfinementProfile::ExternalCodex(profile));
    let error = match resolve_systemd_sandbox(&spec) {
        Err(error) => error,
        Ok(_) => panic!("hard-link alias outside exact writable root must fail closed"),
    };
    assert!(error.to_string().contains("hard-link alias outside"));
}

#[cfg(target_os = "linux")]
#[test]
fn external_codex_rejects_writable_aliases_to_every_protected_file_class() {
    for protected_class in ["linked-git", "policy-root", "permanent-root"] {
        let temp = tempfile::tempdir().expect("tempdir");
        let workspace = temp.path().join("worktree");
        let git_marker = workspace.join(".git");
        let policy_root = workspace.join(".agents");
        let policy_file = policy_root.join("policy.md");
        let permanent_root = workspace.join(".maco");
        let permanent_file = permanent_root.join("state");
        let incoming = temp.path().join("incoming");
        fs::create_dir(&workspace).expect("workspace");
        fs::create_dir(&policy_root).expect("policy root");
        fs::create_dir(&permanent_root).expect("permanent root");
        fs::create_dir(&incoming).expect("incoming root");
        fs::write(&git_marker, "gitdir: ../primary/.git/worktrees/child\n")
            .expect("linked-worktree marker");
        fs::write(&policy_file, "policy\n").expect("policy file");
        fs::write(&permanent_file, "state\n").expect("permanent state");

        let (protected, alias) = match protected_class {
            "linked-git" => (&git_marker, workspace.join("git-alias")),
            "policy-root" => (&policy_file, workspace.join("policy-alias")),
            "permanent-root" => (&permanent_file, incoming.join("state-alias")),
            _ => unreachable!("bounded protected class"),
        };
        fs::hard_link(protected, &alias).expect("writable hard-link alias");

        let profile = ExternalCodexProfile::read_write(&workspace)
            .with_visible_read_only_root(&policy_root)
            .with_visible_read_only_root(&permanent_root)
            .with_visible_read_only_file(&git_marker)
            .with_writable_artifact_root(&incoming);
        let spec = ProcessSpec::direct(
            "external Codex protected inode aliases",
            PathBuf::from("/bin/true"),
            Vec::<OsString>::new(),
            &workspace,
            128,
        )
        .with_side_effect_confinement(SideEffectConfinementProfile::ExternalCodex(profile));
        let error = match resolve_systemd_sandbox(&spec) {
            Err(error) => error,
            Ok(_) => panic!("{protected_class} writable alias must fail closed"),
        };
        assert!(
            error
                .to_string()
                .contains("protected read-only sandbox file has a writable hard-link alias"),
            "unexpected {protected_class} rejection: {error}"
        );
    }
}

#[cfg(target_os = "linux")]
#[test]
fn protected_alias_scan_skips_read_only_roots_without_a_writable_surface() {
    let temp = tempfile::tempdir().expect("tempdir");
    let workspace = temp.path().join("read-only-workspace");
    fs::create_dir(&workspace).expect("workspace");
    // This absent root is a fail-if-traversed sentinel for an irrelevant large read-only tree.
    let irrelevant_read_only_root = temp.path().join("irrelevant-large-read-only-root");
    let sandbox = ResolvedSystemdSandbox {
        kind: SideEffectConfinementProfileKind::StrictOfflineWorkspace,
        workspace_root: workspace.clone(),
        current_dir: workspace,
        workspace_access: WorkspaceAccess::ReadOnly,
        visible_read_only_roots: vec![irrelevant_read_only_root],
        visible_read_only_files: Vec::new(),
        visible_read_write_roots: Vec::new(),
        visible_read_write_files: Vec::new(),
        external_codex_writable_file_capabilities: Vec::new(),
        external_grok_read_only_file_capabilities: Vec::new(),
        writable_artifact_roots: Vec::new(),
        hidden_roots: Vec::new(),
        isolated_host_view: false,
        resource_limits: ProcessResourceLimits::default(),
        path_identities: Vec::new(),
        mount_checks: Vec::new(),
    };

    sandbox
        .verify_protected_read_only_hardlink_scope()
        .expect("no writable boundary means no protected alias traversal");
}

#[cfg(target_os = "linux")]
#[test]
fn protected_alias_scan_skips_disjoint_read_only_roots_when_writable_files_are_single_link() {
    let temp = tempfile::tempdir().expect("tempdir");
    let workspace = temp.path().join("writable-runtime");
    fs::create_dir(&workspace).expect("workspace");
    fs::write(workspace.join("index"), "staged\n").expect("single-link writable file");
    // Absent on purpose: a fail-if-traversed sentinel for a huge disjoint read-only tree
    // such as a whole repository mounted only so Git can read the worktree.
    let disjoint_read_only_root = temp.path().join("disjoint-large-read-only-root");
    let sandbox = ResolvedSystemdSandbox {
        kind: SideEffectConfinementProfileKind::StrictOfflineWorkspace,
        workspace_root: workspace.clone(),
        current_dir: workspace,
        workspace_access: WorkspaceAccess::ReadWrite,
        visible_read_only_roots: vec![disjoint_read_only_root],
        visible_read_only_files: Vec::new(),
        visible_read_write_roots: Vec::new(),
        visible_read_write_files: Vec::new(),
        external_codex_writable_file_capabilities: Vec::new(),
        external_grok_read_only_file_capabilities: Vec::new(),
        writable_artifact_roots: Vec::new(),
        hidden_roots: Vec::new(),
        isolated_host_view: false,
        resource_limits: ProcessResourceLimits::default(),
        path_identities: Vec::new(),
        mount_checks: Vec::new(),
    };

    sandbox
        .verify_protected_read_only_hardlink_scope()
        .expect("single-link writable files must not inventory a disjoint read-only tree");
}

#[cfg(target_os = "linux")]
#[test]
fn protected_alias_scan_ignores_special_entries_but_preserves_writable_checks() {
    use std::os::unix::fs::FileTypeExt;

    let temp = tempfile::tempdir().expect("tempdir");
    let protected_root = temp.path().join("protected");
    let writable_root = temp.path().join("writable");
    fs::create_dir(&protected_root).expect("protected root");
    fs::create_dir(&writable_root).expect("writable root");
    let socket_path = protected_root.join("socket");
    let _socket =
        crate::test_support::bind_test_unix_socket(&socket_path).expect("protected socket");
    assert!(
        fs::symlink_metadata(&socket_path)
            .expect("protected socket metadata")
            .file_type()
            .is_socket(),
        "protected fixture entry must remain a socket"
    );
    let protected_file = protected_root.join("policy.md");
    fs::write(&protected_file, "policy\n").expect("protected file");
    let sandbox = ResolvedSystemdSandbox {
        kind: SideEffectConfinementProfileKind::StrictOfflineWorkspace,
        workspace_root: writable_root.clone(),
        current_dir: writable_root.clone(),
        workspace_access: WorkspaceAccess::ReadWrite,
        visible_read_only_roots: vec![protected_root.clone()],
        visible_read_only_files: Vec::new(),
        visible_read_write_roots: Vec::new(),
        visible_read_write_files: Vec::new(),
        external_codex_writable_file_capabilities: Vec::new(),
        external_grok_read_only_file_capabilities: Vec::new(),
        writable_artifact_roots: Vec::new(),
        hidden_roots: Vec::new(),
        isolated_host_view: false,
        resource_limits: ProcessResourceLimits::default(),
        path_identities: Vec::new(),
        mount_checks: Vec::new(),
    };

    sandbox
        .verify_protected_read_only_hardlink_scope()
        .expect("read-only socket is irrelevant to regular-file alias identity");

    let mut remaining = MAX_SANDBOX_ENTRY_SCAN;
    let mut writable_links = BTreeMap::new();
    let error = scan_sandbox_tree(&protected_root, true, &mut remaining, &mut writable_links)
        .expect_err("the same socket on a writable surface must remain forbidden");
    assert!(error.to_string().contains("socket, FIFO, or device node"));

    fs::hard_link(&protected_file, writable_root.join("policy-alias.md"))
        .expect("writable hard-link alias");
    let error = sandbox
        .verify_protected_read_only_hardlink_scope()
        .expect_err("protected regular-file alias must remain forbidden");
    assert!(
        error
            .to_string()
            .contains("protected read-only sandbox file has a writable hard-link alias"),
        "unexpected hard-link rejection: {error}"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn external_codex_legitimate_exact_file_exception_is_not_protected_read_only() {
    let temp = tempfile::tempdir().expect("tempdir");
    let workspace = temp.path().join("worktree");
    let policy_root = workspace.join(".agents");
    let exception = policy_root.join("docs/worker.md");
    fs::create_dir_all(exception.parent().expect("exception parent")).expect("policy tree");
    fs::write(&exception, "worker policy\n").expect("writable exception");

    let profile = ExternalCodexProfile::read_write(&workspace)
        .with_visible_read_only_root(&policy_root)
        .with_visible_read_write_file(&exception);
    let spec = ProcessSpec::direct(
        "external Codex exact exception",
        PathBuf::from("/bin/true"),
        Vec::<OsString>::new(),
        &workspace,
        128,
    )
    .with_side_effect_confinement(SideEffectConfinementProfile::ExternalCodex(profile));
    let sandbox = resolve_systemd_sandbox(&spec)
        .expect("legitimate exact exception")
        .expect("resolved sandbox");
    assert_eq!(
        sandbox
            .effective_path_access(&exception)
            .expect("effective exception access"),
        Some(SandboxMountAccess::ReadWrite)
    );
}

#[cfg(target_os = "linux")]
#[test]
fn external_codex_held_file_capability_rejects_replacement_before_resolution() {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempfile::tempdir().expect("tempdir");
    let workspace = temp.path().join("worktree");
    let policy_root = workspace.join(".agents");
    let exception = policy_root.join("docs/worker.md");
    fs::create_dir_all(exception.parent().expect("exception parent")).expect("policy tree");
    fs::write(&exception, "worker policy\n").expect("writable exception");
    fs::set_permissions(&exception, fs::Permissions::from_mode(0o600)).expect("exception mode");
    let held_file = Arc::new(
        OpenOptions::new()
            .read(true)
            .write(true)
            .open(&exception)
            .expect("held exception"),
    );

    let profile = ExternalCodexProfile::read_write(&workspace)
        .with_visible_read_only_root(&policy_root)
        .with_visible_read_write_file_capability(&exception, held_file)
        .expect("held exact exception capability");
    let spec = ProcessSpec::direct(
        "external Codex held exact exception",
        PathBuf::from("/bin/true"),
        Vec::<OsString>::new(),
        &workspace,
        128,
    )
    .with_side_effect_confinement(SideEffectConfinementProfile::ExternalCodex(profile));
    let sandbox = resolve_systemd_sandbox(&spec)
        .expect("unchanged held exception")
        .expect("resolved sandbox");
    assert_eq!(
        sandbox
            .effective_path_access(&exception)
            .expect("effective exception access"),
        Some(SandboxMountAccess::ReadWrite)
    );

    fs::rename(&exception, workspace.join("original-worker.md"))
        .expect("exchange original exception");
    fs::write(&exception, "replacement\n").expect("replacement exception");
    fs::set_permissions(&exception, fs::Permissions::from_mode(0o600)).expect("replacement mode");
    assert!(
        sandbox.verify_path_identities().is_err(),
        "resolved sandbox must retain and revalidate the held capability"
    );
    let error = match resolve_systemd_sandbox(&spec) {
        Err(error) => error,
        Ok(_) => panic!("replacement must not inherit the held writable capability"),
    };
    assert!(
        error
            .to_string()
            .contains("writable file capability identity changed"),
        "unexpected replacement rejection: {error}"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn exact_writable_file_capability_carves_read_only_parent_from_writable_artifact_root() {
    let temp = tempfile::tempdir().expect("tempdir");
    let workspace = temp.path().join("worktree");
    let incoming = temp.path().join("incoming");
    let carrier = incoming.join("worker-journals");
    let journal = carrier.join("worker-a.jsonl");
    let sibling = carrier.join("sibling");
    fs::create_dir(&workspace).expect("workspace");
    fs::create_dir_all(&carrier).expect("journal carrier");
    fs::write(&journal, []).expect("journal");
    fs::write(&sibling, []).expect("sibling");
    let held_journal = Arc::new(
        OpenOptions::new()
            .read(true)
            .write(true)
            .open(&journal)
            .expect("held journal capability"),
    );

    let profile = ExternalCodexProfile::read_write(&workspace)
        .with_visible_read_write_file_capability(&journal, held_journal)
        .expect("exact writable journal")
        .with_writable_artifact_root(&incoming);
    let spec = ProcessSpec::direct(
        "exact writable file parent boundary",
        PathBuf::from("/bin/true"),
        Vec::<OsString>::new(),
        &workspace,
        128,
    )
    .with_side_effect_confinement(SideEffectConfinementProfile::ExternalCodex(profile));
    let sandbox = resolve_systemd_sandbox(&spec)
        .expect("resolve exact writable file sandbox")
        .expect("resolved sandbox");

    for (path, expected) in [
        (&incoming, SandboxMountAccess::ReadWrite),
        (&carrier, SandboxMountAccess::ReadOnly),
        (&sibling, SandboxMountAccess::ReadOnly),
        (&journal, SandboxMountAccess::ReadWrite),
    ] {
        assert_eq!(
            sandbox
                .effective_path_access(path)
                .expect("effective path access"),
            Some(expected),
            "unexpected access for {}",
            path.display()
        );
    }
    for (path, access) in [
        (&incoming, SandboxMountAccess::ReadWrite),
        (&carrier, SandboxMountAccess::ReadOnly),
        (&journal, SandboxMountAccess::ReadWrite),
    ] {
        assert!(
            sandbox
                .mount_checks
                .iter()
                .any(|check| check.path == *path && check.access == access),
            "missing {access:?} mount check for {}",
            path.display()
        );
    }

    let mut command = Command::new("systemd-run");
    apply_systemd_sandbox_properties(&mut command, &sandbox);
    let arguments = command
        .get_args()
        .map(|argument| argument.to_string_lossy().into_owned())
        .collect::<BTreeSet<_>>();
    assert!(arguments.contains(&format!("--property=ReadOnlyPaths={}", carrier.display())));
    assert!(!arguments.contains(&format!(
        "--property=BindReadOnlyPaths={}",
        carrier.display()
    )));
    assert!(arguments.contains(&format!("--property=BindPaths={}", journal.display())));
    assert!(arguments.contains(&format!("--property=ReadWritePaths={}", journal.display())));
}

#[cfg(target_os = "linux")]
#[test]
fn nested_codex_profile_appends_exact_journal_while_outer_keeps_parent_nonwritable() {
    use std::os::unix::fs::PermissionsExt;

    const CHILD_ENV: &str = "MACO_TEST_NESTED_CODEX_JOURNAL_CHILD";
    const JOURNAL_ENV: &str = "MACO_TEST_NESTED_CODEX_JOURNAL_PATH";
    const JOURNAL_PARENT_ENV: &str = "MACO_TEST_NESTED_CODEX_JOURNAL_PARENT";
    const TEST_NAME: &str = "process_runner::tests::nested_codex_profile_appends_exact_journal_while_outer_keeps_parent_nonwritable";

    if env::var_os(CHILD_ENV).is_some() {
        let journal = PathBuf::from(env::var_os(JOURNAL_ENV).expect("journal fixture"));
        let journal_parent =
            PathBuf::from(env::var_os(JOURNAL_PARENT_ENV).expect("journal parent fixture"));
        let mut file = OpenOptions::new()
            .append(true)
            .open(&journal)
            .expect("append exact journal through both sandboxes");
        file.write_all(b"{\"command\":[\"probe\"],\"cwd\":\".\",\"start_timestamp\":\"s\",\"end_timestamp\":\"e\",\"changed_paths\":[]}\n")
            .expect("write exact journal entry");
        assert!(
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(journal_parent.join("sibling"))
                .is_err(),
            "the journal carrier parent must remain nonwritable"
        );
        return;
    }

    skip_without_containment!();
    if !strict_backend_available_for_tests() {
        return;
    }

    let temp = tempfile::tempdir().expect("journal containment tempdir");
    let workspace = temp.path().join("worktree");
    let incoming = temp.path().join("incoming");
    let journal_parent = incoming.join("worker-journals");
    fs::create_dir(&workspace).expect("workspace");
    fs::create_dir_all(&journal_parent).expect("journal carrier");
    fs::set_permissions(&journal_parent, fs::Permissions::from_mode(0o700))
        .expect("journal carrier mode");
    for name in [".git", ".agents", ".codex"] {
        let path = journal_parent.join(name);
        fs::create_dir(&path).expect("protected mount target");
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .expect("protected mount target mode");
    }
    let journal = journal_parent.join("worker-a.jsonl");
    fs::write(&journal, []).expect("journal leaf");
    fs::set_permissions(&journal, fs::Permissions::from_mode(0o600)).expect("journal mode");
    let held_journal = Arc::new(
        OpenOptions::new()
            .read(true)
            .write(true)
            .open(&journal)
            .expect("held journal capability"),
    );

    let codex = trusted_system_executable(
        "codex",
        &[
            "/run/current-system/sw/bin/codex",
            "/usr/bin/codex",
            "/bin/codex",
        ],
    )
    .expect("trusted Codex executable");
    let test_binary = env::current_exe().expect("current test executable");
    let filesystem_permissions = format!(
        "permissions.maco_external_codex.filesystem={{\":minimal\"=\"read\",\":workspace_roots\"={{\".\"=\"write\"}},{}=\"write\",{}=\"read\"}}",
        toml_test_string(&journal_parent),
        toml_test_string(&test_binary)
    );
    let argv = vec![
        OsString::from("-c"),
        OsString::from("default_permissions=\"maco_external_codex\""),
        OsString::from("-c"),
        OsString::from("permissions.maco_external_codex.network={enabled=false}"),
        OsString::from("-c"),
        OsString::from(filesystem_permissions),
        OsString::from("sandbox"),
        OsString::from("-P"),
        OsString::from("maco_external_codex"),
        OsString::from("-C"),
        workspace.as_os_str().to_os_string(),
        OsString::from("--"),
        test_binary.as_os_str().to_os_string(),
        OsString::from("--exact"),
        OsString::from(TEST_NAME),
        OsString::from("--nocapture"),
    ];
    let environment = BTreeMap::from([
        (CHILD_ENV.to_string(), "1".to_string()),
        (JOURNAL_ENV.to_string(), journal.display().to_string()),
        (
            JOURNAL_PARENT_ENV.to_string(),
            journal_parent.display().to_string(),
        ),
        ("TMPDIR".to_string(), "/tmp".to_string()),
    ]);
    let profile = ExternalCodexProfile::read_write(&workspace)
        .with_visible_read_write_file_capability(&journal, held_journal)
        .expect("outer exact-file capability")
        .with_writable_artifact_root(&incoming);
    let output = run_process(
        ProcessSpec::direct(
            "nested Codex exact worker-journal probe",
            codex,
            argv,
            &workspace,
            8 * 1024,
        )
        .with_environment(EnvironmentMode::InheritAndSet(environment))
        .with_stdin(StdinMode::Null)
        .with_timeout(Some(CONTENTION_RESILIENT_PROCESS_TEST_TIMEOUT))
        .with_side_effect_confinement(SideEffectConfinementProfile::ExternalCodex(profile)),
    )
    .expect("run nested Codex journal probe");

    assert!(
        output.status.is_some_and(|status| status.success()),
        "nested probe failed: {output:#?}"
    );
    assert!(output.safety_evidence_verified());
    assert!(fs::read(&journal)
        .expect("captured journal")
        .starts_with(b"{\"command\":[\"probe\"]"));
    assert!(!journal_parent.join("sibling").exists());
}

#[cfg(target_os = "linux")]
fn toml_test_string(path: &Path) -> String {
    let value = path.to_string_lossy();
    format!("\"{}\"", value.replace('\\', "\\\\").replace('\"', "\\\""))
}

#[cfg(target_os = "linux")]
#[test]
fn external_codex_outer_sandbox_enforces_control_and_report_write_boundaries() {
    skip_without_containment!();
    const CHILD_ENV: &str = "MACO_TEST_EXTERNAL_CODEX_WRITE_BOUNDARY_CHILD";
    const ASSIGNED_PATH_ENV: &str = "MACO_TEST_EXTERNAL_CODEX_ASSIGNED_PATH";
    const REPORT_PATH_ENV: &str = "MACO_TEST_EXTERNAL_CODEX_REPORT_PATH";
    const PROTECTED_PATH_ENVS: &[&str] = &[
        "MACO_TEST_EXTERNAL_CODEX_PROTECTED_0",
        "MACO_TEST_EXTERNAL_CODEX_PROTECTED_1",
        "MACO_TEST_EXTERNAL_CODEX_PROTECTED_2",
        "MACO_TEST_EXTERNAL_CODEX_PROTECTED_3",
        "MACO_TEST_EXTERNAL_CODEX_PROTECTED_4",
        "MACO_TEST_EXTERNAL_CODEX_PROTECTED_5",
        "MACO_TEST_EXTERNAL_CODEX_PROTECTED_6",
        "MACO_TEST_EXTERNAL_CODEX_PROTECTED_7",
    ];

    if env::var_os(CHILD_ENV).is_some() {
        let protected = PROTECTED_PATH_ENVS
            .iter()
            .map(|name| PathBuf::from(env::var_os(name).expect("protected-path fixture")))
            .collect::<Vec<_>>();
        for path in protected {
            assert!(
                fs::write(&path, b"forbidden mutation\n").is_err(),
                "outer sandbox allowed a protected write to {}",
                path.display()
            );
        }
        let assigned =
            PathBuf::from(env::var_os(ASSIGNED_PATH_ENV).expect("assigned-path fixture"));
        let report = PathBuf::from(env::var_os(REPORT_PATH_ENV).expect("report-path fixture"));
        fs::write(assigned, b"assigned writable\n").expect("write ordinary assigned file");
        fs::write(report, b"incoming writable\n").expect("write designated incoming report");
        return;
    }

    if !strict_backend_available_for_tests() {
        return;
    }

    let test_binary = env::current_exe().expect("current test executable");
    let test_output_root = test_binary
        .parent()
        .and_then(Path::parent)
        .expect("test output root");
    let temp = tempfile::tempdir_in(test_output_root).expect("test output tempdir");
    let primary = temp.path().join("primary");
    let primary_git = primary.join(".git");
    let common_state = primary_git.join("maco/state");
    let workspace = temp.path().join("worktree");
    let permanent_control = workspace.join(".maco/control");
    let cache_control = workspace.join(".maco-cache/state");
    let codex_control = workspace.join(".codex/state");
    let policy_control = workspace.join(".agents/policy.md");
    let git_marker = workspace.join(".git");
    let ignore_control = workspace.join(".gitignore");
    let assigned = workspace.join("src/assigned.txt");
    let incoming = temp.path().join("incoming");
    let report = incoming.join("report.txt");
    fs::create_dir_all(primary_git.join("worktrees/child")).expect("primary worktree state");
    fs::create_dir_all(&common_state).expect("common claim state");
    fs::create_dir_all(workspace.join(".maco")).expect("MACO control root");
    fs::create_dir_all(workspace.join(".maco-cache")).expect("MACO cache root");
    fs::create_dir_all(workspace.join(".codex")).expect("Codex control root");
    fs::create_dir_all(workspace.join(".agents")).expect("policy control root");
    fs::create_dir_all(workspace.join("src")).expect("assigned source root");
    fs::create_dir(&incoming).expect("incoming report root");
    fs::write(primary_git.join("config"), "primary-config\n").expect("primary config");
    fs::write(common_state.join("claims.json"), "common-state\n").expect("common state");
    fs::write(
        &git_marker,
        format!(
            "gitdir: {}\n",
            primary_git.join("worktrees/child").display()
        ),
    )
    .expect("linked-worktree marker");
    fs::write(&permanent_control, "MACO control\n").expect("MACO control");
    fs::write(&cache_control, "cache control\n").expect("cache control");
    fs::write(&codex_control, "Codex control\n").expect("Codex control");
    fs::write(&policy_control, "policy control\n").expect("policy control");
    fs::write(&ignore_control, "ignore control\n").expect("ignore control");
    fs::write(&assigned, "assigned original\n").expect("assigned file");

    let protected = [
        primary_git.join("config"),
        common_state.join("claims.json"),
        git_marker.clone(),
        permanent_control.clone(),
        cache_control.clone(),
        codex_control.clone(),
        policy_control.clone(),
        ignore_control.clone(),
    ];
    let mut environment = BTreeMap::new();
    environment.insert(CHILD_ENV.to_string(), "1".to_string());
    for (name, path) in PROTECTED_PATH_ENVS.iter().zip(&protected) {
        environment.insert((*name).to_string(), path.display().to_string());
    }
    environment.insert(
        ASSIGNED_PATH_ENV.to_string(),
        assigned.display().to_string(),
    );
    environment.insert(REPORT_PATH_ENV.to_string(), report.display().to_string());
    let profile = ExternalCodexProfile::read_write(&workspace)
        .with_visible_read_only_root(workspace.join(".maco"))
        .with_visible_read_only_root(workspace.join(".maco-cache"))
        .with_visible_read_only_root(workspace.join(".codex"))
        .with_visible_read_only_root(workspace.join(".agents"))
        .with_visible_read_only_file(&git_marker)
        .with_visible_read_only_file(&ignore_control)
        .with_writable_artifact_root(&incoming)
        .with_hidden_root(&primary);
    let unit_capture = TestSystemdUnitNameCapture::start();
    let output = run_process(
        ProcessSpec::direct(
            "ExternalCodex live write-boundary probe",
            env::current_exe().expect("current test executable"),
            [
                OsString::from("--exact"),
                OsString::from(
                    "process_runner::tests::external_codex_outer_sandbox_enforces_control_and_report_write_boundaries",
                ),
            ],
            &workspace,
            4 * 1024,
        )
        .with_environment(EnvironmentMode::InheritAndSet(environment))
        .with_stdin(StdinMode::Null)
        .with_timeout(Some(CONTENTION_RESILIENT_PROCESS_TEST_TIMEOUT))
        .with_side_effect_confinement(SideEffectConfinementProfile::ExternalCodex(profile)),
    );
    let unit_names = unit_capture.finish();
    let output = output.expect("run ExternalCodex live write-boundary probe");

    assert!(output.status.is_some_and(|status| status.success()));
    assert!(output.safety_evidence_verified());
    assert_eq!(
        output.side_effects,
        SideEffectConfinementEvidence::Verified(SideEffectConfinementProfileKind::ExternalCodex)
    );
    assert_eq!(
        fs::read_to_string(primary_git.join("config")).expect("primary config evidence"),
        "primary-config\n"
    );
    assert_eq!(
        fs::read_to_string(common_state.join("claims.json")).expect("common state evidence"),
        "common-state\n"
    );
    for (path, expected) in [
        (&permanent_control, "MACO control\n"),
        (&cache_control, "cache control\n"),
        (&codex_control, "Codex control\n"),
        (&policy_control, "policy control\n"),
        (&ignore_control, "ignore control\n"),
    ] {
        assert_eq!(
            fs::read_to_string(path).expect("protected control evidence"),
            expected
        );
    }
    assert!(fs::read_to_string(&git_marker)
        .expect("linked-worktree marker evidence")
        .starts_with("gitdir: "));
    assert_eq!(
        fs::read_to_string(&assigned).expect("assigned write evidence"),
        "assigned writable\n"
    );
    assert_eq!(
        fs::read_to_string(&report).expect("incoming report evidence"),
        "incoming writable\n"
    );
    assert!(
        !unit_names.is_empty(),
        "strict run allocated no systemd unit"
    );
    assert_systemd_units_have_no_residue(&unit_names);
}

#[cfg(target_os = "linux")]
#[test]
fn external_grok_unix_stream_initialization_preserves_codex_and_write_boundaries() {
    use std::os::unix::net::UnixStream;

    const MODE_FILE: &str = ".maco-external-grok-unix-stream-mode";
    const MARKER_FILE: &str = "initialized.txt";
    const PROTECTED_FILE: &str = "outside-worktree.txt";

    // The strict guardian starts from `env -i`; keep this nested test independent of screened
    // `MACO_TEST_*` propagation by carrying its mode in the already-confined managed worktree.
    let current_dir = env::current_dir().expect("current test directory");
    let mode_file = current_dir.join(MODE_FILE);
    if mode_file.is_file() {
        let mode = fs::read_to_string(&mode_file).expect("runtime mode fixture");
        let mode = mode.trim();
        let marker = current_dir.join(MARKER_FILE);
        let protected = current_dir
            .parent()
            .expect("managed worktree parent")
            .join(PROTECTED_FILE);
        assert!(
            fs::write(&protected, "forbidden\n").is_err(),
            "{mode} profile wrote outside its managed worktree"
        );
        match mode.as_str() {
            "codex" => {
                let error =
                    UnixStream::pair().expect_err("ExternalCodex must continue to reject AF_UNIX");
                assert_eq!(error.raw_os_error(), Some(libc::EPERM));
                fs::write(marker, "eperm\n").expect("write Codex EPERM evidence");
            }
            "grok" => {
                let (left, right) =
                    UnixStream::pair().expect("ExternalGrok must admit local Unix streams");
                drop((left, right));
                fs::write(marker, "initialized\n").expect("write Grok worktree evidence");
            }
            other => panic!("unexpected runtime mode {other}"),
        }
        return;
    }
    skip_without_containment!();

    let test_binary = env::current_exe().expect("current test executable");
    let test_output_root = test_binary
        .parent()
        .and_then(Path::parent)
        .expect("test output root");
    let temp = tempfile::tempdir_in(test_output_root).expect("test output tempdir");
    let codex_worktree = temp.path().join("codex-worktree");
    let grok_worktree = temp.path().join("grok-worktree");
    fs::create_dir(&codex_worktree).expect("Codex worktree");
    fs::create_dir(&grok_worktree).expect("Grok worktree");
    let protected = temp.path().join(PROTECTED_FILE);
    fs::write(&protected, "protected\n").expect("protected fixture");

    let run_case = |mode: &str,
                    worktree: &Path,
                    side_effects: SideEffectConfinementProfile|
     -> ProcessOutput {
        fs::write(worktree.join(MODE_FILE), mode).expect("runtime mode fixture");
        let output = run_process(
            ProcessSpec::direct(
                format!("External{mode} UnixStream initialization probe"),
                &test_binary,
                [
                    OsString::from("--exact"),
                    OsString::from(
                        "process_runner::tests::external_grok_unix_stream_initialization_preserves_codex_and_write_boundaries",
                    ),
                ],
                worktree,
                4 * 1024,
            )
            .with_environment(EnvironmentMode::ClearAndSet(BTreeMap::new()))
            .with_stdin(StdinMode::Null)
            .with_timeout(Some(CONTENTION_RESILIENT_PROCESS_TEST_TIMEOUT))
            .with_side_effect_confinement(side_effects),
        )
        .unwrap_or_else(|error| panic!("run External{mode} UnixStream probe: {error}"));
        assert!(
            output.status.is_some_and(|status| status.success()),
            "External{mode} UnixStream child failed: {output:#?}"
        );
        assert!(output.safety_evidence_verified());
        output
    };

    let unit_capture = TestSystemdUnitNameCapture::start();
    let codex_output = run_case(
        "codex",
        &codex_worktree,
        SideEffectConfinementProfile::ExternalCodex(ExternalCodexProfile::read_write(
            &codex_worktree,
        )),
    );
    assert_eq!(
        codex_output.side_effects,
        SideEffectConfinementEvidence::Verified(SideEffectConfinementProfileKind::ExternalCodex)
    );
    assert_eq!(
        fs::read_to_string(codex_worktree.join(MARKER_FILE)).expect("Codex EPERM evidence"),
        "eperm\n"
    );

    let grok_output = run_case(
        "grok",
        &grok_worktree,
        SideEffectConfinementProfile::ExternalGrok(ExternalGrokProfile::read_write(&grok_worktree)),
    );
    assert_eq!(
        grok_output.side_effects,
        SideEffectConfinementEvidence::Verified(SideEffectConfinementProfileKind::ExternalGrok)
    );
    assert_eq!(
        fs::read_to_string(grok_worktree.join(MARKER_FILE)).expect("Grok initialization evidence"),
        "initialized\n"
    );
    assert_eq!(
        fs::read_to_string(&protected).expect("protected evidence"),
        "protected\n"
    );
    let unit_names = unit_capture.finish();
    assert_eq!(
        unit_names.len(),
        2,
        "Codex and Grok strict runs must each allocate one systemd unit"
    );
    assert_systemd_units_have_no_residue(&unit_names);
}

#[cfg(target_os = "linux")]
#[test]
fn mountinfo_parser_decodes_paths_and_rejects_malformed_or_oversized_input() {
    let parsed = parse_sandbox_mountinfo(
        b"10 1 8:1 / / rw,relatime - ext4 /dev/root rw\n\
              11 10 8:1 /repo/policy /repo/work\\040tree/policy rw - ext4 /dev/root rw\n",
    )
    .expect("synthetic mountinfo");
    assert_eq!(parsed.len(), 2);
    assert_eq!(parsed[1].root, PathBuf::from("/repo/policy"));
    assert_eq!(
        parsed[1].mount_point,
        PathBuf::from("/repo/work tree/policy")
    );
    assert!(parse_sandbox_mountinfo(b"10 1 8:1 / /\n").is_err());
    assert!(
        parse_sandbox_mountinfo(b"10 1 8:1 /bad\\escape /point rw - ext4 /dev/root rw\n").is_err()
    );
    let oversized = vec![b'x'; MAX_SANDBOX_MOUNTINFO_LINE_BYTES + 1];
    assert!(parse_sandbox_mountinfo(&oversized).is_err());
}

#[cfg(target_os = "linux")]
#[test]
fn same_filesystem_mount_identity_rejects_rw_aliases_and_nested_conflicts() {
    let workspace = PathBuf::from("/repo/worktree");
    let policy_root = workspace.join(".agents");
    let protected_file = workspace.join(".git");
    let exception = policy_root.join("docs/worker.md");
    let incoming = PathBuf::from("/run/maco/incoming");
    let sandbox = ResolvedSystemdSandbox {
        kind: SideEffectConfinementProfileKind::ExternalCodex,
        workspace_root: workspace.clone(),
        current_dir: workspace.clone(),
        workspace_access: WorkspaceAccess::ReadWrite,
        visible_read_only_roots: vec![policy_root.clone()],
        visible_read_only_files: vec![protected_file.clone()],
        visible_read_write_roots: Vec::new(),
        visible_read_write_files: vec![exception.clone()],
        external_codex_writable_file_capabilities: Vec::new(),
        external_grok_read_only_file_capabilities: Vec::new(),
        writable_artifact_roots: vec![incoming.clone()],
        hidden_roots: Vec::new(),
        isolated_host_view: false,
        resource_limits: ProcessResourceLimits::default(),
        path_identities: Vec::new(),
        mount_checks: Vec::new(),
    };
    let base = b"10 1 8:1 / / rw,relatime - ext4 /dev/root rw\n";

    let mut alias = base.to_vec();
    alias.extend_from_slice(
        b"11 10 8:1 /repo/worktree/.git /repo/worktree/alias rw - ext4 /dev/root rw\n",
    );
    let alias_mountinfo = parse_sandbox_mountinfo(&alias).expect("alias mountinfo");
    let error = verify_sandbox_mount_alias_conflicts(&sandbox, &alias_mountinfo)
        .expect_err("same-filesystem writable alias");
    assert!(error.to_string().contains("mount identity conflict"));

    let mut artifact_alias = base.to_vec();
    artifact_alias.extend_from_slice(
        b"12 10 8:1 /repo/worktree/.agents /run/maco/incoming rw - ext4 /dev/root rw\n",
    );
    let artifact_mountinfo =
        parse_sandbox_mountinfo(&artifact_alias).expect("artifact alias mountinfo");
    assert!(
        verify_sandbox_mount_alias_conflicts(&sandbox, &artifact_mountinfo).is_err(),
        "incoming artifact alias to protected policy root must fail closed"
    );

    let mut nested_exception = base.to_vec();
    nested_exception.extend_from_slice(
            b"13 10 8:1 /repo/worktree/.git /repo/worktree/.agents/docs/worker.md rw - ext4 /dev/root rw\n",
        );
    let nested_mountinfo = parse_sandbox_mountinfo(&nested_exception).expect("nested mountinfo");
    assert!(
        verify_sandbox_mount_alias_conflicts(&sandbox, &nested_mountinfo).is_err(),
        "writable exception mounted over protected content must fail closed"
    );

    let ordinary_mountinfo = parse_sandbox_mountinfo(base).expect("ordinary mountinfo");
    verify_sandbox_mount_alias_conflicts(&sandbox, &ordinary_mountinfo)
        .expect("ordinary direct RO/RW nesting");
}

#[cfg(target_os = "linux")]
#[test]
fn ordinary_external_codex_exact_path_properties_reject_drift() {
    let sandbox = ResolvedSystemdSandbox {
        kind: SideEffectConfinementProfileKind::ExternalCodex,
        workspace_root: PathBuf::from("/worktree"),
        current_dir: PathBuf::from("/worktree"),
        workspace_access: WorkspaceAccess::ReadWrite,
        visible_read_only_roots: vec![PathBuf::from("/worktree/.maco")],
        visible_read_only_files: vec![PathBuf::from("/worktree/.git")],
        visible_read_write_roots: vec![PathBuf::from("/worktree/.agents/docs")],
        visible_read_write_files: vec![PathBuf::from("/worktree/AGENTS.md")],
        external_codex_writable_file_capabilities: Vec::new(),
        external_grok_read_only_file_capabilities: Vec::new(),
        writable_artifact_roots: Vec::new(),
        hidden_roots: vec![PathBuf::from("/primary")],
        isolated_host_view: false,
        resource_limits: ProcessResourceLimits::default(),
        path_identities: Vec::new(),
        mount_checks: Vec::new(),
    };
    let runtime = Path::new("/run/user/1000/maco-process");
    let mut inaccessible = BTreeSet::from([PathBuf::from("/primary")]);
    inaccessible.extend(known_sensitive_socket_paths());
    let exact = BTreeMap::from([
        (
            "InaccessiblePaths".to_string(),
            joined_property_paths(&inaccessible),
        ),
        (
            "ReadOnlyPaths".to_string(),
            "/worktree/.git /worktree/.maco".to_string(),
        ),
        (
            "BindReadOnlyPaths".to_string(),
            "/worktree/.maco /worktree/.git".to_string(),
        ),
        (
            "ReadWritePaths".to_string(),
            "/worktree /worktree/.agents/docs /worktree/AGENTS.md /run/user/1000/maco-process"
                .to_string(),
        ),
        (
            "BindPaths".to_string(),
            "/run/user/1000/maco-process /worktree /worktree/.agents/docs /worktree/AGENTS.md"
                .to_string(),
        ),
    ]);
    verify_exact_systemd_path_properties(&sandbox, &exact, runtime)
        .expect("exact ordinary ExternalCodex properties");

    for name in [
        "ReadOnlyPaths",
        "BindReadOnlyPaths",
        "BindPaths",
        "ReadWritePaths",
        "InaccessiblePaths",
    ] {
        let mut extra = exact.clone();
        extra
            .get_mut(name)
            .expect("fixture property")
            .push_str(" /unexpected");
        let error = verify_exact_systemd_path_properties(&sandbox, &extra, runtime)
            .expect_err("unexpected effective path must fail closed");
        assert!(
            error.to_string().contains(name),
            "unexpected {name} extra-entry failure: {error}"
        );

        let mut omitted = exact.clone();
        let remaining = omitted[name]
            .split_whitespace()
            .skip(1)
            .collect::<Vec<_>>()
            .join(" ");
        omitted.insert(name.to_string(), remaining);
        let error = verify_exact_systemd_path_properties(&sandbox, &omitted, runtime)
            .expect_err("omitted effective path must fail closed");
        assert!(
            error.to_string().contains(name),
            "unexpected {name} omission failure: {error}"
        );
    }

    let mut remapped = exact;
    remapped.insert(
        "BindPaths".to_string(),
        format!(
            "/worktree:/unexpected {runtime_path}",
            runtime_path = runtime.display()
        ),
    );
    let error = verify_exact_systemd_path_properties(&sandbox, &remapped, runtime)
        .expect_err("remapped writable bind must fail closed");
    assert!(error.to_string().contains("BindPaths"));
}

#[cfg(target_os = "linux")]
fn joined_property_paths(paths: &BTreeSet<PathBuf>) -> String {
    paths
        .iter()
        .map(|path| path.to_string_lossy())
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(target_os = "linux")]
#[test]
fn isolated_host_view_resolves_disjoint_required_mounts_and_root_tmpfs() {
    if !Path::new("/nix/store").is_dir() {
        eprintln!(
            "skipping Nix-store-dependent isolated-host-view test: /nix/store is unavailable"
        );
        return;
    }

    let temp = tempfile::tempdir().expect("tempdir");
    let view = temp.path().join("view");
    let materialized = temp.path().join("materialized");
    let source = temp.path().join("source");
    let runtime = temp.path().join("runtime");
    for path in [&view, &materialized, &source, &runtime] {
        fs::create_dir(path).expect("fixture directory");
    }
    let profile = StrictOfflineWorkspaceProfile::read_only(&view)
        .with_visible_read_only_root("/nix/store")
        .with_visible_read_only_root(&materialized)
        .with_hidden_root(&source)
        .with_isolated_host_view();
    let spec = ProcessSpec::direct(
        "isolated reviewer fixture",
        PathBuf::from("/nix/store/reviewer-fixture"),
        Vec::<OsString>::new(),
        &view,
        128,
    )
    .with_side_effect_confinement(SideEffectConfinementProfile::StrictOfflineWorkspace(
        profile,
    ));
    let mut sandbox = resolve_systemd_sandbox(&spec)
        .expect("resolve isolated sandbox")
        .expect("sandbox config");
    let env_helper = trusted_system_executable(
        "env",
        &["/usr/bin/env", "/bin/env", "/run/current-system/sw/bin/env"],
    )
    .expect("trusted env helper");
    sandbox
        .add_isolated_runtime_file(&env_helper)
        .expect("bind exact helper alias");
    let canonical_env_helper = fs::canonicalize(&env_helper).expect("canonical env helper");
    sandbox
        .add_isolated_runtime_file(&canonical_env_helper)
        .expect("bind helper nested under visible Nix store");
    sandbox
        .add_private_runtime_root(&runtime)
        .expect("bind private runtime");
    assert!(sandbox.isolated_host_view);
    assert!(sandbox.mount_checks.iter().any(|check| {
        check.path == Path::new("/")
            && check.access == SandboxMountAccess::IsolatedRoot
            && !check.optional
    }));
    assert!(sandbox.visible_read_only_files.contains(&env_helper));
    assert!(sandbox
        .visible_read_only_files
        .contains(&canonical_env_helper));
    assert!(sandbox
        .mount_checks
        .iter()
        .any(|check| { check.path == env_helper && check.access == SandboxMountAccess::ReadOnly }));
    assert!(sandbox.mount_checks.iter().any(|check| {
        check.path == runtime && check.access == SandboxMountAccess::PrivateRuntime
    }));
    assert!(sandbox.mount_checks.iter().any(|check| {
        check.path == source && check.access == SandboxMountAccess::Inaccessible && !check.optional
    }));
    assert!(sandbox.mount_checks.iter().any(|check| {
        check.path == materialized
            && check.access == SandboxMountAccess::ReadOnly
            && !check.optional
    }));

    let mut command = Command::new("systemd-run");
    apply_systemd_sandbox_properties(&mut command, &sandbox);
    assert!(command
        .get_args()
        .any(|arg| arg == OsStr::new("--property=TemporaryFileSystem=/:ro")));
}

#[cfg(target_os = "linux")]
#[test]
fn isolated_root_property_requires_exact_single_read_only_root() {
    for value in ["/:ro", "  /:ro\n"] {
        assert!(
            is_exact_isolated_host_view_property(value),
            "expected exact isolated root property: {value:?}"
        );
    }

    for value in [
        "",
        "/tmp:ro",
        "/:ro /etc:ro",
        "/:ro /etc:rw",
        "/:ro /:ro",
        "/:rw",
        "/:ro,rw",
        "/:rw,ro",
        "/:ro,nodev",
        "/:",
        "/",
    ] {
        assert!(
            !is_exact_isolated_host_view_property(value),
            "unexpectedly accepted isolated root property: {value:?}"
        );
    }
}

#[cfg(target_os = "linux")]
#[test]
fn isolated_root_property_and_required_inaccessible_report_fail_closed() {
    let sandbox = ResolvedSystemdSandbox {
        kind: SideEffectConfinementProfileKind::StrictOfflineWorkspace,
        workspace_root: PathBuf::from("/view"),
        current_dir: PathBuf::from("/view"),
        workspace_access: WorkspaceAccess::ReadOnly,
        visible_read_only_roots: vec![PathBuf::from("/nix/store")],
        visible_read_only_files: Vec::new(),
        visible_read_write_roots: Vec::new(),
        visible_read_write_files: Vec::new(),
        external_codex_writable_file_capabilities: Vec::new(),
        external_grok_read_only_file_capabilities: Vec::new(),
        writable_artifact_roots: Vec::new(),
        hidden_roots: vec![PathBuf::from("/source")],
        isolated_host_view: true,
        resource_limits: ProcessResourceLimits::default(),
        path_identities: Vec::new(),
        mount_checks: Vec::new(),
    };
    let mut properties = BTreeMap::from([("TemporaryFileSystem".to_string(), "/:ro".to_string())]);
    verify_isolated_host_view_property(&sandbox, &properties)
        .expect("exact isolated root property");
    properties.insert("TemporaryFileSystem".to_string(), "/tmp:ro".to_string());
    assert!(verify_isolated_host_view_property(&sandbox, &properties).is_err());

    use std::os::unix::fs::PermissionsExt;
    let temp = tempfile::tempdir().expect("tempdir");
    let report = temp.path().join("report");
    fs::write(
            &report,
            "security 0000000000000000 0000000000000000 0000000000000000 0000000000000000 1 2\nisolated-root tmpfs tmpfs ro,nodev\ninaccessible\ninaccessible-missing\n",
        )
        .expect("write report");
    fs::set_permissions(&report, fs::Permissions::from_mode(0o600)).expect("report mode");
    let checks = vec![
        SandboxMountCheck {
            path: PathBuf::from("/"),
            device: 0,
            inode: 0,
            access: SandboxMountAccess::IsolatedRoot,
            optional: false,
        },
        SandboxMountCheck {
            path: PathBuf::from("/source"),
            device: 0,
            inode: 0,
            access: SandboxMountAccess::Inaccessible,
            optional: false,
        },
        SandboxMountCheck {
            path: PathBuf::from("/optional-socket"),
            device: 0,
            inode: 0,
            access: SandboxMountAccess::Inaccessible,
            optional: true,
        },
    ];
    verify_sandbox_mount_report(&report, &checks).expect("isolated mount evidence");
    fs::write(
            &report,
            "security 0000000000000000 0000000000000000 0000000000000000 0000000000000000 1 2\nisolated-root tmpfs tmpfs ro,nodev\ninaccessible-missing\ninaccessible-missing\n",
        )
        .expect("replace report");
    assert!(verify_sandbox_mount_report(&report, &checks).is_err());
    assert!(SYSTEMD_GUARDIAN_SCRIPT.contains("required inaccessible path was not mounted"));
}

#[cfg(target_os = "linux")]
#[test]
fn isolated_exact_bindings_are_order_independent_and_alias_mounts_bind_target_identity() {
    use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};

    let expected = BTreeSet::from([
        (PathBuf::from("/nix/store"), PathBuf::from("/nix/store")),
        (PathBuf::from("/review-view"), PathBuf::from("/review-view")),
        (PathBuf::from("/usr/bin/env"), PathBuf::from("/usr/bin/env")),
        (
            PathBuf::from("/nix/store/helper/bin/maco"),
            PathBuf::from("/nix/store/helper/bin/maco"),
        ),
    ]);
    verify_exact_property_bindings(
        "BindReadOnlyPaths",
        "/usr/bin/env /nix/store/helper/bin/maco /review-view /nix/store",
        &expected,
    )
    .expect("canonical binding set ignores property order");
    assert!(verify_exact_property_bindings(
        "BindReadOnlyPaths",
        "/usr/bin/env /nix/store/helper/bin/maco /review-view /nix/store /unexpected",
        &expected,
    )
    .is_err());

    let temp = tempfile::tempdir().expect("tempdir");
    let target = temp.path().join("target");
    let alias = temp.path().join("alias");
    fs::write(&target, "helper").expect("target");
    fs::set_permissions(&target, fs::Permissions::from_mode(0o500)).expect("target mode");
    symlink(&target, &alias).expect("alias");
    let target_metadata = fs::metadata(&alias).expect("follow alias metadata");
    let report = temp.path().join("report");
    fs::write(
            &report,
            format!(
                "security 0000000000000000 0000000000000000 0000000000000000 0000000000000000 1 2\nmounted {} {} ro\n",
                target_metadata.dev(),
                target_metadata.ino()
            ),
        )
        .expect("report");
    fs::set_permissions(&report, fs::Permissions::from_mode(0o600)).expect("report mode");
    verify_sandbox_mount_report(
        &report,
        &[SandboxMountCheck {
            path: alias,
            device: target_metadata.dev(),
            inode: target_metadata.ino(),
            access: SandboxMountAccess::ReadOnly,
            optional: false,
        }],
    )
    .expect("alias path may become a mounted regular target with the bound identity");
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires the trusted user-systemd/cgroup runtime; compile-only in claimed validation waves"]
fn trusted_network_profile_masks_repo_state_and_seals_private_objects() {
    let temp = tempfile::tempdir().expect("tempdir");
    let primary = temp.path().join("primary");
    let state = primary.join(".git/maco/state");
    let runtime = temp.path().join("runtime");
    let sealed_objects = runtime.join("objects");
    fs::create_dir_all(&state).expect("state");
    fs::create_dir_all(&sealed_objects).expect("sealed objects");
    fs::write(sealed_objects.join("visible"), "object").expect("visible object");
    fs::write(state.join("auth-key"), "secret").expect("state secret");
    let script = format!(
        "test -r '{}' && test ! -r '{}'",
        sealed_objects.join("visible").display(),
        state.join("auth-key").display()
    );
    let profile = TrustedFixedNetworkProfile::read_write(&runtime)
        .with_visible_read_only_root(&sealed_objects)
        .with_hidden_root(&primary);
    let output = run_process(
        ProcessSpec::direct(
            "trusted network mount denial",
            PathBuf::from("/bin/sh"),
            [OsString::from("-c"), OsString::from(script)],
            &runtime,
            1024,
        )
        .with_side_effect_confinement(SideEffectConfinementProfile::TrustedFixedNetwork(profile)),
    )
    .expect("run trusted network mount test");
    assert!(output.status.is_some_and(|status| status.success()));
    assert_eq!(
        output.side_effects,
        SideEffectConfinementEvidence::Verified(
            SideEffectConfinementProfileKind::TrustedFixedNetwork
        )
    );
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires the trusted user-systemd/cgroup runtime; compile-only in claimed validation waves"]
fn trusted_network_profile_bounds_timeout_output_and_cleanup() {
    let temp = tempfile::tempdir().expect("tempdir");
    let output = run_process(
        ProcessSpec::direct(
            "trusted network bounded output",
            PathBuf::from("/bin/sh"),
            [OsString::from("-c"), OsString::from("printf 123456789")],
            temp.path(),
            8,
        )
        .with_side_effect_confinement(SideEffectConfinementProfile::TrustedFixedNetwork(
            TrustedFixedNetworkProfile::read_write(temp.path()),
        )),
    )
    .expect("run bounded output test");
    assert!(output.stdout.is_truncated());
    assert!(output.process_tree.is_verified_empty());

    let timeout = run_process(
        ProcessSpec::direct(
            "trusted network bounded timeout",
            PathBuf::from("/bin/sh"),
            [OsString::from("-c"), OsString::from("sleep 30")],
            temp.path(),
            128,
        )
        .with_side_effect_confinement(SideEffectConfinementProfile::TrustedFixedNetwork(
            TrustedFixedNetworkProfile::read_write(temp.path()),
        ))
        .with_timeout(Some(Duration::from_millis(50))),
    )
    .expect("run timeout test");
    assert!(timeout.timed_out);
    assert!(timeout.process_tree.is_verified_empty());
}

#[test]
fn required_confinement_rejects_existing_tee_before_target_start() {
    let temp = tempfile::tempdir().expect("tempdir");
    let tee = temp.path().join("existing.log");
    let marker = temp.path().join("target-ran");
    fs::write(&tee, "preserve").expect("seed existing tee");
    let error = run_process(
        ProcessSpec::shell(
            "strict existing tee",
            Shell::for_current_platform(),
            format!("touch '{}'", marker.display()),
            temp.path(),
            128,
        )
        .with_stdout(StreamCapture::bounded(128).tee_to(&tee)),
    )
    .expect_err("required mode must reject an existing tee");

    assert!(matches!(error, ProcessRunError::OpenTee { .. }));
    assert_eq!(fs::read_to_string(tee).expect("preserved tee"), "preserve");
    assert!(!marker.exists());
}

#[cfg(target_os = "linux")]
#[test]
fn sandbox_scan_rejects_fifo_and_external_hardlink_alias() {
    use std::os::unix::ffi::OsStrExt;

    let temp = tempfile::tempdir().expect("tempdir");
    let workspace = temp.path().join("workspace");
    fs::create_dir(&workspace).expect("workspace");
    let fifo = workspace.join("ipc");
    let fifo_name = std::ffi::CString::new(fifo.as_os_str().as_bytes()).expect("fifo path");
    // SAFETY: fifo_name is a valid NUL-terminated path and mode has no invalid bits.
    assert_eq!(unsafe { libc::mkfifo(fifo_name.as_ptr(), 0o600) }, 0);
    let sandbox = ResolvedSystemdSandbox {
        kind: SideEffectConfinementProfileKind::StrictOfflineWorkspace,
        workspace_root: workspace.clone(),
        current_dir: workspace.clone(),
        workspace_access: WorkspaceAccess::ReadWrite,
        visible_read_only_roots: Vec::new(),
        visible_read_only_files: Vec::new(),
        visible_read_write_roots: Vec::new(),
        visible_read_write_files: Vec::new(),
        external_codex_writable_file_capabilities: Vec::new(),
        external_grok_read_only_file_capabilities: Vec::new(),
        writable_artifact_roots: Vec::new(),
        hidden_roots: Vec::new(),
        isolated_host_view: false,
        resource_limits: ProcessResourceLimits::default(),
        path_identities: Vec::new(),
        mount_checks: Vec::new(),
    };
    assert!(sandbox.verify_no_special_entries().is_err());

    fs::remove_file(&fifo).expect("remove fifo");
    let outside = temp.path().join("outside");
    fs::write(&outside, "outside").expect("outside file");
    fs::hard_link(&outside, workspace.join("alias")).expect("external hardlink alias");
    assert!(sandbox.verify_no_special_entries().is_err());
}

#[cfg(target_os = "linux")]
#[test]
fn unit_mount_report_binds_identity_access_and_inaccessibility() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let temp = tempfile::tempdir().expect("tempdir");
    let visible = temp.path().join("visible");
    fs::write(&visible, "visible").expect("visible");
    let metadata = fs::metadata(&visible).expect("visible metadata");
    let report = temp.path().join("report");
    fs::write(
            &report,
            format!(
                "security 0000000000000000 0000000000000000 0000000000000000 0000000000000000 1 2\nmounted {} {} ro\ninaccessible\n",
                metadata.dev(),
                metadata.ino()
            ),
        )
        .expect("report");
    fs::set_permissions(&report, fs::Permissions::from_mode(0o600)).expect("report mode");
    let checks = vec![
        SandboxMountCheck {
            path: visible,
            device: metadata.dev(),
            inode: metadata.ino(),
            access: SandboxMountAccess::ReadOnly,
            optional: false,
        },
        SandboxMountCheck {
            path: PathBuf::from("/masked"),
            device: 0,
            inode: 0,
            access: SandboxMountAccess::Inaccessible,
            optional: false,
        },
    ];

    verify_sandbox_mount_report(&report, &checks).expect("valid unit mount report");
    fs::write(
            &report,
            format!(
                "security 0000000000000000 0000000000000000 0000000000000000 0000000000000000 1 2\nmounted {} {} rw\ninaccessible\n",
                metadata.dev(),
                metadata.ino()
            ),
        )
        .expect("replace report");
    assert!(verify_sandbox_mount_report(&report, &checks).is_err());
}

#[cfg(target_os = "linux")]
#[test]
fn system_call_error_number_accepts_name_and_numeric_eperm_only() {
    verify_system_call_error_number("EPERM").expect("named EPERM");
    verify_system_call_error_number(&libc::EPERM.to_string()).expect("numeric EPERM");
    assert!(verify_system_call_error_number("0").is_err());
    assert!(verify_system_call_error_number("EACCES").is_err());
}

#[cfg(target_os = "linux")]
#[test]
fn system_call_filter_accepts_retained_and_complete_expanded_deny_forms() {
    let retained = retained_system_call_filter_fixture();
    verify_effective_system_call_filter(
        SideEffectConfinementProfileKind::StrictOfflineWorkspace,
        &retained,
    )
    .expect("retained deny groups");

    let expanded = expanded_system_call_filter_fixture();
    verify_effective_system_call_filter(
        SideEffectConfinementProfileKind::StrictOfflineWorkspace,
        &expanded.join(" "),
    )
    .expect("complete expanded deny groups");
}

#[cfg(target_os = "linux")]
#[test]
fn external_codex_alone_admits_inner_bubblewrap_namespaces_and_mounts() {
    let mut external = program_visibility_sandbox(Path::new("/worktree"));
    external.kind = SideEffectConfinementProfileKind::ExternalCodex;
    let mut command = Command::new("systemd-run");
    apply_systemd_sandbox_properties(&mut command, &external);
    let arguments = command
        .get_args()
        .map(|argument| argument.to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    assert!(arguments
        .iter()
        .any(|argument| argument == "--property=RestrictNamespaces=no"));
    assert!(arguments.iter().any(|argument| {
        argument == "--property=RestrictAddressFamilies=AF_INET AF_INET6 AF_NETLINK"
    }));
    let external_filter = arguments
        .iter()
        .find_map(|argument| argument.strip_prefix("--property=SystemCallFilter="))
        .expect("ExternalCodex syscall filter");
    verify_effective_system_call_filter(
        SideEffectConfinementProfileKind::ExternalCodex,
        external_filter,
    )
    .expect("ExternalCodex bubblewrap-compatible deny list");
    verify_effective_namespace_restriction(SideEffectConfinementProfileKind::ExternalCodex, "no")
        .expect("ExternalCodex namespaces are available to bubblewrap");
    assert!(verify_effective_namespace_restriction(
        SideEffectConfinementProfileKind::ExternalCodex,
        "yes",
    )
    .is_err());

    for kind in [
        SideEffectConfinementProfileKind::StrictOfflineWorkspace,
        SideEffectConfinementProfileKind::TrustedFixedNetwork,
        SideEffectConfinementProfileKind::ExternalGrok,
        SideEffectConfinementProfileKind::TrustedCompatibility,
    ] {
        let mut ordinary = program_visibility_sandbox(Path::new("/worktree"));
        ordinary.kind = kind;
        let mut command = Command::new("systemd-run");
        apply_systemd_sandbox_properties(&mut command, &ordinary);
        let arguments = command
            .get_args()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert!(
            arguments
                .iter()
                .any(|argument| argument == "--property=RestrictNamespaces=yes"),
            "{kind:?} namespace confinement changed"
        );
        let expected_address_families = match kind {
            SideEffectConfinementProfileKind::StrictOfflineWorkspace => {
                "--property=RestrictAddressFamilies=AF_UNIX"
            }
            SideEffectConfinementProfileKind::TrustedFixedNetwork
            | SideEffectConfinementProfileKind::TrustedCompatibility => {
                "--property=RestrictAddressFamilies=AF_INET AF_INET6"
            }
            SideEffectConfinementProfileKind::ExternalGrok => {
                "--property=RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6"
            }
            SideEffectConfinementProfileKind::ExternalCodex => {
                unreachable!("ExternalCodex is checked separately")
            }
        };
        assert!(
            arguments
                .iter()
                .any(|argument| argument == expected_address_families),
            "{kind:?} address-family confinement changed"
        );
        assert!(
            arguments
                .iter()
                .all(|argument| !argument.contains("AF_NETLINK")),
            "{kind:?} unexpectedly gained AF_NETLINK"
        );
        let filter = arguments
            .iter()
            .find_map(|argument| argument.strip_prefix("--property=SystemCallFilter="))
            .unwrap_or_else(|| panic!("{kind:?} syscall filter"));
        verify_effective_system_call_filter(kind, filter)
            .unwrap_or_else(|error| panic!("{kind:?} syscall confinement changed: {error}"));
        verify_effective_namespace_restriction(kind, "yes")
            .unwrap_or_else(|error| panic!("{kind:?} namespace verification changed: {error}"));
        assert!(verify_effective_namespace_restriction(kind, "no").is_err());
        assert!(filter
            .split_whitespace()
            .any(|token| token.trim_start_matches('~') == "@mount"));
    }

    let ordinary_filter = retained_system_call_filter_fixture();
    assert!(verify_effective_system_call_filter(
        SideEffectConfinementProfileKind::ExternalCodex,
        &ordinary_filter,
    )
    .is_err());
    assert!(verify_effective_system_call_filter(
        SideEffectConfinementProfileKind::TrustedFixedNetwork,
        external_filter,
    )
    .is_err());
}

#[cfg(target_os = "linux")]
#[test]
fn system_call_filter_rejects_each_incomplete_group_and_allow_list() {
    let expanded = expanded_system_call_filter_fixture();
    for (group, representatives) in required_denied_group_representatives() {
        let Some(missing) = representatives.first() else {
            continue;
        };
        let incomplete = expanded
            .iter()
            .filter(|token| token.trim_start_matches('~') != *missing)
            .cloned()
            .collect::<Vec<_>>()
            .join(" ");
        let error = verify_effective_system_call_filter(
            SideEffectConfinementProfileKind::StrictOfflineWorkspace,
            &incomplete,
        )
        .expect_err("incomplete group expansion must fail closed");
        assert!(
            error.to_string().contains(group),
            "unexpected {group} failure: {error}"
        );
    }
    assert!(verify_effective_system_call_filter(
        SideEffectConfinementProfileKind::StrictOfflineWorkspace,
        "read write exit exit_group",
    )
    .is_err());
}

#[cfg(target_os = "linux")]
fn retained_system_call_filter_fixture() -> String {
    let mut tokens = required_denied_group_representatives()
        .into_iter()
        .map(|(group, _)| group.to_string())
        .collect::<Vec<_>>();
    tokens[0].insert(0, '~');
    tokens.extend(
        REQUIRED_DENIED_SYSCALLS
            .iter()
            .map(|value| value.to_string()),
    );
    tokens.extend(["socket", "socketpair", "socketcall"].map(str::to_string));
    tokens.join(" ")
}

#[cfg(target_os = "linux")]
fn expanded_system_call_filter_fixture() -> Vec<String> {
    let mut tokens = vec!["~expanded-deny-list".to_string()];
    for (group, representatives) in required_denied_group_representatives() {
        if representatives.is_empty() {
            tokens.push(group.to_string());
        } else {
            tokens.extend(representatives.iter().map(|value| value.to_string()));
        }
    }
    tokens.extend(
        REQUIRED_DENIED_SYSCALLS
            .iter()
            .map(|value| value.to_string()),
    );
    tokens.extend(["socket", "socketpair", "socketcall"].map(str::to_string));
    tokens
}

#[cfg(unix)]
#[test]
fn drains_large_stdout_and_stderr_without_false_timeout() {
    let temp = tempfile::tempdir().expect("tempdir");
    let output_log = temp.path().join("stdout.log");
    let spec = ProcessSpec::shell(
            "large-output command",
            Shell::UnixSh,
            "i=0; while [ \"$i\" -lt 256 ]; do printf '%4096s' O; i=$((i + 1)); done; i=0; while [ \"$i\" -lt 256 ]; do printf '%4096s' E >&2; i=$((i + 1)); done",
            temp.path(),
            16 * 1024,
        )
        .with_containment(ContainmentPolicy::TrustedBestEffort)
        // The timeout is a liveness fuse for a functional pipe-drain test, not a throughput
        // benchmark. Thirty seconds is intentionally far above the 2 MiB fixture's ordinary
        // runtime; expiry means the drain stopped making progress, not ordinary scheduler jitter.
        .with_timeout(Some(Duration::from_secs(30)))
        .with_stdout(StreamCapture::bounded(16 * 1024).tee_to(&output_log));

    let output = run_process(spec).expect("run large-output command");

    assert!(output.status.is_some_and(|status| status.success()));
    assert!(!output.timed_out);
    assert!(output.stdout.is_truncated());
    assert!(output.stderr.is_truncated());
    assert_eq!(output.stdout.as_bytes().len(), 16 * 1024);
    assert_eq!(output.stderr.as_bytes().len(), 16 * 1024);
    assert!(
        std::fs::metadata(&output_log)
            .expect("stdout log metadata")
            .len()
            >= 256 * 4096
    );
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(
        std::fs::metadata(&output_log)
            .expect("stdout log permissions")
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
}

#[cfg(unix)]
#[test]
fn continuous_output_does_not_starve_timeout_polling() {
    let temp = tempfile::tempdir().expect("tempdir");
    let spec = ProcessSpec::shell(
        "continuous-output command",
        Shell::UnixSh,
        "trap '' TERM; while :; do printf '%4096s' O; printf '%4096s' E >&2; done",
        temp.path(),
        1024,
    )
    .with_containment(ContainmentPolicy::TrustedBestEffort)
    .with_timeout(Some(Duration::from_secs(1)));
    let started = Instant::now();

    let output = run_process(spec).expect("run continuous-output command");
    let elapsed = started.elapsed();

    assert!(output.timed_out);
    assert!(output.stdout.is_truncated());
    assert!(output.stderr.is_truncated());
    assert!(elapsed >= Duration::from_millis(900));
    // Real timeout polling is the subject here. The upper bound is deliberately ten times the
    // requested timeout so a failure means continuous backlog prevented timeout observation,
    // not that a loaded host scheduled the runner a few milliseconds late.
    assert!(
        elapsed < Duration::from_secs(10),
        "continuous output delayed the one-second timeout for {elapsed:?}"
    );
}

#[cfg(unix)]
#[test]
fn cancellation_terminates_owned_process_group_and_delayed_descendant() {
    let temp = tempfile::tempdir().expect("tempdir");
    let ready = temp.path().join("ready");
    let delayed = temp.path().join("delayed");
    let release_delayed = temp.path().join("release-delayed");
    let descendant_pid = temp.path().join("descendant.pid");
    let command = format!(
            "(while [ ! -e '{}' ]; do sleep 0.01; done; touch '{}') & descendant=$!; echo \"$descendant\" > '{}'; touch '{}'; trap '' TERM; while :; do sleep 1; done",
            release_delayed.display(),
            delayed.display(),
            descendant_pid.display(),
            ready.display(),
        );
    let cancellation = ProcessCancellation::new();
    let worker_cancellation = cancellation.clone();
    let workdir = temp.path().to_path_buf();
    let worker = thread::spawn(move || {
        run_process_cancellable(
            ProcessSpec::shell(
                "cancellable process group",
                Shell::UnixSh,
                command,
                workdir,
                1024,
            )
            .with_containment(ContainmentPolicy::TrustedBestEffort)
            .with_timeout(Some(Duration::from_secs(5))),
            &worker_cancellation,
        )
    });

    while !ready.exists() && !worker.is_finished() {
        thread::sleep(POLL_INTERVAL);
    }
    assert!(
        ready.exists(),
        "process runner completed before the child reached its ready gate"
    );
    cancellation.cancel();
    let output = worker
        .join()
        .unwrap_or_else(|_| panic!("cancellable runner thread panicked"))
        .expect("cancel contained process group");

    assert!(!output.timed_out);
    assert!(output
        .process_error
        .as_deref()
        .is_some_and(|error| error.contains("cancelled")));
    let pid = fs::read_to_string(descendant_pid).expect("cancelled descendant pid");
    assert_process_not_executable(&pid, "cancelled descendant");
    fs::write(release_delayed, b"release").expect("release any surviving descendant");
    assert!(!delayed.exists());
}

#[cfg(unix)]
#[test]
fn completion_first_observed_after_deadline_is_a_timeout() {
    let started = Instant::now();
    let deadline = started
        .checked_add(Duration::from_millis(50))
        .expect("representable deadline");
    let before_deadline = started
        .checked_add(Duration::from_millis(40))
        .expect("representable early observation");
    let after_deadline = started
        .checked_add(Duration::from_millis(60))
        .expect("representable late observation");

    assert_eq!(
        process_loop_decision(true, false, Some(deadline), before_deadline),
        ProcessLoopDecision::Complete
    );
    assert_eq!(
        process_loop_decision(true, false, Some(deadline), after_deadline),
        ProcessLoopDecision::Timeout
    );
}

#[cfg(unix)]
#[test]
fn normal_exit_terminates_descendants_holding_pipes() {
    const WHOLE_CALL_BOUND: Duration = Duration::from_secs(3);

    let temp = tempfile::tempdir().expect("tempdir");
    let descendant_pid = temp.path().join("descendant.pid");
    let command = format!(
            "(trap '' TERM; echo descendant-started; echo descendant-error >&2; while :; do sleep 1; done) & descendant=$!; echo \"$descendant\" > '{}'; echo parent-exiting",
            descendant_pid.display()
        );
    let spec = ProcessSpec::shell(
        "hung command",
        Shell::UnixSh,
        command,
        temp.path(),
        8 * 1024,
    )
    .with_containment(ContainmentPolicy::TrustedBestEffort)
    .with_timeout(Some(Duration::from_secs(2)));

    let (completion_tx, completion_rx) = mpsc::channel();
    // Start before `thread::spawn`: worker creation and scheduling are part of the whole call.
    let whole_call_started = Instant::now();
    let _worker = thread::spawn(move || {
        let _ = completion_tx.send(run_process(spec));
    });
    // Prompt whole-call completion is the contract here. The event is emitted only after
    // `run_process` has completed process-tree cleanup, pipe finalization, and its internal
    // joins. Three seconds preserves the original bound; expiry means lifecycle completion
    // itself stopped being prompt. There is no unbounded JoinHandle wait on this path.
    let completion = completion_rx
        .recv_timeout(WHOLE_CALL_BOUND.saturating_sub(whole_call_started.elapsed()))
        .expect("descendant pipe lifecycle completed within its three-second contract");
    let whole_call_elapsed = whole_call_started.elapsed();
    assert!(
            whole_call_elapsed < WHOLE_CALL_BOUND,
            "descendant pipe lifecycle exceeded its whole-call three-second contract: {whole_call_elapsed:?}"
        );
    let output = completion.expect("run descendant-spawning command");

    assert!(!output.timed_out);
    assert!(output.status.is_some_and(|status| status.success()));
    assert_eq!(output.process_error, None);
    assert!(output
        .stdout
        .summarize_chars(8 * 1024)
        .text
        .contains("descendant-started"));
    assert!(output
        .stderr
        .summarize_chars(8 * 1024)
        .text
        .contains("descendant-error"));
    let pid = std::fs::read_to_string(descendant_pid).expect("descendant pid");
    assert_process_gone(&pid, "output-pipe descendant");
}

#[cfg(unix)]
#[test]
fn normal_exit_kills_delayed_background_mutation_before_return() {
    let temp = tempfile::tempdir().expect("tempdir");
    let marker = temp.path().join("delayed-mutation");
    let release = temp.path().join("release-delayed-mutation");
    let descendant_pid = temp.path().join("delayed-descendant.pid");
    let command = format!(
        "(while [ ! -e '{}' ]; do sleep 0.01; done; touch '{}') >/dev/null 2>&1 & echo $! > '{}'",
        release.display(),
        marker.display(),
        descendant_pid.display(),
    );
    let spec = ProcessSpec::shell(
        "delayed descendant command",
        Shell::UnixSh,
        command,
        temp.path(),
        1024,
    )
    .with_containment(ContainmentPolicy::TrustedBestEffort)
    .with_timeout(Some(Duration::from_secs(2)));

    let output = run_process(spec).expect("run delayed descendant command");

    assert!(output.status.is_some_and(|status| status.success()));
    assert!(!output.timed_out);
    let pid = fs::read_to_string(descendant_pid).expect("delayed descendant pid");
    assert_process_not_executable(&pid, "delayed-mutation descendant");
    fs::write(release, b"release").expect("release any surviving delayed mutation");
    assert!(!marker.exists());
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires the trusted user-systemd/cgroup runtime; compile-only in claimed validation waves"]
fn required_containment_verifies_normal_nonzero_and_timeout_units_empty() {
    let temp = tempfile::tempdir().expect("tempdir");
    let unit_capture = TestSystemdUnitNameCapture::start();
    let normal = run_process(
        ProcessSpec::shell(
            "normal contained command",
            Shell::UnixSh,
            "exit 0",
            temp.path(),
            128,
        )
        .with_timeout(Some(Duration::from_secs(2))),
    );
    let unit_names = unit_capture.finish();
    let normal = match normal {
        Ok(output) => output,
        Err(error) if is_verified_backend_unavailable(&error) => {
            report_verified_backend_unavailable_skip(&error, &unit_names);
            return;
        }
        Err(error) => panic!("run normal contained command: {error:?}"),
    };
    assert!(normal.status.is_some_and(|status| status.success()));
    assert!(normal.process_tree.is_verified_empty());
    assert_eq!(normal.process_error, None);

    let nonzero = run_process(
        ProcessSpec::shell(
            "nonzero contained command",
            Shell::UnixSh,
            "exit 7",
            temp.path(),
            128,
        )
        .with_timeout(Some(Duration::from_secs(2))),
    )
    .expect("run nonzero contained command");
    assert_eq!(nonzero.status.and_then(|status| status.code()), Some(7));
    assert!(nonzero.process_tree.is_verified_empty());
    assert_eq!(nonzero.process_error, None);

    let timed_out = run_process(
        ProcessSpec::shell(
            "timed out contained command",
            Shell::UnixSh,
            "sleep 30",
            temp.path(),
            128,
        )
        .with_timeout(Some(Duration::from_secs(2))),
    )
    .expect("run timed out contained command");
    assert!(timed_out.timed_out);
    assert!(
        timed_out.process_tree.is_verified_empty(),
        "timed out strict run did not prove cleanup: {timed_out:?}"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn unsupported_path_masking_refuses_before_target_and_leaves_no_residue() {
    skip_without_containment!();
    let temp = tempfile::tempdir().expect("tempdir");
    let marker = temp.path().join("target-ran");
    let unit_capture = TestSystemdUnitNameCapture::start();
    let result = run_process(
        ProcessSpec::shell(
            "path-mask enforcement probe",
            Shell::UnixSh,
            format!("touch '{}'", marker.display()),
            temp.path(),
            256,
        )
        .with_timeout(Some(CONTENTION_RESILIENT_PROCESS_TEST_TIMEOUT)),
    );
    let unit_names = unit_capture.finish();

    match result {
        Ok(output) => {
            assert!(output.safety_evidence_verified());
            assert!(marker.exists());
        }
        Err(error) if is_verified_backend_unavailable(&error) => {
            assert!(!marker.exists());
            report_verified_backend_unavailable_skip(&error, &unit_names);
        }
        Err(error) => panic!("unexpected strict backend probe failure: {error:?}"),
    }
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires the trusted user-systemd/cgroup runtime; compile-only in claimed validation waves"]
fn inaccessible_placeholder_blocks_nix_daemon_socket_access() {
    use std::os::unix::net::UnixStream;

    const CHILD_ENV: &str = "MACO_TEST_INACCESSIBLE_SOCKET_CHILD";
    const SOCKET_PATH: &str = "/nix/var/nix/daemon-socket/socket";
    if env::var_os(CHILD_ENV).is_some() {
        let marker = PathBuf::from(
            env::var_os("MACO_TEST_INACCESSIBLE_SOCKET_MARKER").expect("marker path"),
        );
        let open_error = File::open(SOCKET_PATH).expect_err("masked socket must not open");
        let connect_error =
            UnixStream::connect(SOCKET_PATH).expect_err("masked socket must not connect");
        fs::write(
            marker,
            format!(
                "open={:?};connect={:?}\n",
                open_error.raw_os_error(),
                connect_error.raw_os_error()
            ),
        )
        .expect("write inaccessible-socket evidence");
        return;
    }
    match UnixStream::connect(SOCKET_PATH) {
        Ok(control) => drop(control),
        Err(error) => {
            eprintln!(
                    "skipping inaccessible-placeholder causal probe because the host Nix daemon socket is unavailable: {error}"
                );
            return;
        }
    }
    if !strict_backend_available_for_tests() {
        return;
    }

    let temp = tempfile::tempdir().expect("tempdir");
    let marker = temp.path().join("socket-access-blocked");
    let mut environment = BTreeMap::new();
    environment.insert(CHILD_ENV.to_string(), "1".to_string());
    environment.insert(
        "MACO_TEST_INACCESSIBLE_SOCKET_MARKER".to_string(),
        marker.display().to_string(),
    );
    let unit_capture = TestSystemdUnitNameCapture::start();
    let output = run_process(
        ProcessSpec::direct(
            "inaccessible socket placeholder probe",
            env::current_exe().expect("current test executable"),
            [
                OsString::from("--exact"),
                OsString::from(
                    "process_runner::tests::inaccessible_placeholder_blocks_nix_daemon_socket_access",
                ),
            ],
            temp.path(),
            4 * 1024,
        )
        .with_environment(EnvironmentMode::InheritAndSet(environment))
        .with_timeout(Some(Duration::from_secs(5))),
    );
    let unit_names = unit_capture.finish();
    let output = output.expect("run inaccessible socket placeholder probe");

    assert!(output.status.is_some_and(|status| status.success()));
    assert!(output.safety_evidence_verified());
    let evidence = fs::read_to_string(&marker).expect("socket denial evidence");
    assert!(evidence.contains("open=Some("));
    assert!(evidence.contains("connect=Some("));
    assert!(
        !unit_names.is_empty(),
        "strict run allocated no systemd unit"
    );
    assert_systemd_units_have_no_residue(&unit_names);
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires the trusted user-systemd/cgroup runtime; compile-only in claimed validation waves"]
fn one_cancellation_cleans_two_simultaneous_strict_process_trees() {
    let temp = tempfile::tempdir().expect("tempdir");
    let cancellation = ProcessCancellation::new();
    let mut workers = Vec::new();
    let mut ready_paths = Vec::new();
    for index in 0..2usize {
        let ready = temp.path().join(format!("ready-{index}"));
        ready_paths.push(ready.clone());
        let workdir = temp.path().to_path_buf();
        let worker_cancellation = cancellation.clone();
        workers.push(thread::spawn(move || {
            let unit_capture = TestSystemdUnitNameCapture::start();
            let result = run_process_cancellable(
                ProcessSpec::shell(
                    format!("simultaneous cancellable process {index}"),
                    Shell::UnixSh,
                    format!(
                        "touch '{}'; trap '' TERM; while :; do sleep 1; done",
                        ready.display()
                    ),
                    workdir,
                    1024,
                )
                .with_timeout(Some(Duration::from_secs(10))),
                &worker_cancellation,
            );
            (result, unit_capture.finish())
        }));
    }

    while !ready_paths.iter().all(|path| path.exists())
        && workers.iter().any(|worker| !worker.is_finished())
    {
        thread::sleep(POLL_INTERVAL);
    }
    cancellation.cancel();
    let results = workers
        .into_iter()
        .map(|worker| {
            worker
                .join()
                .unwrap_or_else(|_| panic!("strict cancellation worker panicked"))
        })
        .collect::<Vec<_>>();
    let unit_names = results
        .iter()
        .flat_map(|(_, unit_names)| unit_names.iter().cloned())
        .collect::<Vec<_>>();

    if let Some(error) = results
        .iter()
        .filter_map(|(result, _)| result.as_ref().err())
        .find(|error| is_verified_backend_unavailable(error))
    {
        report_verified_backend_unavailable_skip(error, &unit_names);
        return;
    }
    assert!(ready_paths.iter().all(|path| path.exists()));
    for (output, _) in results {
        let output = output.expect("cancel strict contained process");
        assert!(output.process_tree.is_verified_empty());
        assert!(output.side_effects.is_verified());
        assert!(output
            .process_error
            .as_deref()
            .is_some_and(|error| error.contains("cancelled")));
    }
    assert!(
        !unit_names.is_empty(),
        "strict runs allocated no systemd units"
    );
    assert_systemd_units_have_no_residue(&unit_names);
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires the trusted user-systemd/cgroup runtime; compile-only in claimed validation waves"]
fn exact_git_read_roots_do_not_expose_private_tmp_sibling() {
    if !strict_backend_available_for_tests() {
        return;
    }

    let temp = tempfile::tempdir().expect("tempdir");
    let workspace = temp.path().join("bounded-runtime");
    let worktree = temp.path().join("verified-worktree");
    let objects = temp.path().join("verified-common-objects");
    let sibling = temp.path().join("unrelated-sibling");
    for directory in [&workspace, &worktree, &objects, &sibling] {
        fs::create_dir(directory).expect("create sandbox fixture directory");
    }
    fs::write(worktree.join("tracked"), "tracked\n").expect("worktree marker");
    fs::write(objects.join("object"), "object\n").expect("objects marker");
    fs::write(sibling.join("sentinel"), "untouched\n").expect("sibling sentinel");
    let completed = workspace.join("completed");
    let command = format!(
        "test -r '{}' && test -r '{}' && test ! -e '{}' && touch '{}'",
        worktree.join("tracked").display(),
        objects.join("object").display(),
        sibling.join("sentinel").display(),
        completed.display()
    );
    let profile = StrictOfflineWorkspaceProfile::read_write(&workspace)
        .with_visible_read_only_root(&worktree)
        .with_visible_read_only_root(&objects);
    let unit_capture = TestSystemdUnitNameCapture::start();
    let output = run_process(
        ProcessSpec::shell(
            "exact bounded Git read roots",
            Shell::UnixSh,
            command,
            &workspace,
            1024,
        )
        .with_side_effect_confinement(SideEffectConfinementProfile::StrictOfflineWorkspace(
            profile,
        ))
        .with_timeout(Some(Duration::from_secs(3))),
    );
    let unit_names = unit_capture.finish();
    let output = output.expect("run exact bounded Git read-root probe");

    assert!(output.status.is_some_and(|status| status.success()));
    assert!(output.safety_evidence_verified());
    assert!(completed.is_file());
    assert_eq!(
        fs::read_to_string(sibling.join("sentinel")).expect("preserved sibling sentinel"),
        "untouched\n"
    );
    assert!(
        !unit_names.is_empty(),
        "strict run allocated no systemd unit"
    );
    assert_systemd_units_have_no_residue(&unit_names);
}

#[cfg(target_os = "linux")]
#[test]
fn strict_target_cannot_launch_sibling_user_unit() {
    skip_without_containment!();
    if !strict_backend_available_for_tests() {
        return;
    }
    let temp = tempfile::tempdir().expect("tempdir");
    let marker = temp.path().join("sibling-unit-ran");
    let release = temp.path().join("release-sibling-unit");
    let unit = format!(
        "maco-escape-test-{}-{}",
        std::process::id(),
        NEXT_SYSTEMD_UNIT_ID.fetch_add(1, Ordering::Relaxed)
    );
    let systemd_run = trusted_system_executable(
        "systemd-run",
        &[
            "/run/current-system/sw/bin/systemd-run",
            "/usr/bin/systemd-run",
            "/bin/systemd-run",
        ],
    )
    .expect("trusted systemd-run");
    let shell = trusted_system_executable(
        "sh",
        &["/run/current-system/sw/bin/sh", "/usr/bin/sh", "/bin/sh"],
    )
    .expect("trusted shell");
    let command = format!(
        r#"'{}' --user --quiet --collect --unit '{}' -- '{}' -c "while [ ! -e '{}' ]; do sleep 0.01; done; touch '{}'"#,
        systemd_run.display(),
        unit,
        shell.display(),
        release.display(),
        marker.display()
    );
    let output = run_process(
        ProcessSpec::shell(
            "sibling systemd escape",
            Shell::UnixSh,
            command,
            temp.path(),
            4096,
        )
        .with_timeout(Some(Duration::from_secs(3))),
    )
    .expect("run blocked sibling-unit attempt");

    assert!(!output.status.is_some_and(|status| status.success()));
    assert!(output.process_tree.is_verified_empty());
    assert!(output.side_effects.is_verified());

    let systemctl = trusted_system_executable(
        "systemctl",
        &[
            "/run/current-system/sw/bin/systemctl",
            "/usr/bin/systemctl",
            "/bin/systemctl",
        ],
    )
    .expect("trusted systemctl");
    let status = Command::new(&systemctl)
        .args(["--user", "--quiet", "is-active", &unit])
        .status()
        .expect("query sibling unit");
    if status.success() {
        let _ = Command::new(&systemctl)
            .args(["--user", "stop", &unit])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
    assert!(!status.success(), "sibling transient unit survived");
    assert!(!marker.exists(), "sibling transient unit mutated the host");
}

#[cfg(target_os = "linux")]
#[test]
fn strict_target_cannot_create_hardlinks_or_fifos_after_start_gate() {
    skip_without_containment!();
    if !strict_backend_available_for_tests() {
        return;
    }
    let temp = tempfile::tempdir().expect("tempdir");
    fs::write(temp.path().join("source"), "source").expect("source");
    let output = run_process(
        ProcessSpec::shell(
            "post-gate IPC creation",
            Shell::UnixSh,
            "ln source alias >/dev/null 2>&1 || :; mkfifo fifo >/dev/null 2>&1 || :",
            temp.path(),
            128,
        )
        .with_timeout(Some(Duration::from_secs(2))),
    )
    .expect("run post-gate creation attempts");

    assert!(output.status.is_some_and(|status| status.success()));
    assert!(output.safety_evidence_verified());
    assert!(!temp.path().join("alias").exists());
    assert!(!temp.path().join("fifo").exists());
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires the trusted user-systemd/cgroup runtime; compile-only in claimed validation waves"]
fn strict_target_cannot_create_network_or_sysv_ipc_endpoints() {
    let temp = tempfile::tempdir().expect("tempdir");
    let marker = temp.path().join("all-blocked");
    let python = trusted_system_executable(
        "python3",
        &[
            "/run/current-system/sw/bin/python3",
            "/usr/bin/python3",
            "/bin/python3",
        ],
    )
    .expect("trusted python3");
    let probe = r#"
import ctypes
import errno
import pathlib
import socket
import sys

try:
    socket.socket(socket.AF_INET, socket.SOCK_STREAM)
except OSError as error:
    if error.errno != errno.EPERM:
        raise
else:
    raise SystemExit("IPv4 socket creation unexpectedly succeeded")

libc = ctypes.CDLL(None, use_errno=True)
probes = [
    ("shmget", (0, 4096, 0o600), libc.shmctl),
    ("msgget", (0, 0o600), libc.msgctl),
    ("semget", (0, 1, 0o600), libc.semctl),
]
for name, arguments, cleanup in probes:
    ctypes.set_errno(0)
    identifier = getattr(libc, name)(*arguments)
    error = ctypes.get_errno()
    if identifier != -1:
        cleanup(identifier, 0, 0)
        raise SystemExit(f"{name} unexpectedly succeeded")
    if error != errno.EPERM:
        raise OSError(error, f"{name} returned an unexpected error")

pathlib.Path(sys.argv[1]).write_text("blocked\n", encoding="utf-8")
"#;
    let unit_capture = TestSystemdUnitNameCapture::start();
    let result = run_process(
        ProcessSpec::direct(
            "network and SysV IPC denial probe",
            python,
            vec![
                OsString::from("-c"),
                OsString::from(probe),
                marker.as_os_str().to_os_string(),
            ],
            temp.path(),
            4096,
        )
        .with_timeout(Some(Duration::from_secs(3))),
    );
    let unit_names = unit_capture.finish();

    match result {
        Ok(output) => {
            assert!(
                output.status.is_some_and(|status| status.success()),
                "denial probe failed unexpectedly: {output:?}"
            );
            assert!(output.safety_evidence_verified());
            assert!(marker.exists());
        }
        Err(error) if is_verified_backend_unavailable(&error) => {
            assert!(!marker.exists());
            report_verified_backend_unavailable_skip(&error, &unit_names);
        }
        Err(error) => panic!("unexpected denial probe failure: {error:?}"),
    }
}

#[cfg(target_os = "linux")]
#[test]
fn required_containment_kills_setsid_delayed_mutation_with_closed_stdio() {
    skip_without_containment!();
    if !strict_backend_available_for_tests() {
        return;
    }
    let temp = tempfile::tempdir().expect("tempdir");
    let marker = temp.path().join("escaped-delayed-mutation");
    let pid_file = temp.path().join("escaped-delayed.pid");
    let release = temp.path().join("release-escaped-delayed");
    let command = format!(
            "setsid sh -c 'echo $$ > \"{}\"; while [ ! -e \"{}\" ]; do sleep 0.01; done; touch \"{}\"' >/dev/null 2>&1 & i=0; while [ ! -s \"{}\" ] && [ \"$i\" -lt 100 ]; do sleep 0.01; i=$((i + 1)); done",
            pid_file.display(),
            release.display(),
            marker.display(),
            pid_file.display()
        );
    let output = run_process(
        ProcessSpec::shell(
            "setsid delayed mutation",
            Shell::UnixSh,
            command,
            temp.path(),
            128,
        )
        .with_timeout(Some(Duration::from_secs(2))),
    )
    .expect("run setsid delayed mutation");

    assert!(output.status.is_some_and(|status| status.success()));
    assert!(output.process_tree.is_verified_empty());
    let escaped_pid = fs::read_to_string(&pid_file)
        .expect("escaped delayed process pid")
        .trim()
        .parse::<libc::pid_t>()
        .expect("numeric escaped delayed process pid");
    // SAFETY: signal 0 probes existence without delivering a signal.
    assert_eq!(unsafe { libc::kill(escaped_pid, 0) }, -1);
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::ESRCH),
        "escaped delayed descendant survived return"
    );
    fs::write(release, b"release").expect("release any surviving delayed descendant");
    assert!(!marker.exists());
}

#[cfg(target_os = "linux")]
#[test]
fn required_containment_unavailable_refuses_before_spawn() {
    const CHILD_ENV: &str = "MACO_TEST_CONTAINMENT_UNAVAILABLE_CHILD";
    if env::var_os(CHILD_ENV).is_some() {
        let marker = PathBuf::from(env::var_os("MACO_TEST_CONTAINMENT_MARKER").expect("marker"));
        let spec = ProcessSpec::shell(
            "unavailable strict containment",
            Shell::UnixSh,
            format!("touch '{}'", marker.display()),
            marker.parent().expect("marker parent"),
            128,
        );
        let error = run_process(spec).expect_err("strict containment must be unavailable");
        assert!(matches!(
            error,
            ProcessRunError::ContainmentUnavailable { .. }
        ));
        assert!(!marker.exists());
        return;
    }

    let temp = tempfile::tempdir().expect("tempdir");
    let marker = temp.path().join("must-not-run");
    let status = Command::new(std::env::current_exe().expect("current test executable"))
        .args([
            "--exact",
            "process_runner::tests::required_containment_unavailable_refuses_before_spawn",
        ])
        .env(CHILD_ENV, "1")
        .env("MACO_TEST_DISABLE_STRICT_CONTAINMENT", "1")
        .env("MACO_TEST_CONTAINMENT_MARKER", &marker)
        .current_dir(temp.path())
        .status()
        .expect("run unavailable-containment child test");
    assert!(status.success());
    assert!(!marker.exists());
}

#[cfg(target_os = "linux")]
#[test]
fn exhausted_total_budget_returns_typed_setup_timeout_without_starting_target() {
    let temp = tempfile::tempdir().expect("tempdir");
    let marker = temp.path().join("must-not-run");
    let error = run_process(
        ProcessSpec::shell(
            "expired setup budget",
            Shell::UnixSh,
            format!("touch '{}'", marker.display()),
            temp.path(),
            128,
        )
        .with_timeout(Some(Duration::ZERO)),
    )
    .expect_err("zero total budget must expire before target release");

    assert!(matches!(error, ProcessRunError::SetupTimeout { .. }));
    assert!(!marker.exists());
}

#[cfg(target_os = "linux")]
#[test]
fn strict_runtime_files_ignore_ambient_tmpdir() {
    skip_without_containment!();
    const CHILD_ENV: &str = "MACO_TEST_AMBIENT_TMP_CHILD";
    if env::var_os(CHILD_ENV).is_some() {
        let ambient = PathBuf::from(env::var_os("MACO_TEST_AMBIENT_TMP_PATH").expect("ambient"));
        let output = run_process(ProcessSpec::shell(
            "ambient temp containment",
            Shell::UnixSh,
            ":",
            &ambient,
            128,
        ))
        .expect("run with ambient TMPDIR");
        assert!(output.process_tree.is_verified_empty());
        assert_eq!(fs::read_dir(&ambient).expect("ambient entries").count(), 0);
        return;
    }

    if !strict_backend_available_for_tests() {
        return;
    }

    let temp = tempfile::tempdir().expect("tempdir");
    let ambient = temp.path().join("redirected-temp");
    fs::create_dir(&ambient).expect("create redirected temp");
    let status = Command::new(std::env::current_exe().expect("current test executable"))
        .args([
            "--exact",
            "process_runner::tests::strict_runtime_files_ignore_ambient_tmpdir",
        ])
        .env(CHILD_ENV, "1")
        .env("MACO_TEST_AMBIENT_TMP_PATH", &ambient)
        .env("TMPDIR", &ambient)
        .current_dir(temp.path())
        .status()
        .expect("run ambient-temp child test");
    assert!(status.success());
    assert_eq!(fs::read_dir(&ambient).expect("ambient entries").count(), 0);
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires the trusted user-systemd/cgroup runtime; compile-only in claimed validation waves"]
fn parent_death_around_launcher_spawn_leaves_no_runtime_or_secret() {
    const CHILD_ENV: &str = "MACO_TEST_LAUNCHER_DEATH_CHILD";
    if env::var_os(CHILD_ENV).is_some() {
        let root = PathBuf::from(env::var_os("MACO_TEST_LAUNCHER_DEATH_ROOT").expect("root"));
        let marker = root.join("target-ran");
        let mut environment = BTreeMap::new();
        environment.insert(
            "MACO_PRIVATE_LAUNCH_SECRET".to_string(),
            "never-persist-before-service".to_string(),
        );
        let _ = run_process(
            ProcessSpec::shell(
                "launcher death child",
                Shell::UnixSh,
                format!("touch '{}'", marker.display()),
                &root,
                128,
            )
            .with_environment(EnvironmentMode::ClearAndSet(environment))
            .with_timeout(Some(Duration::from_secs(10))),
        );
        panic!("launcher death child unexpectedly returned");
    }

    if !strict_backend_available_for_tests() {
        return;
    }

    for case in ["before-spawn", "after-spawn"] {
        let temp = tempfile::tempdir().expect("tempdir");
        let spawned = temp.path().join("launcher-spawned");
        let mut command = Command::new(std::env::current_exe().expect("current test executable"));
        command
                .args([
                    "--exact",
                    "process_runner::tests::parent_death_around_launcher_spawn_leaves_no_runtime_or_secret",
                ])
                .env(CHILD_ENV, "1")
                .env("MACO_TEST_LAUNCHER_DEATH_ROOT", temp.path());
        if case == "before-spawn" {
            command.env("MACO_TEST_ABORT_BEFORE_CHILD_SPAWN", "1");
        } else {
            command
                .env("MACO_TEST_AFTER_CHILD_SPAWN_MARKER", &spawned)
                .env("MACO_TEST_HOLD_AFTER_CHILD_SPAWN", "1");
        }
        let mut child = command.spawn().expect("spawn launcher death child");
        let runner_pid = child.id();
        if case == "after-spawn" {
            let deadline = Instant::now() + Duration::from_secs(10);
            while !spawned.exists() {
                assert!(child.try_wait().unwrap().is_none());
                assert!(Instant::now() < deadline, "launcher spawn marker missing");
                thread::sleep(POLL_INTERVAL);
            }
            let pid = libc::pid_t::try_from(runner_pid).expect("runner pid_t");
            // SAFETY: pid identifies the live isolated test child.
            assert_eq!(unsafe { libc::kill(pid, libc::SIGKILL) }, 0);
        }
        let status = child.wait().expect("reap launcher death child");
        assert!(!status.success());
        assert!(!temp.path().join("target-ran").exists());
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let residue = systemd_runner_residue(runner_pid);
            if residue.is_empty() {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "{case} runner left residue: {}",
                residue.join("; ")
            );
            thread::sleep(Duration::from_millis(50));
        }
    }
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires the trusted user-systemd/cgroup runtime; compile-only in claimed validation waves"]
fn parent_sigkill_after_environment_publish_removes_secret_and_unit() {
    const CHILD_ENV: &str = "MACO_TEST_PUBLISHED_ENV_DEATH_CHILD";
    if env::var_os(CHILD_ENV).is_some() {
        let root = PathBuf::from(env::var_os("MACO_TEST_PUBLISHED_ENV_ROOT").expect("root"));
        let marker = root.join("target-ran");
        let mut environment = BTreeMap::new();
        environment.insert(
            "MACO_PUBLISHED_PRIVATE_SECRET".to_string(),
            "remove-me-with-runtime-directory".to_string(),
        );
        let _ = run_process(
            ProcessSpec::shell(
                "published environment death child",
                Shell::UnixSh,
                format!("touch '{}'", marker.display()),
                &root,
                128,
            )
            .with_environment(EnvironmentMode::ClearAndSet(environment))
            .with_timeout(Some(Duration::from_secs(10))),
        );
        panic!("published environment death child unexpectedly returned");
    }

    if !strict_backend_available_for_tests() {
        return;
    }

    let temp = tempfile::tempdir().expect("tempdir");
    let published = temp.path().join("environment-published");
    let mut child = Command::new(std::env::current_exe().expect("current test executable"))
            .args([
                "--exact",
                "process_runner::tests::parent_sigkill_after_environment_publish_removes_secret_and_unit",
            ])
            .env(CHILD_ENV, "1")
            .env("MACO_TEST_PUBLISHED_ENV_ROOT", temp.path())
            .env("MACO_TEST_ENVIRONMENT_PUBLISHED_MARKER", &published)
            .env("MACO_TEST_HOLD_AFTER_ENVIRONMENT_PUBLISH", "1")
            .spawn()
            .expect("spawn published environment death child");
    let runner_pid = child.id();
    let deadline = Instant::now() + Duration::from_secs(10);
    while !published.exists() {
        assert!(child.try_wait().unwrap().is_none());
        assert!(
            Instant::now() < deadline,
            "environment publish marker missing"
        );
        thread::sleep(POLL_INTERVAL);
    }
    let runtime_root = trusted_linux_runtime_root().expect("runtime root");
    let prefix = format!("maco-process-{runner_pid}-");
    let environment_path = fs::read_dir(&runtime_root)
        .unwrap()
        .filter_map(Result::ok)
        .find(|entry| entry.file_name().to_string_lossy().starts_with(&prefix))
        .expect("managed runtime directory")
        .path()
        .join("environment");
    assert!(fs::read_to_string(&environment_path)
        .expect("published environment")
        .contains("remove-me-with-runtime-directory"));
    {
        use std::os::unix::fs::PermissionsExt;

        assert_eq!(
            fs::metadata(&environment_path)
                .expect("published environment metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
    let pid = libc::pid_t::try_from(runner_pid).expect("runner pid_t");
    // SAFETY: pid identifies the live isolated test child.
    assert_eq!(unsafe { libc::kill(pid, libc::SIGKILL) }, 0);
    assert!(!child
        .wait()
        .expect("reap published environment child")
        .success());
    assert!(!temp.path().join("target-ran").exists());

    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let residue = systemd_runner_residue(runner_pid);
        if residue.is_empty() {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "published environment runner left residue: {}",
            residue.join("; ")
        );
        thread::sleep(Duration::from_millis(50));
    }
    assert!(!environment_path.exists());
    let next = run_process(
        ProcessSpec::shell(
            "post-publish-death slot probe",
            Shell::UnixSh,
            ":",
            temp.path(),
            128,
        )
        .with_timeout(Some(Duration::from_secs(2))),
    )
    .expect("slot reusable after published environment owner death");
    assert!(next.process_tree.is_verified_empty());
}

#[cfg(target_os = "linux")]
#[test]
fn target_environment_cannot_overwrite_guardian_gate_state() {
    skip_without_containment!();
    if !strict_backend_available_for_tests() {
        return;
    }
    let temp = tempfile::tempdir().expect("tempdir");
    let preloaded_start = temp.path().join("preloaded-start");
    let bogus_ready = temp.path().join("bogus-ready");
    let malicious_sleep = temp.path().join("malicious-sleep");
    fs::write(&preloaded_start, "start\n").expect("preload fake start gate");
    let mut environment = BTreeMap::new();
    environment.insert(
        "start_fifo".to_string(),
        preloaded_start.display().to_string(),
    );
    environment.insert("ready".to_string(), bogus_ready.display().to_string());
    environment.insert(
        "sleep_program".to_string(),
        malicious_sleep.display().to_string(),
    );
    environment.insert("owner_pid".to_string(), "1".to_string());
    let output = run_process(
        ProcessSpec::shell(
            "guardian environment collision",
            Shell::UnixSh,
            "printf '%s|%s|%s' \"$start_fifo\" \"$ready\" \"$sleep_program\"",
            temp.path(),
            1024,
        )
        .with_environment(EnvironmentMode::ClearAndSet(environment))
        .with_timeout(Some(CONTENTION_RESILIENT_PROCESS_TEST_TIMEOUT)),
    )
    .expect("run guardian collision environment");

    assert!(output.status.is_some_and(|status| status.success()));
    assert!(output.process_tree.is_verified_empty());
    assert!(output
        .stdout
        .summarize_chars(1024)
        .text
        .contains("preloaded-start"));
    assert!(!bogus_ready.exists());
    assert!(!malicious_sleep.exists());
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires the trusted user-systemd/cgroup runtime; compile-only in claimed validation waves"]
fn guardian_reaps_unit_when_runner_aborts_before_start_release() {
    const CHILD_ENV: &str = "MACO_TEST_PRE_GATE_ABORT_CHILD";
    if env::var_os(CHILD_ENV).is_some() {
        let marker =
            PathBuf::from(env::var_os("MACO_TEST_PRE_GATE_MARKER").expect("pre-gate marker path"));
        let _ = run_process(
            ProcessSpec::shell(
                "pre-gate abort guardian child",
                Shell::UnixSh,
                format!("touch '{}'", marker.display()),
                marker.parent().expect("pre-gate marker parent"),
                128,
            )
            .with_timeout(Some(Duration::from_secs(10))),
        );
        panic!("pre-gate guardian child unexpectedly returned");
    }

    if !strict_backend_available_for_tests() {
        return;
    }

    let temp = tempfile::tempdir().expect("tempdir");
    let marker = temp.path().join("must-not-run");
    let mut child = Command::new(std::env::current_exe().expect("current test executable"))
        .args([
            "--exact",
            "process_runner::tests::guardian_reaps_unit_when_runner_aborts_before_start_release",
        ])
        .env(CHILD_ENV, "1")
        .env("MACO_TEST_ABORT_BEFORE_START_RELEASE", "1")
        .env("MACO_TEST_PRE_GATE_MARKER", &marker)
        .current_dir(temp.path())
        .spawn()
        .expect("spawn isolated pre-gate guardian child test");
    let runner_pid = child.id();
    let exit_deadline = Instant::now() + Duration::from_secs(10);
    let status = loop {
        if let Some(status) = child.try_wait().expect("query pre-gate guardian child") {
            break status;
        }
        if Instant::now() >= exit_deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("pre-gate failpoint did not abort its isolated runner");
        }
        thread::sleep(POLL_INTERVAL);
    };
    assert!(!status.success());
    assert!(!marker.exists(), "target crossed the unreleased start gate");

    let residue_deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let residue = systemd_runner_residue(runner_pid);
        if residue.is_empty() {
            break;
        }
        assert!(
            Instant::now() < residue_deadline,
            "pre-gate runner abort left containment residue: {}",
            residue.join("; ")
        );
        thread::sleep(Duration::from_millis(50));
    }

    let next = run_process(
        ProcessSpec::shell(
            "post-pre-gate-abort slot probe",
            Shell::UnixSh,
            ":",
            temp.path(),
            128,
        )
        .with_timeout(Some(Duration::from_secs(2))),
    )
    .expect("kernel released the pre-gate aborted runner's slot lock");
    assert!(next.status.is_some_and(|status| status.success()));
    assert!(next.process_tree.is_verified_empty());
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires the trusted user-systemd/cgroup runtime; compile-only in claimed validation waves"]
fn guardian_reaps_unit_and_blocks_mutation_after_runner_sigabrt() {
    const CHILD_ENV: &str = "MACO_TEST_ABORTED_GUARDIAN_CHILD";
    if env::var_os(CHILD_ENV).is_some() {
        let started =
            PathBuf::from(env::var_os("MACO_TEST_GUARDIAN_STARTED").expect("started marker path"));
        let mutation = PathBuf::from(
            env::var_os("MACO_TEST_GUARDIAN_MUTATION").expect("mutation marker path"),
        );
        let trigger = PathBuf::from(
            env::var_os("MACO_TEST_GUARDIAN_TRIGGER").expect("mutation trigger path"),
        );
        let command = format!(
            "touch '{}'; while [ ! -e '{}' ]; do sleep 0.01; done; touch '{}'; sleep 30",
            started.display(),
            trigger.display(),
            mutation.display()
        );
        let _ = run_process(
            ProcessSpec::shell(
                "runner abort guardian child",
                Shell::UnixSh,
                command,
                started.parent().expect("started marker parent"),
                128,
            )
            .with_timeout(Some(Duration::from_secs(35))),
        );
        panic!("guardian child unexpectedly returned before its runner was aborted");
    }

    if !strict_backend_available_for_tests() {
        return;
    }

    let temp = tempfile::tempdir().expect("tempdir");
    let started = temp.path().join("target-started");
    let mutation = temp.path().join("delayed-mutation");
    let trigger = temp.path().join("allow-mutation");
    let mut child = Command::new(std::env::current_exe().expect("current test executable"))
        .args([
            "--exact",
            "process_runner::tests::guardian_reaps_unit_and_blocks_mutation_after_runner_sigabrt",
        ])
        .env(CHILD_ENV, "1")
        .env("MACO_TEST_GUARDIAN_STARTED", &started)
        .env("MACO_TEST_GUARDIAN_MUTATION", &mutation)
        .env("MACO_TEST_GUARDIAN_TRIGGER", &trigger)
        .current_dir(temp.path())
        .spawn()
        .expect("spawn isolated guardian child test");
    let runner_pid = child.id();
    let start_deadline = Instant::now() + Duration::from_secs(10);
    while !started.exists() {
        assert!(
            child.try_wait().expect("query guardian child").is_none(),
            "guardian child exited before launching its target"
        );
        assert!(
            Instant::now() < start_deadline,
            "guardian child did not launch its target"
        );
        thread::sleep(POLL_INTERVAL);
    }

    let runner_pid_t = libc::pid_t::try_from(runner_pid).expect("runner pid_t");
    // SAFETY: runner_pid identifies the live isolated child owned by this test.
    assert_eq!(unsafe { libc::kill(runner_pid_t, libc::SIGABRT) }, 0);
    let status = child.wait().expect("reap aborted guardian child");
    assert!(!status.success());

    thread::sleep(Duration::from_millis(100));
    fs::write(&trigger, "go").expect("release any surviving target mutation");
    thread::sleep(Duration::from_millis(300));
    assert!(
        !mutation.exists(),
        "contained target mutated state after its runner was aborted"
    );

    let residue_deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let residue = systemd_runner_residue(runner_pid);
        if residue.is_empty() {
            break;
        }
        assert!(
            Instant::now() < residue_deadline,
            "aborted runner left containment residue: {}",
            residue.join("; ")
        );
        thread::sleep(Duration::from_millis(50));
    }

    let next = run_process(
        ProcessSpec::shell(
            "post-abort slot probe",
            Shell::UnixSh,
            ":",
            temp.path(),
            128,
        )
        .with_timeout(Some(Duration::from_secs(2))),
    )
    .expect("kernel released the aborted runner's slot lock");
    assert!(next.status.is_some_and(|status| status.success()));
    assert!(next.process_tree.is_verified_empty());
}

#[cfg(target_os = "linux")]
fn strict_backend_available_for_tests() -> bool {
    static AVAILABILITY: std::sync::OnceLock<Result<(), String>> = std::sync::OnceLock::new();
    match AVAILABILITY.get_or_init(|| {
        let temp = tempfile::tempdir().expect("strict backend probe tempdir");
        let marker = temp.path().join("target-ran");
        let unit_capture = TestSystemdUnitNameCapture::start();
        let result = run_process(
            ProcessSpec::shell(
                "cached strict backend capability probe",
                Shell::UnixSh,
                format!("touch '{}'", marker.display()),
                temp.path(),
                128,
            )
            .with_timeout(Some(CONTENTION_RESILIENT_PROCESS_TEST_TIMEOUT)),
        );
        let unit_names = unit_capture.finish();
        match result {
            Ok(output) => {
                assert!(output.safety_evidence_verified());
                assert!(marker.exists());
                Ok(())
            }
            Err(error) if missing_delegated_user_manager_failure(&error).is_some() => {
                assert!(!marker.exists());
                Err(missing_delegated_user_manager_failure(&error)
                    .expect("matched delegated-manager failure")
                    .summary
                    .clone())
            }
            Err(error) if is_verified_backend_unavailable(&error) => {
                assert!(!marker.exists());
                assert_systemd_units_have_no_residue(&unit_names);
                Err(error.to_string())
            }
            Err(error) => panic!("unexpected strict backend capability failure: {error:?}"),
        }
    }) {
        Ok(()) => true,
        Err(reason) => {
            eprintln!(
                    "skipping containment-dependent test: delegated systemd user manager unavailable: {reason}"
                );
            false
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn strict_backend_available_for_tests() -> bool {
    false
}

#[cfg(target_os = "linux")]
fn report_verified_backend_unavailable_skip(error: &ProcessRunError, unit_names: &[String]) {
    if let Some(failure) = missing_delegated_user_manager_failure(error) {
        eprintln!(
            "skipping containment-dependent test: delegated systemd user manager unavailable: {}",
            failure.summary
        );
        return;
    }
    assert_systemd_units_have_no_residue(unit_names);
    eprintln!(
        "skipping containment-dependent test: verified containment backend unavailable: {error}"
    );
}

#[cfg(target_os = "linux")]
fn assert_systemd_units_have_no_residue(unit_names: &[String]) {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let residue = captured_systemd_unit_residue(unit_names);
        if residue.is_empty() {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "strict backend left captured containment residue: {}",
            residue.join("; ")
        );
        thread::sleep(Duration::from_millis(25));
    }
}

#[cfg(target_os = "linux")]
fn captured_systemd_unit_residue(unit_names: &[String]) -> Vec<String> {
    let mut residue = Vec::new();
    let systemctl = find_trusted_unix_executable(
        "systemctl",
        &[
            "/usr/bin/systemctl",
            "/bin/systemctl",
            "/run/current-system/sw/bin/systemctl",
        ],
    )
    .expect("trusted systemctl");
    let runtime_root = trusted_linux_runtime_root().expect("trusted runtime root");
    for unit_name in unit_names {
        let units = Command::new(&systemctl)
            .env_clear()
            .env("XDG_RUNTIME_DIR", &runtime_root)
            .stdin(Stdio::null())
            .args([
                "--user",
                "list-units",
                unit_name,
                "--all",
                "--no-legend",
                "--no-pager",
                "--plain",
            ])
            .output()
            .expect("list captured runner unit");
        if !units.status.success() {
            let stderr = String::from_utf8_lossy(&units.stderr);
            residue.push(format!(
                "systemctl observation error for {unit_name}: status {}; stderr={:?}",
                units.status,
                stderr.trim()
            ));
        } else {
            residue.extend(
                String::from_utf8_lossy(&units.stdout)
                    .lines()
                    .map(|line| format!("unit {line}")),
            );
        }
    }

    let runtime_names = unit_names
        .iter()
        .map(|unit_name| {
            unit_name
                .strip_suffix(".service")
                .unwrap_or(unit_name)
                .to_owned()
        })
        .collect::<BTreeSet<_>>();
    residue.extend(
        fs::read_dir(runtime_root)
            .expect("read runtime root")
            .filter_map(Result::ok)
            .filter_map(|entry| entry.file_name().into_string().ok())
            .filter(|name| runtime_names.contains(name))
            .map(|name| format!("runtime {name}")),
    );

    let captured_names = unit_names
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let manager = systemd_user_manager_cgroup().expect("systemd user manager cgroup");
    let app_slice = Path::new("/sys/fs/cgroup")
        .join(manager.strip_prefix("/").unwrap_or(&manager))
        .join("app.slice");
    residue.extend(
        fs::read_dir(app_slice)
            .expect("read user app.slice")
            .filter_map(Result::ok)
            .filter_map(|entry| entry.file_name().into_string().ok())
            .filter(|name| captured_names.contains(name.as_str()))
            .map(|name| format!("cgroup {name}")),
    );

    for entry in fs::read_dir("/proc").expect("read proc") {
        let Ok(entry) = entry else {
            continue;
        };
        if entry.file_name().to_string_lossy().parse::<u32>().is_err() {
            continue;
        }
        let Ok(command_line) = fs::read(entry.path().join("cmdline")) else {
            continue;
        };
        for unit_name in unit_names {
            if command_line_references_systemd_unit(&command_line, unit_name) {
                residue.push(format!(
                    "process {} for {unit_name}",
                    entry.file_name().to_string_lossy()
                ));
            }
        }
    }
    residue
}

#[cfg(target_os = "linux")]
fn command_line_references_systemd_unit(command_line: &[u8], unit_name: &str) -> bool {
    if command_line
        .split(|byte| *byte == 0)
        .any(|argument| argument == unit_name.as_bytes())
    {
        return true;
    }
    let runtime_name = unit_name.strip_suffix(".service").unwrap_or(unit_name);
    let runtime_name = runtime_name.as_bytes();
    command_line
        .windows(runtime_name.len())
        .enumerate()
        .any(|(index, candidate)| {
            if candidate != runtime_name {
                return false;
            }
            let before_is_boundary = index == 0 || matches!(command_line[index - 1], b'/' | b'\0');
            let after = index + runtime_name.len();
            let after_is_boundary =
                after == command_line.len() || matches!(command_line[after], b'/' | b'\0');
            before_is_boundary && after_is_boundary
        })
}

#[cfg(target_os = "linux")]
#[test]
fn systemd_unit_name_capture_is_thread_local_and_raii_scoped() {
    let main_capture = TestSystemdUnitNameCapture::start();
    record_systemd_unit_name_for_test("maco-process-1-26.service");
    let child_names = thread::spawn(|| {
        record_systemd_unit_name_for_test("maco-process-1-ignored.service");
        let child_capture = TestSystemdUnitNameCapture::start();
        record_systemd_unit_name_for_test("maco-process-1-260.service");
        child_capture.finish()
    })
    .join()
    .expect("join isolated unit-name capture");
    record_systemd_unit_name_for_test("maco-process-1-27.service");

    assert_eq!(child_names, vec!["maco-process-1-260.service".to_string()]);
    assert_eq!(
        main_capture.finish(),
        vec![
            "maco-process-1-26.service".to_string(),
            "maco-process-1-27.service".to_string()
        ]
    );
    let runtime_260 = b"/run/user/1000/maco-process-1-260/environment\0target\0";
    assert!(!command_line_references_systemd_unit(
        runtime_260,
        "maco-process-1-26.service"
    ));
    assert!(command_line_references_systemd_unit(
        runtime_260,
        "maco-process-1-260.service"
    ));
    assert!(command_line_references_systemd_unit(
        b"systemd-run\0--unit\0maco-process-1-26.service\0",
        "maco-process-1-26.service"
    ));

    let abandoned_capture = TestSystemdUnitNameCapture::start();
    record_systemd_unit_name_for_test("maco-process-1-abandoned.service");
    drop(abandoned_capture);
    let fresh_capture = TestSystemdUnitNameCapture::start();
    record_systemd_unit_name_for_test("maco-process-1-fresh.service");
    assert_eq!(
        fresh_capture.finish(),
        vec!["maco-process-1-fresh.service".to_string()]
    );
}

#[cfg(target_os = "linux")]
fn systemd_runner_residue(runner_pid: u32) -> Vec<String> {
    let prefix = format!("maco-process-{runner_pid}-");
    let pattern = format!("{prefix}*");
    let mut residue = Vec::new();
    let systemctl = find_trusted_unix_executable(
        "systemctl",
        &[
            "/usr/bin/systemctl",
            "/bin/systemctl",
            "/run/current-system/sw/bin/systemctl",
        ],
    )
    .expect("trusted systemctl");
    let units = Command::new(systemctl)
        .args([
            "--user",
            "list-units",
            &pattern,
            "--all",
            "--no-legend",
            "--no-pager",
            "--plain",
        ])
        .output()
        .expect("list runner units");
    if !units.status.success() {
        residue.push(format!("systemctl exited with {}", units.status));
    } else {
        residue.extend(
            String::from_utf8_lossy(&units.stdout)
                .lines()
                .map(|line| format!("unit {line}")),
        );
    }

    let runtime_root = trusted_linux_runtime_root().expect("trusted runtime root");
    residue.extend(
        fs::read_dir(runtime_root)
            .expect("read runtime root")
            .filter_map(Result::ok)
            .filter_map(|entry| entry.file_name().into_string().ok())
            .filter(|name| name.starts_with(&prefix))
            .map(|name| format!("runtime {name}")),
    );

    let manager = systemd_user_manager_cgroup().expect("systemd user manager cgroup");
    let app_slice = Path::new("/sys/fs/cgroup")
        .join(manager.strip_prefix("/").unwrap_or(&manager))
        .join("app.slice");
    residue.extend(
        fs::read_dir(app_slice)
            .expect("read user app.slice")
            .filter_map(Result::ok)
            .filter_map(|entry| entry.file_name().into_string().ok())
            .filter(|name| name.starts_with(&prefix))
            .map(|name| format!("cgroup {name}")),
    );

    for entry in fs::read_dir("/proc").expect("read proc") {
        let Ok(entry) = entry else {
            continue;
        };
        if entry.file_name().to_string_lossy().parse::<u32>().is_err() {
            continue;
        }
        let Ok(command_line) = fs::read(entry.path().join("cmdline")) else {
            continue;
        };
        if String::from_utf8_lossy(&command_line).contains(&prefix) {
            residue.push(format!("process {}", entry.file_name().to_string_lossy()));
        }
    }
    residue
}

#[test]
fn stuck_owned_io_thread_aborts_instead_of_detaching() {
    const CHILD_ENV: &str = "MACO_TEST_STUCK_IO_CHILD";
    if env::var_os(CHILD_ENV).is_some() {
        let deadline_observed = PathBuf::from(
            env::var_os("MACO_TEST_STUCK_IO_DEADLINE_OBSERVED").expect("logical deadline marker"),
        );
        let unexpected_return = PathBuf::from(
            env::var_os("MACO_TEST_STUCK_IO_UNEXPECTED_RETURN").expect("unexpected-return marker"),
        );

        struct StepClock {
            elapsed: std::cell::Cell<Duration>,
            deadline_observed: PathBuf,
            deadline_published: std::cell::Cell<bool>,
        }

        impl IoThreadClock for StepClock {
            type Deadline = Duration;

            fn deadline_after(&self, duration: Duration) -> Self::Deadline {
                self.elapsed.get().saturating_add(duration)
            }

            fn before(&self, deadline: &Self::Deadline) -> bool {
                self.elapsed.get() < *deadline
            }

            fn wait(&self, duration: Duration) {
                let elapsed = self.elapsed.get().saturating_add(duration);
                self.elapsed.set(elapsed);
                if elapsed >= THREAD_JOIN_GRACE && !self.deadline_published.replace(true) {
                    fs::write(&self.deadline_observed, b"deadline-elapsed")
                        .expect("publish logical deadline observation");
                }
            }
        }

        let cancel = Arc::new(AtomicBool::new(false));
        let handle = thread::spawn(|| loop {
            thread::sleep(Duration::from_secs(60));
        });
        let thread = OwnedIoThread { handle, cancel };
        let clock = StepClock {
            elapsed: std::cell::Cell::new(Duration::ZERO),
            deadline_observed,
            deadline_published: std::cell::Cell::new(false),
        };
        let _ = thread.finish_with_clock(false, "synthetic stuck I/O owner", &clock);
        fs::write(unexpected_return, b"returned").expect("publish unexpected stuck-owner return");
        panic!("stuck owner unexpectedly returned");
    }

    let temp = tempfile::tempdir().expect("tempdir");
    let deadline_observed = temp.path().join("deadline-observed");
    let unexpected_return = temp.path().join("unexpected-return");
    let mut child = Command::new(std::env::current_exe().expect("current test executable"))
        .args([
            "--exact",
            "process_runner::tests::stuck_owned_io_thread_aborts_instead_of_detaching",
        ])
        .env(CHILD_ENV, "1")
        .env("MACO_TEST_STUCK_IO_DEADLINE_OBSERVED", &deadline_observed)
        .env("MACO_TEST_STUCK_IO_UNEXPECTED_RETURN", &unexpected_return)
        .current_dir(temp.path())
        .spawn()
        .expect("spawn stuck-owner child test");
    // This is only a harness liveness fuse, not the cleanup-deadline assertion. Its 60-second
    // margin is 120 times the production join grace; expiry means the injected clock no longer
    // drives the owner to its fail-closed state, rather than that cleanup was slightly slow.
    let harness_deadline = Instant::now() + Duration::from_secs(60);
    let status = loop {
        if let Some(status) = child.try_wait().expect("poll logical-deadline child") {
            break status;
        }
        if Instant::now() >= harness_deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("stuck-owner child did not react to the injected cleanup deadline");
        }
        thread::sleep(POLL_INTERVAL);
    };
    assert!(!status.success());
    assert!(
        deadline_observed.exists(),
        "owner failed closed before the injected join deadline elapsed"
    );
    assert!(
        !unexpected_return.exists(),
        "stuck I/O owner was detached instead of failing closed"
    );
}

include!("tests_part2.rs");
