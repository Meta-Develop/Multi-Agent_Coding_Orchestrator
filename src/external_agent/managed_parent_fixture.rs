//! Offline byte peer for the real contained app-server runner. This deliberately
//! bypasses executable/account preflight, never production admission or collection.
//! Python is not qualified as a provider runtime by this test-only entrypoint.

use super::*;

pub(crate) fn run(
    spec: &ExternalAgentCommand,
    cancellation: &ProcessCancellation,
    mut payload: serde_json::Value,
) -> Result<ExternalAgentRun> {
    let started = Instant::now();
    let python = [
        "/run/current-system/sw/bin/python3",
        "/usr/bin/python3",
        "/bin/python3",
    ]
    .into_iter()
    .map(PathBuf::from)
    .find(|path| path.is_file())
    .context("offline fixture requires python3")?;
    let python = fs::canonicalize(python)?;
    let fixture = tempfile::tempdir()?;
    let script = fixture.path().join("peer.py");
    fs::write(
        &script,
        include_str!("../../tests/fixtures/codex-managed-parent/peer.py"),
    )?;
    let mut staging = ExternalOutputStaging::create(&spec.cwd, None)?;
    staging.stage_codex_home()?;
    let mut controls = protected_worktree_controls(spec)?;
    controls.writable_artifact_root = Some(staging.root_path().to_path_buf());
    let SideEffectConfinementProfile::ExternalCodex(profile) = external_side_effect_profile(
        spec,
        &python,
        ExternalProgramTrust::TrustedSystemCodex,
        &controls,
    )?
    else {
        bail!("offline fixture requires the Codex outer profile");
    };
    let profile = profile.with_visible_read_only_root(fixture.path());
    let argv = audited_codex_app_server_argv(spec, &controls, EnvironmentVersion::new(0, 162, 0))?;
    let process = ProcessSpec::direct(
        "offline managed parent app-server peer",
        &python,
        [script.into_os_string()].into_iter().chain(argv.clone()),
        &spec.cwd,
        1024 * 1024,
    )
    .with_stdin(StdinMode::Interactive)
    .with_stdin_limit(MAX_PROMPT_BYTES)
    .with_timeout(Some(spec.timeout))
    .with_side_effect_confinement(SideEffectConfinementProfile::ExternalCodex(profile));
    let signal = staging.root_path().join("worker-started");
    let cancel_active = payload["case"] == "cancel-active-worker"
        && payload["mode"] == "worker"
        && payload["report"]["id"] == "worker";
    payload["signal"] = serde_json::json!(signal);
    let prompt = format!(
        "{}\nOFFLINE_FIXTURE={}\n",
        fs::read_to_string(&spec.prompt)?,
        payload
    );
    let finished = std::sync::atomic::AtomicBool::new(false);
    let interactive = std::thread::scope(|scope| {
        if cancel_active {
            scope.spawn(|| {
                while !finished.load(std::sync::atomic::Ordering::Acquire) {
                    if signal.is_file() {
                        cancellation.cancel();
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
            });
        }
        let result = if spec.workspace_access == WorkspaceAccess::ReadWrite {
            run_managed_worker_app_server_process(process, cancellation, spec, prompt)
        } else {
            run_read_only_terminal_app_server_process(process, cancellation, spec, prompt)
        };
        finished.store(true, std::sync::atomic::Ordering::Release);
        result
    })?;
    assert!(
        interactive.process.safety_evidence_verified(),
        "{interactive:?}"
    );
    assert!(interactive.process.process_tree.is_verified_empty());
    let mut run = failed_external_run(
        spec,
        started,
        vec!["offline-app-server-peer".into()],
        false,
        String::new(),
    );
    run.error = None;
    // The injected runner replaces only preflight/executable selection. Containment,
    // protocol captures, permissions, journals and usage below are observed normally.
    run.program_trust = ExternalProgramTrust::TrustedSystemCodex;
    let mut output = reserve_external_output(&spec.output_last_message)?;
    let mut log = reserve_external_output(&spec.json_log)?;
    record_completed_app_server_target(
        &mut run,
        interactive,
        &mut staging,
        &mut output,
        &mut log,
        &CredentialRedactor::default(),
        CompletedTargetContext {
            runtime: ExternalExecutionRuntime::Verified,
            codex_version: Some((0, 162, 0)),
            spec,
            original_spec: spec,
            protected_controls: &controls,
            argv_digest: &argv_digest(&argv)?,
            program_identity: &external_program_identity(&python)?,
            grok_acp_parent_evidence: None,
            grok_acp_launch_schema_identity: None,
            grok_headless_schema: None,
            claude_broker_witness: None,
        },
    );
    run.replace_worker_journal_artifacts(capture_worker_journal_artifacts(
        &controls,
        run.scratch_quiescence_verified(),
    ));
    // Match the production wrapper's host-held invocation receipt. The peer
    // supplies neither this identity nor a self-asserted budget settlement.
    run.retain_live_budget_invocation_for_test(spec);
    run.duration_ms = duration_millis(started.elapsed());
    Ok(run)
}
