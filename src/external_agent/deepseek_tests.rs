//! Offline receipts: real capture/persistence, synthetic process and credentials.
use super::*;
use std::os::unix::{fs::PermissionsExt, process::ExitStatusExt};

pub(crate) fn fixture_events() -> Vec<serde_json::Value> {
    include_str!("../runtime_adapter/fixtures/deepseek/completed.ndjson")
        .lines()
        .filter(|line| !line.starts_with('#'))
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

pub(crate) fn stream(events: &[serde_json::Value]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for event in events {
        serde_json::to_writer(&mut bytes, event).unwrap();
        bytes.push(b'\n');
    }
    bytes
}

pub(crate) fn command(root: &Path) -> Result<ExternalAgentCommand> {
    let workspace = root.join("workspace");
    fs::create_dir_all(workspace.join(".git"))?;
    for root in PERMANENT_CONTROL_ROOTS.iter().chain(POLICY_CONTROL_ROOTS) {
        fs::create_dir_all(workspace.join(root))?;
    }
    let incoming = root.join("incoming");
    fs::create_dir_all(&incoming)?;
    fs::set_permissions(&incoming, fs::Permissions::from_mode(0o700))?;
    let program = root.join("dsh");
    let prompt = root.join("research.attempt-1.prompt.md");
    fs::write(&program, b"synthetic executable identity")?;
    fs::write(&prompt, b"inspect README.md")?;
    Ok(ExternalAgentCommand::codex(
        program,
        workspace,
        prompt,
        incoming.join("events.jsonl"),
        incoming.join("report.json"),
        Duration::from_secs(5),
    )
    .with_runtime_adapter(
        RuntimeId::DeepSeek,
        RuntimeAdapterConfig::defaults(RuntimeId::DeepSeek),
    )
    .with_model_selection(Some("deepseek-v4-pro".into()), Some("high".into()))
    .with_workspace_access(WorkspaceAccess::ReadOnly))
}

pub(crate) fn capture(
    spec: &ExternalAgentCommand,
    bytes: Vec<u8>,
    truncated: bool,
    exit: i32,
    diagnostic: Option<String>,
    environment: &BTreeMap<String, String>,
) -> Result<ExternalAgentRun> {
    let mut report = failed_external_run(
        spec,
        Instant::now(),
        vec!["dsh".into()],
        false,
        "fixture".into(),
    );
    report.error = None;
    deepseek_capture::bind_launch(spec, &mut report)?;
    let mut staged = reserve_external_output(&spec.output_last_message.with_extension("staged"))?;
    let mut output = reserve_external_output(&spec.output_last_message)?;
    let mut log = reserve_external_output(&spec.json_log)?;
    let controls = protected_worktree_controls(spec)?;
    let identity = external_program_identity(&spec.program)?;
    let redactor = CredentialRedactor::from_runtime(environment, None, None)?;
    let process = ProcessOutput {
        status: Some(std::process::ExitStatus::from_raw(exit << 8)),
        duration: Duration::from_millis(1),
        timed_out: false,
        process_tree: ProcessTreeEvidence::VerifiedEmpty(ContainmentBackend::SystemdUserService),
        side_effects: SideEffectConfinementEvidence::Verified(
            SideEffectConfinementProfileKind::ExternalCodex,
        ),
        stdout: CapturedBytes::from_bytes_with_truncation_for_test(bytes, truncated),
        stderr: CapturedBytes::from_bytes_for_test(
            diagnostic.clone().unwrap_or_default().into_bytes(),
        ),
        process_error: diagnostic,
        stdin_error: None,
    };
    record_completed_target(
        &mut report,
        process,
        CompletedTargetStaging {
            output: &mut staged,
            codex_home: None,
        },
        &mut output,
        &mut log,
        &redactor,
        CompletedTargetContext {
            runtime: ExternalExecutionRuntime::Verified,
            codex_version: None,
            spec,
            original_spec: spec,
            protected_controls: &controls,
            argv_digest: "fixture",
            program_identity: &identity,
            grok_acp_parent_evidence: None,
            grok_acp_launch_schema_identity: None,
            grok_headless_schema: None,
            claude_broker_witness: None,
        },
    );
    Ok(report)
}

#[test]
fn deepseek_capture_extracts_terminal_text_and_keeps_raw_stream() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let spec = command(temp.path())?;
    let bytes = stream(&fixture_events());
    let report = capture(&spec, bytes.clone(), false, 0, None, &BTreeMap::new())?;
    assert_eq!(
        report.output_last_message(),
        Some(b"inspection complete".as_slice())
    );
    assert_eq!(fs::read(&spec.json_log)?, bytes);
    assert_eq!(report.stdout_bytes(), bytes);
    assert!(report.publishable, "{:?}", report.error);
    Ok(())
}

#[test]
fn deepseek_capture_refuses_incomplete_or_ambiguous_terminal_evidence() -> Result<()> {
    for case in [
        "nonzero",
        "truncated",
        "duplicate-final",
        "missing-final",
        "failed-final",
        "missing-text",
        "wrong-session",
        "duplicate-session",
        "after-final",
        "error-event",
    ] {
        let temp = tempfile::tempdir()?;
        let spec = command(temp.path())?;
        let mut events = fixture_events();
        match case {
            "duplicate-final" => events.push(events.last().unwrap().clone()),
            "missing-final" => {
                events.pop();
            }
            "failed-final" => {
                events.last_mut().unwrap()["reason"]["kind"] = serde_json::json!("error")
            }
            "missing-text" => {
                events
                    .last_mut()
                    .unwrap()
                    .as_object_mut()
                    .unwrap()
                    .remove("text");
            }
            "wrong-session" => events.last_mut().unwrap()["sessionId"] = serde_json::json!("other"),
            "duplicate-session" => events.insert(1, events[0].clone()),
            "after-final" => events.push(serde_json::json!({"type":"text","text":"late"})),
            "error-event" => events.insert(
                1,
                serde_json::json!({"type":"error","message":"runner failed"}),
            ),
            _ => {}
        }
        let report = capture(
            &spec,
            stream(&events),
            case == "truncated",
            if case == "nonzero" { 1 } else { 0 },
            None,
            &BTreeMap::new(),
        )?;
        assert!(report.output_last_message().is_none(), "{case}");
        assert!(!report.publishable, "{case}");
        assert!(report.error.is_some(), "{case}");
    }
    Ok(())
}

#[test]
fn deepseek_patch_snapshot_is_bound_to_bytes_and_cannot_restore_authority() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let spec = command(temp.path())?;
    let mut events = fixture_events();
    events[0]["cwd"] = serde_json::json!(spec.cwd);
    let run = capture(&spec, stream(&events), false, 0, None, &BTreeMap::new())?;
    assert!(run.deepseek_research_paths(&spec).is_ok());
    let expected =
        crate::runtime_adapter::deepseek::privacy_patch_document("deepseek-v4-pro", "high")?;
    let wire = serde_json::to_value(&run)?;
    assert_eq!(
        wire["deepseek_launch_patch"]["sha256"],
        sha256_hex(expected.as_bytes())
    );
    assert_eq!(wire["deepseek_launch_patch"]["model"], "deepseek-v4-pro");
    assert_eq!(wire["deepseek_launch_patch"]["effort"], "high");
    let mut changed = spec.clone();
    changed.reasoning_effort = Some("low".into());
    assert!(run.deepseek_research_paths(&changed).is_err());
    changed = spec.clone();
    changed.prompt = temp.path().join("research.attempt-2.prompt.md");
    assert!(run.deepseek_research_paths(&changed).is_err());
    let restored: ExternalAgentRun = serde_json::from_value(wire)?;
    assert!(restored.stdout.run_metadata.deepseek_launch_patch.is_none());
    assert!(restored.deepseek_research_paths(&spec).is_err());
    Ok(())
}

#[test]
fn deepseek_key_echo_is_redacted_through_persistence() -> Result<()> {
    let secret = r#"synthetic-deepseek-"quoted"-\-0123456789"#;
    let quoted = serde_json::to_string(secret)?;
    let escaped = &quoted[1..quoted.len() - 1];
    for diagnostic in [false, true] {
        let temp = tempfile::tempdir()?;
        let spec = command(temp.path())?;
        let mut events = fixture_events();
        let echo = format!("raw={secret} escaped={escaped}");
        events.last_mut().unwrap()["text"] = serde_json::json!(echo);
        let report = capture(
            &spec,
            stream(&events),
            false,
            0,
            diagnostic.then_some(echo),
            &BTreeMap::from([("DEEPSEEK_API_KEY".into(), secret.into())]),
        )?;
        let serialized = serde_json::to_vec(&report)?;
        let report_path = temp.path().join("persisted-run.json");
        fs::write(&report_path, serialized)?;
        for bytes in [
            fs::read(report_path)?,
            fs::read(&spec.json_log)?,
            fs::read(spec.output_last_message.with_extension("staged"))?,
            report.stdout_bytes().to_vec(),
            report.stderr.bytes.clone(),
            report.output_last_message().unwrap_or_default().to_vec(),
        ] {
            let text = String::from_utf8(bytes)?;
            assert!(
                !text.contains(secret) && !text.contains(escaped),
                "credential persisted"
            );
        }
        if !diagnostic {
            assert!(fs::read_to_string(&spec.output_last_message)?.contains("[REDACTED]"));
        }
        for line in fs::read_to_string(&spec.json_log)?.lines() {
            let event: serde_json::Value = serde_json::from_str(line)?;
            if let Some(text) = event.get("text").and_then(serde_json::Value::as_str) {
                assert!(
                    !text.contains(secret) && !text.contains(escaped),
                    "encoded credential persisted"
                );
            }
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn deepseek_profile_hides_executable_sibling_canary() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let spec = command(temp.path())?;
    let canary = temp.path().join("sibling-canary");
    fs::write(&canary, b"unrelated private file")?;
    fs::write(&spec.program, b"#!/bin/sh\n[ -x \"$0\" ] || exit 8\n[ ! -r \"$1\" ] || exit 9\nIFS= read -r header < \"$2\" || exit 10\n[ \"$header\" = '# MACO DeepSeek headless launch overlay.' ] || exit 11\nprintf confined\n")?;
    fs::set_permissions(&spec.program, fs::Permissions::from_mode(0o700))?;
    let mut run = failed_external_run(&spec, Instant::now(), vec![], false, "fixture".into());
    deepseek_capture::bind_launch(&spec, &mut run)?;
    let patch = run
        .stdout
        .run_metadata
        .deepseek_launch_patch
        .as_ref()
        .unwrap();
    let snapshot = patch.snapshot();
    let patch_path = crate::runtime_adapter::deepseek::launch_patch_path(&spec.prompt);
    fs::set_permissions(&patch_path, fs::Permissions::from_mode(0o600))?;
    fs::write(
        &patch_path,
        b"mutated after the parent bound the exact launch bytes",
    )?;
    let controls = protected_worktree_controls(&spec)?;
    let SideEffectConfinementProfile::ExternalCodex(profile) = external_side_effect_profile(
        &spec,
        &spec.program,
        ExternalProgramTrust::ExplicitCustom,
        &controls,
    )?
    else {
        bail!("expected read-only profile")
    };
    assert!(profile.visible_read_only_files().contains(&spec.program));
    assert!(!profile.visible_read_only_files().contains(&canary));
    assert!(!profile
        .visible_read_only_roots()
        .iter()
        .any(|root| canary.starts_with(root)));
    let properties = crate::process_runner::external_codex_systemd_properties_for_test(
        profile.clone(),
        &spec.program,
        &spec.cwd,
    )?;
    assert!(properties.contains(&"--property=ProtectHome=tmpfs".to_string()));
    assert!(properties.contains(&format!(
        "--property=BindReadOnlyPaths={}",
        spec.program.display()
    )));
    assert!(!properties.contains(&format!(
        "--property=BindReadOnlyPaths={}",
        temp.path().display()
    )));
    // Exercise the real confinement backend with an offline shell probe.
    let mut process_spec = ProcessSpec::direct(
        "DeepSeek executable sibling confinement",
        &spec.program,
        [&canary, &patch_path],
        &spec.cwd,
        4096,
    )
    .with_stdin(StdinMode::Null)
    .with_environment(EnvironmentMode::ClearAndSet(BTreeMap::new()))
    .with_timeout(Some(Duration::from_secs(15)))
    .with_side_effect_confinement(SideEffectConfinementProfile::ExternalCodex(profile));
    // The existing source-only capability must still refuse an external destination.
    let mut source_only = process_spec.clone();
    source_only.read_only_input_snapshots =
        vec![crate::process_runner::ReadOnlyInputSnapshot::capture(
            &patch_path,
            &sha256_hex(&fs::read(&patch_path)?),
        )?];
    let refusal = crate::process_runner::run_process(source_only).unwrap_err();
    assert!(
        refusal
            .to_string()
            .contains("source snapshot lacks an exact read-only workspace capability"),
        "{refusal}"
    );
    process_spec.read_only_input_snapshots = vec![snapshot];
    let process = crate::process_runner::run_process(process_spec)?;
    assert!(process.safety_evidence_verified(), "{process:?}");
    assert_eq!(
        process.status.and_then(|status| status.code()),
        Some(0),
        "{process:?}"
    );
    assert_eq!(process.stdout.as_bytes(), b"confined");
    Ok(())
}
