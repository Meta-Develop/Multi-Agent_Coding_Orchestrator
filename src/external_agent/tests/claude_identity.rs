use super::*;
use crate::process_runner::{
    CapturedBytes, ContainmentBackend, ProcessTreeEvidence, SideEffectConfinementEvidence,
    SideEffectConfinementProfileKind,
};
use crate::runtime_adapter::claude::{
    ClaudeBrokerBinding, ClaudeBrokerTerminalSeal, ClaudeBrokerUpstreamResponse,
    ClaudeParentBroker, ClaudeTransportCredentialGrant, CLAUDE_MANAGED_PRIMARY_MODEL,
};
use std::os::unix::{fs::PermissionsExt, process::ExitStatusExt};
use std::process::ExitStatus;

/// Providerless complete-witness fixture through the real completion-recording boundary.
pub(crate) fn record_claude_completion_for_test(
    root: &Path,
    access: WorkspaceAccess,
) -> Result<(ExternalAgentCommand, ExternalAgentRun)> {
    create_mandatory_control_roots(root)?;
    let incoming = root.join("incoming");
    fs::create_dir(&incoming)?;
    fs::set_permissions(&incoming, fs::Permissions::from_mode(0o700))?;
    let prompt = root.join("prompt.md");
    fs::write(&prompt, "bounded fixture\n")?;
    let command = ExternalAgentCommand::codex(
        "claude",
        root,
        &prompt,
        incoming.join("events.jsonl"),
        incoming.join("report.json"),
        Duration::from_secs(5),
    )
    .with_runtime_adapter(
        RuntimeId::ClaudeCode,
        RuntimeAdapterConfig::defaults(RuntimeId::ClaudeCode),
    )
    .with_workspace_access(access)
    .with_model_selection(
        Some(CLAUDE_MANAGED_PRIMARY_MODEL.to_string()),
        Some("high".to_string()),
    )
    .with_agent_lifecycle(
        root,
        if access == WorkspaceAccess::ReadOnly {
            AgentRole::Auditor.as_str()
        } else {
            AgentRole::Worker.as_str()
        },
        "claude-identity-fixture",
        "terminal",
    );
    let binding = ClaudeBrokerBinding::new(
        "fixture-nonce".to_string(),
        "fixture-digest".to_string(),
        "fixture-account".to_string(),
        1,
        9_999_999,
        ClaudeTransportAuthMode::BareApiKey,
    )
    .map_err(anyhow::Error::msg)?;
    let grant = ClaudeTransportCredentialGrant::new(binding.clone(), b"fake-key".to_vec())
        .map_err(anyhow::Error::msg)?;
    let mut broker = ClaudeParentBroker::new(grant);
    broker
        .handle_http(b"HEAD / HTTP/1.1\r\nHost: localhost\r\n\r\n", |_| {
            unreachable!("HEAD is terminated by the broker")
        })
        .map_err(anyhow::Error::msg)?;
    let stream = exact_claude_native_stream();
    let events = std::str::from_utf8(&stream)?
        .lines()
        .map(serde_json::from_str::<serde_json::Value>)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let sse = events
        .iter()
        .filter_map(|event| event.get("event"))
        .map(|event| format!("data: {event}\n\n"))
        .collect::<String>();
    let body = serde_json::to_vec(&serde_json::json!({
        "model":CLAUDE_MANAGED_PRIMARY_MODEL,"max_tokens":256,"stream":true,
        "messages":[{"role":"user","content":"synthetic"}],"tools":[]
    }))?;
    let mut request = format!(
        "POST /v1/messages HTTP/1.1\r\nHost: localhost\r\nx-api-key: fake-key\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
        body.len()
    )
    .into_bytes();
    request.extend_from_slice(&body);
    broker
        .handle_http(&request, |_| {
            Ok(ClaudeBrokerUpstreamResponse {
                status: 200,
                content_type: "text/event-stream".to_string(),
                body: sse.into_bytes(),
                truncated: false,
            })
        })
        .map_err(anyhow::Error::msg)?;
    let witness = broker.seal(ClaudeBrokerTerminalSeal {
        child_exit_observed: true,
        listener_closed: true,
        upstream_quiescent: true,
        interrupted: false,
    });
    let mut staged = reserve_external_output(&incoming.join("staged.raw"))?;
    let mut output = reserve_external_output(&command.output_last_message)?;
    let mut log = reserve_external_output(&command.json_log)?;
    let identity_path = root.join("identity.txt");
    fs::write(&identity_path, "fixture")?;
    let identity = external_program_identity(&identity_path)?;
    let mut run = failed_external_run(
        &command,
        Instant::now(),
        vec!["claude".to_string()],
        false,
        "fixture".to_string(),
    );
    run.error = None;
    run.program_trust = ExternalProgramTrust::ExplicitCustom;
    let controls = protected_worktree_controls(&command)?;
    record_completed_target(
        &mut run,
        ProcessOutput {
            status: Some(ExitStatus::from_raw(0)),
            duration: Duration::from_millis(1),
            timed_out: false,
            process_tree: ProcessTreeEvidence::VerifiedEmpty(
                ContainmentBackend::SystemdUserService,
            ),
            side_effects: SideEffectConfinementEvidence::Verified(
                SideEffectConfinementProfileKind::ExternalClaude,
            ),
            stdout: CapturedBytes::from_bytes_for_test(stream),
            stderr: CapturedBytes::default(),
            process_error: None,
            stdin_error: None,
        },
        CompletedTargetStaging {
            output: &mut staged,
            codex_home: None,
        },
        &mut output,
        &mut log,
        &CredentialRedactor::default(),
        CompletedTargetContext {
            runtime: ExternalExecutionRuntime::Verified,
            codex_version: None,
            spec: &command,
            original_spec: &command,
            protected_controls: &controls,
            argv_digest: "fixture-digest",
            program_identity: &identity,
            grok_acp_parent_evidence: None,
            grok_acp_launch_schema_identity: None,
            grok_headless_schema: None,
            claude_broker_witness: Some((&witness, &binding)),
        },
    );
    Ok((command, run))
}
