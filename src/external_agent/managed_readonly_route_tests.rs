use std::collections::BTreeMap;
use std::fs;
use std::time::Duration;

use super::*;
use crate::messaging::transport::{
    AssignmentMessagingServer, MACO_MESSAGE_ENDPOINT_ENV, MACO_MESSAGE_TOKEN_ENV,
};

fn managed_shape(
    route: impl Fn(ExternalAgentCommand) -> ExternalAgentCommand,
) -> ExternalAgentCommand {
    route(
        ExternalAgentCommand::codex(
            "codex",
            "/workspace",
            "/run/prompt.md",
            "/run/events.jsonl",
            "/run/report.json",
            Duration::from_secs(5),
        )
        .with_workspace_access(WorkspaceAccess::ReadOnly)
        .with_writable_launch_target(WritableLaunchTarget::ManagedChildWorktree)
        .with_codex_native_delegation_disabled()
        .with_agent_lifecycle("/registry", "child_orchestrator", "run-1", "parent-1"),
    )
}

#[test]
fn managed_readonly_routes_are_exact_and_malformed_opt_in_is_refused() {
    let initial = managed_shape(ExternalAgentCommand::with_codex_managed_worker_requests);
    let continuation =
        managed_shape(ExternalAgentCommand::with_codex_managed_readonly_continuation);
    let initial_route =
        classify_managed_readonly_app_server(&initial, ExternalExecutionRuntime::Verified);
    let continuation_route =
        classify_managed_readonly_app_server(&continuation, ExternalExecutionRuntime::Verified);
    if cfg!(target_os = "linux") {
        assert_eq!(
            initial_route.unwrap(),
            Some(CodexManagedReadonlyRoute::InitialWorkerRequests)
        );
        assert_eq!(
            continuation_route.unwrap(),
            Some(CodexManagedReadonlyRoute::Continuation)
        );
    } else {
        assert!(initial_route.unwrap_err().contains("verified Linux"));
        assert!(continuation_route.unwrap_err().contains("verified Linux"));
    }
    assert!(classify_managed_readonly_app_server(
        &initial,
        ExternalExecutionRuntime::NonpublishableSimulation
    )
    .unwrap_err()
    .contains("verified Linux"));

    let ordinary = ExternalAgentCommand::codex(
        "codex",
        "/workspace",
        "/run/prompt.md",
        "/run/events.jsonl",
        "/run/report.json",
        Duration::from_secs(5),
    )
    .with_workspace_access(WorkspaceAccess::ReadOnly)
    .with_agent_lifecycle("/registry", "worker", "run-1", "worker-1");
    assert_eq!(
        classify_managed_readonly_app_server(&ordinary, ExternalExecutionRuntime::Verified)
            .unwrap(),
        None
    );
    assert!(!ordinary.codex_managed_worker_requests_enabled());
    assert!(!should_use_read_only_researcher_app_server(
        &ordinary,
        ExternalExecutionRuntime::Verified
    ));

    let researcher = ExternalAgentCommand::codex(
        "codex",
        "/workspace",
        "/run/prompt.md",
        "/run/events.jsonl",
        "/run/report.json",
        Duration::from_secs(5),
    )
    .with_workspace_access(WorkspaceAccess::ReadOnly)
    .with_agent_lifecycle("/registry", "researcher", "run-1", "research-1");
    assert_eq!(
        classify_managed_readonly_app_server(&researcher, ExternalExecutionRuntime::Verified)
            .unwrap(),
        None
    );
    assert_eq!(
        should_use_read_only_researcher_app_server(&researcher, ExternalExecutionRuntime::Verified),
        cfg!(target_os = "linux")
    );
    assert!(!researcher.codex_managed_worker_requests_enabled());

    let wrong_role = ExternalAgentCommand::codex(
        "codex",
        "/workspace",
        "/run/prompt.md",
        "/run/events.jsonl",
        "/run/report.json",
        Duration::from_secs(5),
    )
    .with_workspace_access(WorkspaceAccess::ReadOnly)
    .with_codex_native_delegation_disabled()
    .with_agent_lifecycle("/registry", "worker", "run-1", "worker-1")
    .with_codex_managed_worker_requests();
    let report = run_external_agent(&wrong_role);
    assert!(
        report
            .error
            .as_deref()
            .is_some_and(|error| error.contains("opt-in refused")),
        "{report:?}"
    );
    assert!(!report.stdout.target_launch_attempted);

    let missing_endpoint = validate_managed_readonly_execute_binding(
        &initial,
        Some(CodexManagedReadonlyRoute::InitialWorkerRequests),
    );
    assert!(missing_endpoint
        .unwrap_err()
        .contains("sealed inbox endpoint"));
    assert!(validate_managed_readonly_execute_binding(
        &continuation,
        Some(CodexManagedReadonlyRoute::Continuation),
    )
    .is_ok());
}

#[test]
fn managed_routes_do_not_export_message_credentials() -> Result<()> {
    let server =
        AssignmentMessagingServer::start("run-1", "parent-1", |_| Ok(serde_json::json!({})))?;
    let launch = server.launch();
    let initial = managed_shape(ExternalAgentCommand::with_codex_managed_worker_requests)
        .with_assignment_messaging(launch.clone());
    let continuation =
        managed_shape(ExternalAgentCommand::with_codex_managed_readonly_continuation)
            .with_assignment_messaging(launch.clone());
    for command in [&initial, &continuation] {
        let mut environment = BTreeMap::new();
        extend_common_runtime_environment_with_assignment_messaging(command, &mut environment)?;
        assert!(!environment.contains_key(MACO_MESSAGE_ENDPOINT_ENV));
        assert!(!environment.contains_key(MACO_MESSAGE_TOKEN_ENV));
        let overlay = assignment_messaging_launch_environment_overlay(command)?;
        assert!(overlay.is_empty());
    }
    let worker = ExternalAgentCommand::codex(
        "codex",
        "/workspace",
        "/run/prompt.md",
        "/run/events.jsonl",
        "/run/report.json",
        Duration::from_secs(5),
    )
    .with_agent_lifecycle("/registry", "worker", "run-1", "parent-1")
    .with_assignment_messaging(launch);
    let mut environment = BTreeMap::new();
    extend_common_runtime_environment_with_assignment_messaging(&worker, &mut environment)?;
    assert!(environment.contains_key(MACO_MESSAGE_ENDPOINT_ENV));
    assert!(environment.contains_key(MACO_MESSAGE_TOKEN_ENV));
    Ok(())
}

#[test]
fn managed_initial_prompt_selects_dynamic_tool_and_continuation_rejects_it() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let initial_prompt = temp.path().join("initial.md");
    let continuation_prompt = temp.path().join("continuation.md");
    let ordinary_prompt = temp.path().join("ordinary.md");
    fs::write(
        &initial_prompt,
        render_prompt_with_managed_worker_request_tool_appendix(
            "yield acknowledged workers".to_string(),
        )?,
    )?;
    fs::write(&continuation_prompt, "continuation has no worker tool\n")?;
    fs::write(
        &ordinary_prompt,
        render_prompt_with_assignment_messaging_protocol_appendix("ordinary child".to_string())?,
    )?;
    let server =
        AssignmentMessagingServer::start("run-1", "parent-1", |_| Ok(serde_json::json!({})))?;
    let initial = managed_shape(ExternalAgentCommand::with_codex_managed_worker_requests)
        .with_assignment_messaging(server.launch());
    let mut initial = initial;
    initial.prompt = initial_prompt;
    initial.verify_assignment_messaging_protocol_instructions()?;
    assert!(initial.codex_managed_worker_requests_enabled());
    assert!(validate_managed_readonly_execute_binding(
        &initial,
        Some(CodexManagedReadonlyRoute::InitialWorkerRequests),
    )
    .is_ok());

    let mut continuation =
        managed_shape(ExternalAgentCommand::with_codex_managed_readonly_continuation);
    continuation.prompt = continuation_prompt;
    continuation.verify_assignment_messaging_protocol_instructions()?;
    assert!(!continuation.codex_managed_worker_requests_enabled());

    let mut stolen = continuation.clone();
    stolen.prompt = initial.prompt.clone();
    assert!(stolen
        .verify_assignment_messaging_protocol_instructions()
        .is_err());

    let mut ordinary = ExternalAgentCommand::codex(
        "codex",
        "/workspace",
        &ordinary_prompt,
        "/run/events.jsonl",
        "/run/report.json",
        Duration::from_secs(5),
    )
    .with_agent_lifecycle("/registry", "worker", "run-1", "parent-1")
    .with_assignment_messaging(server.launch());
    ordinary.prompt = ordinary_prompt;
    ordinary.verify_assignment_messaging_protocol_instructions()?;
    assert!(!ordinary.codex_managed_worker_requests_enabled());
    Ok(())
}
