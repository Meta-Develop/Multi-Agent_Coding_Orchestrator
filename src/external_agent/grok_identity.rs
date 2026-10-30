//! Writable identity acceptance consumes only the original parent-held native
//! capture. Public usage evidence and deserialized reports cannot supply it.
use super::*;

pub(super) fn publication_refusal(
    command: &ExternalAgentCommand,
    report: &ExternalAgentRun,
) -> Option<&'static str> {
    if command.invocation != ExternalAgentInvocation::Grok
        || grok_acp_stdio_protocol_selected(command)
        || command.workspace_access != WorkspaceAccess::ReadWrite
    {
        return None;
    }
    let Some(capture) = report.stdout.run_metadata.grok_native_usage.as_ref() else {
        return Some("Grok writable publication lacks parent-held native usage and identity");
    };
    if capture.command != *command || !capture.process_completed {
        return Some("Grok writable identity does not bind the completed admitted invocation");
    }
    if !report
        .authenticated_grok_usage(command)
        .is_some_and(|(_, complete)| complete)
    {
        return Some("Grok writable publication requires complete parent-held native usage");
    }
    for observation in std::iter::once(&capture.observation).chain(&capture.prior_observations) {
        if let Some(refusal) = observation.served_identity().publication_refusal(
            command.model.as_deref(),
            command.reasoning_effort.as_deref(),
        ) {
            return Some(refusal);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process_runner::CapturedBytes;
    use serde_json::json;

    fn command() -> ExternalAgentCommand {
        ExternalAgentCommand::codex(
            "grok",
            ".",
            "prompt",
            "log",
            "report",
            Duration::from_secs(1),
        )
        .with_runtime_adapter(
            RuntimeId::Grok,
            RuntimeAdapterConfig::defaults(RuntimeId::Grok),
        )
        .with_workspace_access(WorkspaceAccess::ReadWrite)
        .with_model_selection(Some("grok-4.6".into()), Some("low".into()))
    }

    fn capture(terminal: serde_json::Value) -> CapturedBytes {
        let mut event = json!({"type":"end", "stopReason":"end_turn", "sessionId":"s", "requestId":"r",
            "usage":{"input_tokens":9,"output_tokens":3,"total_tokens":12}});
        event
            .as_object_mut()
            .unwrap()
            .extend(terminal.as_object().unwrap().clone());
        CapturedBytes::from_bytes_for_test((event.to_string() + "\n").into_bytes())
    }

    #[test]
    fn writable_identity_refusals_preserve_native_token_settlement() {
        let command = command();
        for terminal in [
            json!({}),
            json!({"modelUsage": []}),
            json!({"modelUsage":{"grok-4.7":{}}}),
            json!({"modelUsage":{"grok-4.6-build":{}}}),
            json!({"modelUsage":{"grok-4.6":{},"grok-4.7":{}}}),
            json!({"modelUsage":{"grok-4.6":{}},"effort":"xhigh"}),
            json!({"modelUsage":{"grok-4.6":{}},"reasoning_effort":"unknown"}),
        ] {
            let mut run =
                failed_external_run(&command, Instant::now(), vec![], false, String::new());
            run.retain_grok_native_usage_for_test(&command, &capture(terminal), true);
            assert!(publication_refusal(&command, &run).is_some());
            let (usage, complete) = run.authenticated_grok_usage(&command).unwrap();
            assert_eq!(usage.total_tokens, 12);
            assert!(
                complete,
                "identity refusal must not erase complete native charges"
            );
        }
    }

    #[test]
    fn public_identity_wire_copies_and_rebinding_cannot_supply_custody() -> Result<()> {
        let command = command();
        let mut run = failed_external_run(&command, Instant::now(), vec![], false, String::new());
        let stdout = capture(json!({"modelUsage":{"grok-4.6":{}}}));
        run.retain_grok_native_usage_for_test(&command, &stdout, true);
        run.grok_stream_usage_evidence = Some(grok_bounded_stdout_usage_evidence(&stdout));
        let mut wire = serde_json::to_value(&run)?;
        wire["grok_stream_usage_evidence"]["served_identity"]["observed_effort"] = json!("low");
        let restored: ExternalAgentRun = serde_json::from_value(wire)?;
        assert!(publication_refusal(&command, &restored)
            .unwrap()
            .contains("parent-held"));
        assert!(restored.authenticated_grok_usage(&command).is_none());
        let mut rebound = command.clone();
        rebound.reasoning_effort = Some("xhigh".into());
        assert!(publication_refusal(&rebound, &run)
            .unwrap()
            .contains("admitted invocation"));
        assert!(run.authenticated_grok_usage(&rebound).is_none());
        assert!(publication_refusal(&command, &run)
            .unwrap()
            .contains("served effort is unknown"));
        let readonly = command.with_workspace_access(WorkspaceAccess::ReadOnly);
        assert!(publication_refusal(&readonly, &run).is_none());
        Ok(())
    }

    #[test]
    fn admitted_xhigh_requires_private_identity_custody_even_when_effort_is_unknown() -> Result<()>
    {
        let command = command().with_model_selection(Some("grok-4.6".into()), Some("xhigh".into()));
        let mut run = failed_external_run(&command, Instant::now(), vec![], false, String::new());
        let stdout = capture(json!({"modelUsage":{"grok-4.6-build":{}}}));
        run.retain_grok_native_usage_for_test(&command, &stdout, true);
        run.grok_stream_usage_evidence = Some(grok_bounded_stdout_usage_evidence(&stdout));
        assert!(publication_refusal(&command, &run).is_none());
        let restored: ExternalAgentRun = serde_json::from_slice(&serde_json::to_vec(&run)?)?;
        assert_eq!(
            restored.grok_stream_usage_evidence,
            run.grok_stream_usage_evidence
        );
        assert!(publication_refusal(&command, &restored)
            .unwrap()
            .contains("parent-held"));
        assert!(restored.authenticated_grok_usage(&command).is_none());
        Ok(())
    }

    #[test]
    fn writable_missing_usage_truncation_and_continuation_stay_closed() {
        let command = command();
        let mut run = failed_external_run(&command, Instant::now(), vec![], false, String::new());
        assert!(publication_refusal(&command, &run).is_some());
        let stdout = capture(json!({"modelUsage":{"grok-4.6":{}}}));
        run.retain_grok_native_usage_for_test(&command, &stdout, false);
        assert!(publication_refusal(&command, &run).is_some());
        run.retain_grok_native_usage_for_test(
            &command,
            &CapturedBytes::from_bytes_with_truncation_for_test(stdout.as_bytes().to_vec(), true),
            true,
        );
        assert!(publication_refusal(&command, &run).is_some());
        run.retain_grok_native_usage_for_test(&command, &stdout, true);
        let prior = capture(json!({"modelUsage":{"grok-4.7":{}}}));
        run.stdout
            .run_metadata
            .grok_native_usage
            .as_mut()
            .unwrap()
            .prior_observations
            .push(
                crate::runtime_adapter::grok::observe_grok_native_usage(prior.as_bytes(), false)
                    .unwrap(),
            );
        assert!(publication_refusal(&command, &run).is_some());
        assert_eq!(
            run.authenticated_grok_usage(&command)
                .unwrap()
                .0
                .total_tokens,
            24
        );
    }
}
