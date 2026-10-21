//! Select the final native answer before staging it through the parent-held
//! output descriptor. Progress text is never a schema-validation authority.
use super::*;
use crate::runtime_adapter::grok::{
    canonical_grok_structured_output, parse_grok_event_stream, GrokParsedEventStream,
    GrokStreamEvent, GrokStreamOutcome,
};
use serde_json::Value;

/// Capture the exact schema already rendered into native launch argv. Never
/// reopen its pathname after execution to validate a text fallback.
pub(super) fn bind_schema(spec: &ExternalAgentCommand, argv: &[OsString]) -> Result<Option<Value>> {
    if spec.invocation != ExternalAgentInvocation::Grok
        || grok_acp_stdio_protocol_selected(spec)
        || spec.output_schema.is_none()
    {
        return Ok(None);
    }
    let mut schemas = argv.windows(2).filter(|pair| pair[0] == "--json-schema");
    let schema = schemas
        .next()
        .and_then(|pair| pair[1].to_str())
        .context("Grok launch argv is missing its bound output schema")?;
    if schemas.next().is_some() {
        bail!("Grok launch argv has multiple output schemas");
    }
    Ok(Some(serde_json::from_str(schema)?))
}

fn final_turn(spec: &ExternalAgentCommand, bytes: &[u8]) -> Result<GrokParsedEventStream> {
    if let Ok(stream) = parse_grok_event_stream(bytes) {
        return Ok(stream);
    }
    // Normally the guarded runner supplies only the final turn. Also accept its
    // bounded same-session continuation shape, validating both complete turns.
    // This does not admit arbitrary trailing data or additional continuations.
    if !grok_progress::guarded_worker(spec) || bytes.len() > OUTPUT_TEE_LIMIT_BYTES {
        bail!("Grok runtime output failed bounded streaming-json validation");
    }
    let mut offset = 0;
    for line in bytes.split_inclusive(|byte| *byte == b'\n') {
        offset += line.len();
        let event: Value = serde_json::from_slice(line)
            .context("Grok runtime output failed bounded streaming-json validation")?;
        if event.get("type").and_then(Value::as_str) != Some("end") {
            continue;
        }
        let first = parse_grok_event_stream(&bytes[..offset])?;
        if !grok_progress::worker_no_progress(&bytes[..offset]) {
            bail!("Grok continuation has no bounded idle-turn authorization");
        }
        let last = parse_grok_event_stream(&bytes[offset..])?;
        if let (GrokStreamOutcome::Completed(first), GrokStreamOutcome::Completed(last_end)) =
            (first.outcome(), last.outcome())
        {
            if first.session_id() == last_end.session_id() {
                return Ok(last);
            }
        }
        bail!("Grok continuation session changed or failed");
    }
    bail!("Grok runtime output failed bounded streaming-json validation")
}

pub(super) fn capture(
    spec: &ExternalAgentCommand,
    bytes: &[u8],
    launch_schema: Option<&Value>,
) -> Result<Vec<u8>> {
    let stream = final_turn(spec, bytes)?;
    if !stream.successful_completion() {
        if stream.completed() {
            bail!("Grok runtime returned a non-success terminal streaming-json end event");
        }
        bail!("Grok runtime returned a terminal streaming-json error event");
    }
    if spec.output_schema.is_none() {
        return Ok(stream.response_text().as_bytes().to_vec());
    }
    let GrokStreamOutcome::Completed(end) = stream.outcome() else {
        unreachable!("successful completion requires end")
    };
    if end.structured_output_error().is_some() {
        // A native validation failure is authoritative too. Do not bypass it
        // using text, or reflect its potentially sensitive report contents.
        bail!("Grok runtime returned a terminal structuredOutputError");
    }
    if let Some(structured) = end.structured_output() {
        return canonical_grok_structured_output(structured);
    }

    let schema = launch_schema
        .filter(|_| grok_progress::guarded_worker(spec))
        .context("Grok runtime terminal end event is missing structuredOutput")?;
    let mut after_tool = String::new();
    let mut saw_tool = false;
    for event in stream.events() {
        match event {
            GrokStreamEvent::Other { event_type }
                if matches!(
                    event_type.as_str(),
                    "tool_call" | "tool_call_update" | "tool_use"
                ) =>
            {
                saw_tool = true;
                after_tool.clear();
            }
            GrokStreamEvent::Text(text) => after_tool.push_str(text),
            _ => {}
        }
    }
    if !saw_tool {
        bail!("Grok text fallback has no final tool boundary");
    }
    // Only complete, unwrapped JSON objects after the LAST tool event qualify.
    // Invalid/truncated tails fail closed; earlier reports and nested fragments
    // cannot be mistaken for the final report.
    let mut last = None;
    for value in serde_json::Deserializer::from_str(&after_tool).into_iter::<Value>() {
        let value = value.context("Grok final text is not complete report JSON")?;
        if !value.is_object() {
            bail!("Grok final text report is not a JSON object");
        }
        last = Some(value);
    }
    let last = last.context("Grok text fallback omitted a report after the final tool")?;
    let mut compiler = boon::Compiler::new();
    compiler.set_default_draft(boon::Draft::V2020_12);
    let mut schemas = boon::Schemas::new();
    let id = "https://maco.invalid/held-grok-worker-schema";
    compiler
        .add_resource(id, schema.clone())
        .map_err(|_| anyhow::anyhow!("Grok held output schema could not be registered"))?;
    let index = compiler
        .compile(id, &mut schemas)
        .map_err(|_| anyhow::anyhow!("Grok held output schema could not be compiled"))?;
    schemas
        .validate(&last, index)
        .map_err(|_| anyhow::anyhow!("Grok final text report failed the held output schema"))?;
    canonical_grok_structured_output(&last)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn command() -> ExternalAgentCommand {
        let mut command = ExternalAgentCommand::codex(
            "grok",
            "/worktree",
            "/private/prompt",
            "/private/events",
            "/private/report",
            Duration::from_secs(30),
        )
        .with_runtime_adapter(
            RuntimeId::Grok,
            RuntimeAdapterConfig::defaults(RuntimeId::Grok),
        )
        .with_workspace_access(WorkspaceAccess::ReadWrite)
        .with_agent_lifecycle("/repo", "worker", "run", "readme-worker");
        command.output_schema = Some("/private/worker.schema.json".into());
        command
    }

    fn end(structured: Value) -> Value {
        json!({"type":"end", "stopReason":"end_turn",
            "sessionId":"6b3056ad-f990-4314-b7ff-f9e58c593ac5", "requestId":"request",
            "structuredOutput":structured})
    }

    fn bytes(events: &[Value]) -> Vec<u8> {
        events
            .iter()
            .map(|event| event.to_string() + "\n")
            .collect::<String>()
            .into_bytes()
    }

    fn report() -> Value {
        json!({"id":"readme-worker", "role":"worker", "status":"succeeded",
            "files_changed":["README.md"], "commands_run":[{"command":["git","diff","--check"],
                "cwd":"/worktree"}], "no_further_delegation":true})
    }

    fn schema() -> Value {
        json!({"type":"object", "required":["id","role","status","files_changed","commands_run","no_further_delegation"],
            "additionalProperties":false, "properties":{
            "id":{"const":"readme-worker"}, "role":{"const":"worker"},
            "status":{"enum":["succeeded","failed","rejected"]},
            "files_changed":{"type":"array","items":{"const":"README.md"}},
            "commands_run":{"type":"array", "items":{"type":"object"}},
            "no_further_delegation":{"const":true}}})
    }

    // Shape captured in e2e-mixed-r39u1: premature empty report text,
    // fragmented text, native tools/updates, terminal structuredOutput. Values
    // are synthetic; no provider, account, usage or containment is asserted.
    fn productive_events() -> Vec<Value> {
        vec![
            json!({"type":"text", "data":"{\"id\":\"readme-worker\",\"commands_run\":[],\"files_changed\":[]}"}),
            json!({"type":"tool_call", "toolName":"search_replace", "toolCallId":"edit"}),
            json!({"type":"text", "data":"{\"status\":\"pending\"}"}),
            json!({"type":"tool_call", "toolName":"run_terminal_command", "toolCallId":"check"}),
            json!({"type":"tool_call_update", "toolCallId":"check", "status":"completed"}),
        ]
    }

    #[test]
    fn last_structured_answer_overrides_premature_text_and_drives_adapter_capture() -> Result<()> {
        let spec = command();
        let mut events = productive_events();
        events.push(end(report()));
        let RuntimeAdapterCapturedOutput::Captured(output) =
            runtime_adapter_captured_output(&spec, &bytes(&events), b"", true)?
        else {
            panic!("expected parent staging bytes")
        };
        assert_eq!(serde_json::from_slice::<Value>(&output)?, report());
        Ok(())
    }

    #[test]
    fn text_fallback_uses_last_complete_json_after_last_tool_and_validates_held_schema(
    ) -> Result<()> {
        let mut events = productive_events();
        events.push(json!({"type":"text", "data":report().to_string()}));
        let mut last = report();
        last["status"] = json!("failed");
        let text = last.to_string();
        events.push(json!({"type":"text", "data":&text[..text.len()/2]}));
        events.push(json!({"type":"text", "data":&text[text.len()/2..]}));
        events.push(end(Value::Null));
        assert_eq!(
            serde_json::from_slice::<Value>(&capture(
                &command(),
                &bytes(&events),
                Some(&schema())
            )?)?,
            last
        );
        assert!(capture(&command(), &bytes(&events), None).is_err());
        let mut wrong_schema = schema();
        wrong_schema["properties"]["id"]["const"] = json!("different-worker");
        assert!(capture(&command(), &bytes(&events), Some(&wrong_schema)).is_err());
        // Actual native schema path constraints must also apply to fallback.
        let mut constrained = schema();
        constrained["properties"]["commands_run"]["items"]["properties"] =
            json!({"cwd":{"type":"string","pattern":"^[^/]"}});
        assert!(capture(&command(), &bytes(&events), Some(&constrained)).is_err());
        Ok(())
    }

    #[test]
    fn fallback_never_recovers_pretool_json_or_bypasses_native_errors() {
        for suffix in ["", "{\"id\":", "[]", "```json\n{}\n```", "{}"] {
            let mut events = productive_events();
            events.push(json!({"type":"text", "data":suffix}));
            events.push(end(Value::Null));
            assert!(
                capture(&command(), &bytes(&events), Some(&schema())).is_err(),
                "{suffix}"
            );
        }
        let mut events = vec![
            json!({"type":"text", "data":report().to_string()}),
            end(Value::Null),
        ];
        assert!(capture(&command(), &bytes(&events), Some(&schema())).is_err());
        events = productive_events();
        events.push(json!({"type":"text", "data":report().to_string()}));
        let mut terminal = end(Value::Null);
        terminal["structuredOutputError"] = json!("secret native validation error");
        events.push(terminal);
        let error = capture(&command(), &bytes(&events), Some(&schema()))
            .unwrap_err()
            .to_string();
        assert_eq!(
            error,
            "Grok runtime returned a terminal structuredOutputError"
        );
    }

    #[test]
    fn continuation_selects_last_end_and_refuses_changed_session_or_trailing_bytes() -> Result<()> {
        let first = end(json!({"role":"worker", "status":"pending", "commands_run":[]}));
        let mut events = vec![first.clone()];
        events.extend(productive_events());
        events.push(end(report()));
        assert_eq!(
            serde_json::from_slice::<Value>(&capture(&command(), &bytes(&events), None)?)?,
            report()
        );
        let mut tainted = bytes(&events);
        tainted.extend_from_slice(b"{\"type\":\"text\",\"data\":\"trailing\"}\n");
        assert!(capture(&command(), &tainted, None).is_err());
        let last = events.last_mut().unwrap();
        last["sessionId"] = json!("different");
        assert!(capture(&command(), &bytes(&events), None).is_err());
        events = vec![first.clone(), first, end(report())];
        assert!(capture(&command(), &bytes(&events), None).is_err());
        Ok(())
    }

    #[test]
    fn headless_schema_is_bound_to_launch_argv_without_reopening_path() -> Result<()> {
        let spec = command();
        let argv = vec![
            OsString::from("--json-schema"),
            OsString::from(schema().to_string()),
        ];
        let held = bind_schema(&spec, &argv)?.unwrap();
        assert_eq!(held, schema());
        assert!(bind_schema(&spec, &[]).is_err());
        let duplicate = [argv.clone(), argv].concat();
        assert!(bind_schema(&spec, &duplicate).is_err());
        Ok(())
    }
}
