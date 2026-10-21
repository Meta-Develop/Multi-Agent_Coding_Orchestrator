//! Fail closed on an idle headless WorkerReport; one continuation in the same
//! unit preserves the native session, credentials, deadline and MACO authority.
use super::*;
use crate::process_runner::{ContainedProcessSession, InteractiveProcessRead};
use crate::runtime_adapter::grok::{parse_grok_event_stream, GrokStreamOutcome};

/// Persist a fixed host policy marker in the existing command-report diagnostic
/// surface. Raw provider bytes stay intact; failed/unverified probes cannot mint it.
pub(super) fn record_launch_policy(
    report: &mut ExternalAgentRun,
    spec: &ExternalAgentCommand,
    runtime: ExternalExecutionRuntime,
) {
    if runtime == ExternalExecutionRuntime::Verified
        && spec.invocation == ExternalAgentInvocation::Grok
        && report.stdout.target_launch_attempted
        && report.side_effects
            == Some(
                crate::process_runner::SideEffectConfinementEvidence::Verified(
                    SideEffectConfinementProfileKind::ExternalGrok,
                ),
            )
    {
        report.stderr.text.push_str("\nMACO launch policy: ");
        report
            .stderr
            .text
            .push_str(crate::runtime_adapter::grok::GROK_INNER_SANDBOX_EVIDENCE);
    }
}

const LIMIT: usize = 8 * 1024 * 1024;
const LINE_LIMIT: usize = 1024 * 1024;
const NO_PROGRESS: &str = "worker_no_progress";

pub(super) fn guarded_worker(spec: &ExternalAgentCommand) -> bool {
    spec.invocation == ExternalAgentInvocation::Grok
        && !grok_acp_stdio_protocol_selected(spec)
        && spec.output_schema.is_some()
        && spec.workspace_access == WorkspaceAccess::ReadWrite
        && spec
            .agent_lifecycle
            .as_ref()
            .is_some_and(|identity| identity.role == "worker")
}

/// Only a bounded complete native stream can authorize a continuation. Missing
/// evidence remains missing and is handled by normal output validation.
fn idle_session(bytes: &[u8]) -> Option<String> {
    let stream = parse_grok_event_stream(bytes).ok()?;
    if !stream.successful_completion() {
        return None;
    }
    let GrokStreamOutcome::Completed(end) = stream.outcome() else {
        return None;
    };
    let report = end.structured_output()?;
    if report.get("role")?.as_str()? != "worker" {
        return None;
    }
    let status = report.get("status")?.as_str()?;
    if !matches!(status, "pending" | "not_started" | "not-started")
        || !report.get("commands_run")?.as_array()?.is_empty()
    {
        return None;
    }
    // Unknown event types do not mint tool progress. These are the native tool
    // events; commands reported by the Worker also prevent this specific guard.
    if bytes
        .split(|byte| *byte == b'\n')
        .filter_map(|line| serde_json::from_slice::<serde_json::Value>(line).ok())
        .any(|event| {
            matches!(
                event.get("type").and_then(serde_json::Value::as_str),
                Some("tool_call" | "tool_call_update" | "tool_use")
            )
        })
    {
        return None;
    }
    Some(end.session_id().to_owned())
}

pub(super) fn worker_no_progress(bytes: &[u8]) -> bool {
    idle_session(bytes).is_some()
}

fn valid_session_id(session: &str) -> bool {
    // UUID-shaped IDs only: --resume must never fall back to matching a title.
    session.len() == 36
        && session.bytes().enumerate().all(|(i, b)| {
            if matches!(i, 8 | 13 | 18 | 23) {
                b == b'-'
            } else {
                b.is_ascii_hexdigit()
            }
        })
}

#[derive(Default)]
struct Guard {
    prior: Option<Vec<u8>>,
    last: Option<Vec<u8>>,
    resumed_session: Option<String>,
    boundaries: Vec<i64>,
}

impl Guard {
    fn finished_turn(&mut self, bytes: Vec<u8>, code: i64) -> Result<Option<String>, String> {
        if let Some(expected) = &self.resumed_session {
            let stream =
                parse_grok_event_stream(&bytes).map_err(|_| "Grok continuation stream invalid")?;
            let GrokStreamOutcome::Completed(end) = stream.outcome() else {
                return Err("Grok continuation failed".into());
            };
            if end.session_id() != expected {
                return Err("Grok continuation session changed".into());
            }
        }
        let Some(session) = idle_session(&bytes) else {
            return Ok(None);
        };
        if self.prior.is_some() || code != 0 || !valid_session_id(&session) {
            return Err(NO_PROGRESS.into());
        }
        self.prior = Some(bytes);
        self.resumed_session = Some(session.clone());
        Ok(Some(session))
    }
}

fn interact(
    session: &mut ContainedProcessSession<'_>,
    guard: &mut Guard,
) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    let result = interact_turns(session, guard, &mut bytes);
    guard.last = Some(bytes.clone());
    result.map(|()| bytes)
}

fn interact_turns(
    session: &mut ContainedProcessSession<'_>,
    guard: &mut Guard,
    bytes: &mut Vec<u8>,
) -> Result<(), String> {
    let mut total = 0usize;
    loop {
        let mut line = Vec::new();
        match session.receive_line(Duration::from_millis(100), LINE_LIMIT, &mut line)? {
            InteractiveProcessRead::Timeout => continue,
            InteractiveProcessRead::Eof => {
                return Err("Grok worker exited before turn boundary".into())
            }
            InteractiveProcessRead::Line => {}
        }
        total = total.saturating_add(line.len());
        if total > LIMIT {
            return Err("Grok worker continuation output exceeds bound".into());
        }
        let event: serde_json::Value =
            serde_json::from_slice(&line).map_err(|_| "Grok worker stream invalid")?;
        if event.get("type").and_then(serde_json::Value::as_str) == Some("maco_grok_turn_exit") {
            let code = event
                .get("code")
                .and_then(serde_json::Value::as_i64)
                .ok_or("Grok worker boundary missing status")?;
            guard.boundaries.push(code);
            if let Some(resume) = guard.finished_turn(bytes.clone(), code)? {
                tracing::info!("worker_no_progress: continuing same Grok session once within original deadline");
                session.send_line(resume.as_bytes())?;
                bytes.clear();
                continue;
            }
            session.send_line(b"")?;
            return Ok(());
        }
        bytes.extend_from_slice(&line);
        if !line.ends_with(b"\n") {
            bytes.push(b'\n');
        }
    }
}

type BatchCapture = (
    ProcessOutput,
    Option<ReadOnlyFilesystemEvidence>,
    Option<Vec<u8>>,
);

fn capture_matches(
    raw: &CapturedBytes,
    prior: Option<&[u8]>,
    last: &[u8],
    boundaries: &[i64],
) -> bool {
    let mut expected = Vec::new();
    if let Some(previous) = prior {
        expected.extend_from_slice(previous);
        expected.extend_from_slice(b"{\"type\":\"maco_grok_turn_exit\",\"code\":0}\n");
    }
    expected.extend_from_slice(last);
    if let Some(code) = boundaries.last() {
        expected.extend_from_slice(
            format!("{{\"type\":\"maco_grok_turn_exit\",\"code\":{code}}}\n").as_bytes(),
        );
    }
    !raw.is_truncated() && raw.as_bytes() == expected
}

pub(super) fn run(
    mut spec: ProcessSpec,
    cancellation: &ProcessCancellation,
) -> Result<BatchCapture, ProcessRunError> {
    spec.grok_worker_continuation = true;
    let mut guard = Guard::default();
    let mut final_bytes = None;
    let mut interactive = run_process_interactive(spec, cancellation, |session| {
        let result = interact(session, &mut guard);
        if let Ok(bytes) = &result {
            final_bytes = Some(bytes.clone());
        }
        result.map(|_| ())
    })?;
    if let Err(error) = interactive.interaction {
        interactive.process.process_error =
            append_external_error(interactive.process.process_error.take(), Some(error));
    }
    let mut prior = guard.prior;
    if let Some(bytes) = final_bytes.or(guard.last) {
        if capture_matches(
            &interactive.process.stdout,
            prior.as_deref(),
            &bytes,
            &guard.boundaries,
        ) {
            interactive.process.stdout = CapturedBytes::from_bounded_protocol(bytes);
        } else {
            // Keep the raw native capture and its first known spend floor.
            // Do not double-count the first turn or ignore post-terminal bytes.
            prior = None;
            interactive.process.process_error = append_external_error(
                interactive.process.process_error.take(),
                Some("Grok continuation has incomplete or trailing output".into()),
            );
        }
    }
    Ok((interactive.process, None, prior))
}

#[cfg(test)]
mod tests {
    use super::*;
    const SESSION: &str = "6b3056ad-f990-4314-b7ff-f9e58c593ac5";
    fn stream(status: &str, commands: serde_json::Value, tool: bool) -> Vec<u8> {
        let mut bytes = Vec::new();
        if tool {
            bytes.extend_from_slice(b"{\"type\":\"tool_call\",\"id\":\"t1\"}\n");
        }
        bytes.extend_from_slice(
            serde_json::json!({"type":"end", "stopReason":"end_turn",
            "sessionId":SESSION, "requestId":"r1", "structuredOutput":{
                "role":"worker", "status":status, "commands_run":commands
            }, "usage":{"input_tokens":2,"output_tokens":3,"cache_read_input_tokens":0,
                "cache_creation_input_tokens":0,"total_tokens":5}})
            .to_string()
            .as_bytes(),
        );
        bytes.push(b'\n');
        bytes
    }
    #[test]
    fn grok_no_progress_continues_same_session_once_then_accepts_progress() {
        let mut guard = Guard::default();
        assert_eq!(
            guard
                .finished_turn(stream("pending", serde_json::json!([]), false), 0)
                .unwrap()
                .as_deref(),
            Some(SESSION)
        );
        assert!(guard
            .finished_turn(
                stream(
                    "completed",
                    serde_json::json!([{"command":["git","diff"]}]),
                    true
                ),
                0
            )
            .unwrap()
            .is_none());
        assert!(guard.prior.is_some());
    }
    #[test]
    fn grok_no_progress_second_idle_turn_fails_closed() {
        let mut guard = Guard::default();
        let bytes = stream("pending", serde_json::json!([]), false);
        assert!(guard.finished_turn(bytes.clone(), 0).unwrap().is_some());
        assert_eq!(guard.finished_turn(bytes, 0).unwrap_err(), NO_PROGRESS);
    }
    #[test]
    fn grok_no_progress_keeps_unknown_and_real_tool_evidence_distinct() {
        assert!(idle_session(b"unknown").is_none());
        assert!(idle_session(&stream("pending", serde_json::json!([]), true)).is_none());
        assert!(idle_session(&stream("pending", serde_json::json!([{}]), false)).is_none());
        assert!(!valid_session_id("--option"));
        assert!(!valid_session_id("session title"));
        assert!(valid_session_id(SESSION));
        assert_eq!(
            Guard::default()
                .finished_turn(stream("pending", serde_json::json!([]), false), 1)
                .unwrap_err(),
            NO_PROGRESS
        );
        let mut guard = Guard::default();
        guard
            .finished_turn(stream("pending", serde_json::json!([]), false), 0)
            .unwrap();
        let changed = String::from_utf8(stream("completed", serde_json::json!([]), false))
            .unwrap()
            .replace(SESSION, "11111111-1111-1111-1111-111111111111");
        assert!(guard
            .finished_turn(changed.into_bytes(), 0)
            .unwrap_err()
            .contains("session changed"));
    }
    #[test]
    fn grok_launch_policy_evidence_requires_observed_outer_containment() {
        let spec =
            ExternalAgentCommand::codex("grok", ".", "p", "log", "report", Duration::from_secs(1))
                .with_runtime_adapter(
                    crate::runtime_adapter::RuntimeId::Grok,
                    RuntimeAdapterConfig::defaults(crate::runtime_adapter::RuntimeId::Grok),
                );
        let mut report = failed_external_run(&spec, Instant::now(), vec![], false, String::new());
        record_launch_policy(&mut report, &spec, ExternalExecutionRuntime::Verified);
        assert!(report.stderr.text.is_empty());
        report.stdout.target_launch_attempted = true;
        report.side_effects = Some(
            crate::process_runner::SideEffectConfinementEvidence::Verified(
                SideEffectConfinementProfileKind::ExternalGrok,
            ),
        );
        record_launch_policy(&mut report, &spec, ExternalExecutionRuntime::Verified);
        assert!(report
            .stderr
            .text
            .contains("inner_sandbox=disabled_outer_containment_enforced"));
        let wire = serde_json::to_value(&report).unwrap();
        assert!(wire["stderr"]["text"]
            .as_str()
            .unwrap()
            .contains("MACO launch policy:"));
    }

    #[cfg(unix)]
    #[test]
    fn grok_continuation_protocol_runs_tools_and_rejects_second_idle_report() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;
        for progress in [true, false] {
            let temp = tempfile::tempdir()?;
            let script = temp.path().join("fake-grok");
            let first = String::from_utf8(stream("pending", serde_json::json!([]), false))?;
            let second = String::from_utf8(stream(
                if progress { "completed" } else { "pending" },
                if progress {
                    serde_json::json!([{"command":["append"]}])
                } else {
                    serde_json::json!([])
                },
                progress,
            ))?;
            // Synthetic provider only; the real installed Grok is never invoked.
            std::fs::write(
                &script,
                format!(
                    r#"#!/bin/sh
set -eu
if [ ! -f invoked ]; then
    : > invoked
    [ "$1" = --no-auto-update ] && [ "$2" = --prompt-file ]
    [ "$3" = prompt.md ]
    printf '%s' '{first}'
else
    [ "$2" = --single ]
    [ "$3" = 'Perform the assignment now using your tools, then return the final report.' ]
    [ "$4" = --resume ] && [ "$5" = '{SESSION}' ]
    [ "$6" = --model ] && [ "$7" = grok-4.6 ]
    [ "$8" = --sandbox ] && [ "$9" = off ]
    [ "${{10}}" = --no-subagents ] && [ "${{11}}" = --no-leader ]
    printf '%s' '{second}'
    {edit}
fi
"#,
                    edit = if progress {
                        "printf 'Hello from MACO\\n' >> README.md"
                    } else {
                        ":"
                    }
                ),
            )?;
            std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700))?;
            std::fs::write(temp.path().join("README.md"), "original\n")?;
            let wrapper = temp.path().join("continuation.sh");
            std::fs::write(
                &wrapper,
                crate::runtime_adapter::grok::GROK_WORKER_CONTINUATION_SCRIPT,
            )?;
            let spec = ProcessSpec::direct(
                "synthetic continuation protocol",
                "/bin/sh",
                vec![
                    wrapper.into_os_string(),
                    script.into_os_string(),
                    OsString::from("--no-auto-update"),
                    OsString::from("--prompt-file"),
                    OsString::from("prompt.md"),
                    OsString::from("--model"),
                    OsString::from("grok-4.6"),
                    OsString::from("--sandbox"),
                    OsString::from("off"),
                    OsString::from("--no-subagents"),
                    OsString::from("--no-leader"),
                ],
                temp.path(),
                LIMIT,
            )
            .with_containment(crate::process_runner::ContainmentPolicy::TrustedBestEffort)
            .with_side_effect_confinement(SideEffectConfinementProfile::TrustedCompatibility)
            .with_timeout(Some(Duration::from_secs(3)));
            let mut guard = Guard::default();
            let outcome = run_process_interactive(spec, &ProcessCancellation::new(), |session| {
                interact(session, &mut guard)
            })?;
            assert!(guard.prior.is_some());
            let final_bytes = guard.last.as_deref().unwrap();
            assert!(capture_matches(
                &outcome.process.stdout,
                guard.prior.as_deref(),
                final_bytes,
                &guard.boundaries
            ));
            let mut trailing = outcome.process.stdout.as_bytes().to_vec();
            trailing.extend_from_slice(b"{\"type\":\"text\",\"data\":\"extra\"}\n");
            assert!(!capture_matches(
                &CapturedBytes::from_bounded_protocol(trailing),
                guard.prior.as_deref(),
                final_bytes,
                &guard.boundaries
            ));
            if progress {
                assert!(outcome.interaction.is_ok(), "{:?}", outcome.interaction);
                assert!(outcome.process.status.is_some_and(|s| s.success()));
                assert_eq!(
                    std::fs::read_to_string(temp.path().join("README.md"))?,
                    "original\nHello from MACO\n"
                );
            } else {
                assert_eq!(outcome.interaction.unwrap_err(), NO_PROGRESS);
                assert_eq!(
                    std::fs::read_to_string(temp.path().join("README.md"))?,
                    "original\n"
                );
            }
        }
        Ok(())
    }
}
