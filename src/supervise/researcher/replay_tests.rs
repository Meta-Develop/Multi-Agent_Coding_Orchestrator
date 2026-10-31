use super::*;
use crate::external_agent::codex_app_server::{
    run_app_server_turn, AppServerLimits, AppServerTurn, ApprovalRequest,
    CommandExecutionObservation as Observation, CommandExecutionObservationIssue,
    CommandExecutionStatus as Status, JsonLineTransport, TransportRead,
};
use std::collections::VecDeque;

struct Replay(VecDeque<Vec<u8>>);

impl JsonLineTransport for Replay {
    fn receive(
        &mut self,
        _wait: Duration,
        max_line_bytes: usize,
        destination: &mut Vec<u8>,
    ) -> std::result::Result<TransportRead, String> {
        destination.clear();
        let Some(line) = self.0.pop_front() else {
            return Ok(TransportRead::Eof);
        };
        assert!(line.len() <= max_line_bytes);
        destination.extend(line);
        Ok(TransportRead::Line)
    }

    fn send(&mut self, line: &[u8]) -> std::result::Result<(), String> {
        serde_json::from_slice::<Value>(line).expect("valid client request");
        Ok(())
    }
}

#[test]
fn researcher_replays_codex_0162_login_shell_commands_without_invented_wrappers() -> Result<()> {
    let capture = include_str!("../../../tests/fixtures/codex-0.162.0/researcher-commands.jsonl");
    let first: Value = serde_json::from_str(capture.lines().next().unwrap())?;
    let thread = first["params"]["threadId"].as_str().unwrap();
    let turn = first["params"]["turnId"].as_str().unwrap();
    let mut transport = Replay(
        [
            json!({"id": 1, "result": {}}),
            json!({"id": 2, "result": {
                "thread": {"id": thread}, "model": "gpt-6.1-sol", "reasoningEffort": "xhigh",
                "approvalPolicy": "on-request", "approvalsReviewer": "user",
                "activePermissionProfile": {"id": "maco_external_codex"}, "cwd": "/workspace"
            }}),
            json!({"id": 3, "result": {"turn": {"id": turn, "status": "inProgress"}}}),
            json!({"method": "turn/started", "params": {
                "threadId": thread, "turn": {"id": turn, "status": "inProgress"}
            }}),
        ]
        .into_iter()
        .map(|value| value.to_string().into_bytes())
        .chain(capture.lines().map(|line| line.as_bytes().to_vec()))
        .chain(std::iter::once(
            json!({"method": "turn/completed", "params": {
                "threadId": thread, "turn": {"id": turn, "status": "completed"}
            }})
            .to_string()
            .into_bytes(),
        ))
        .collect(),
    );
    let outcome = run_app_server_turn(
        &mut transport,
        &AppServerTurn {
            cwd: "/workspace".to_string(),
            permission_profile: "maco_external_codex".to_string(),
            prompt: "offline command replay".to_string(),
            model: Some("gpt-6.1-sol".to_string()),
            minimum_effort: Some("xhigh".to_string()),
            output_schema: None,
        },
        AppServerLimits::default(),
        &mut |_: ApprovalRequest| Err("replay must not request approval".to_string()),
        || false,
    )?;
    let transcript = &outcome.command_execution_evidence;
    assert_eq!(transcript.observations.len(), 2);
    let recorded = read_researcher_report(
        Some(include_bytes!(
            "../../../tests/fixtures/codex-0.162.0/researcher-command-report.json"
        )),
        Path::new("report.json"),
    )?
    .report;
    // The old -c claims remain false even though the native -lc commands completed.
    assert!(verify_researcher_command_evidence(&recorded, Some(transcript)).is_err());
    let mut honest = recorded;
    for (index, submitted) in [
        "nl -ba examples/supervise/qualification-data/source-packet.md",
        "ps -p $$ -o args=; :",
    ]
    .into_iter()
    .enumerate()
    {
        honest.commands_run[index].command = vec![submitted.to_string()];
        honest.validation_results[index].command = vec![submitted.to_string()];
    }
    verify_researcher_command_evidence(&honest, Some(transcript))?;

    for invalid in [
        "true",
        "nl  -ba examples/supervise/qualification-data/source-packet.md",
        "nl -ba examples/supervise/qualification-data/source-packet.md ",
        "/bin/bash -lc 'nl -ba examples/supervise/qualification-data/source-packet.md'",
    ] {
        let mut forged = honest.clone();
        forged.commands_run[0].command = vec![invalid.to_string()];
        forged.validation_results[0].command = vec![invalid.to_string()];
        assert!(verify_researcher_command_evidence(&forged, Some(transcript)).is_err());
    }
    for case in ["duplicate", "absent", "cwd", "exit", "status", "validation"] {
        let mut forged = honest.clone();
        match case {
            "duplicate" => forged.commands_run[1] = forged.commands_run[0].clone(),
            "absent" => forged.commands_run.clear(),
            "cwd" => forged.commands_run[0].cwd = PathBuf::from("/other-workspace"),
            "exit" => forged.commands_run[0].exit_code = Some(1),
            "status" => forged.commands_run[0].status = ReviewStatus::Failed,
            "validation" => forged.validation_results[1] = forged.validation_results[0].clone(),
            _ => unreachable!(),
        }
        assert!(
            verify_researcher_command_evidence(&forged, Some(transcript)).is_err(),
            "{case}"
        );
    }
    for case in ["unfinished", "command", "cwd", "exit", "declined"] {
        let mut invalid = transcript.clone();
        let observation = &mut invalid.observations[0];
        let Observation::Complete {
            item_id,
            started,
            completed,
        } = observation
        else {
            panic!("capture must contain a complete command")
        };
        match case {
            "unfinished" => {
                *observation = Observation::Incomplete {
                    item_id: item_id.clone(),
                    started: Some(started.clone()),
                    reason: CommandExecutionObservationIssue::MissingOrInvalidCompletedFields,
                };
            }
            "command" => completed.command = completed.command.replace("-lc", "-c"),
            "cwd" => completed.cwd = "/other-workspace".to_string(),
            "exit" => {
                completed.status = Status::Failed;
                completed.exit_code = Some(1);
            }
            "declined" => {
                completed.status = Status::Declined;
                completed.exit_code = None;
            }
            _ => unreachable!(),
        }
        assert!(
            verify_researcher_command_evidence(&honest, Some(&invalid)).is_err(),
            "{case}"
        );
    }
    Ok(())
}
