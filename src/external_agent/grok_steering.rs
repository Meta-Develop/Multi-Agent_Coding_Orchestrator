//! Grok ACP stdio bridge from authenticated steering mailbox to protocol steering hooks.

use crate::external_agent::ExternalAgentLifecycleIdentity;
use crate::runtime_adapter::grok_acp::{GrokAcpCorrection, GrokAcpSteering};
use crate::steering::{SteeringAction, SteeringOutcome, SteeringPlane};
use anyhow::{Context, Result};
use std::time::{Duration, Instant};

pub(crate) struct GrokAcpSteeringBridge {
    plane: SteeringPlane,
    run_id: String,
    assignment_id: String,
    in_flight_action_id: Option<String>,
}

impl GrokAcpSteeringBridge {
    pub(crate) fn from_identity(identity: &ExternalAgentLifecycleIdentity) -> Result<Self> {
        let plane = SteeringPlane::open(&identity.registry_repo).with_context(|| {
            format!(
                "failed to open steering plane for {}",
                identity.registry_repo.display()
            )
        })?;
        Ok(Self {
            plane,
            run_id: identity.run_id.clone(),
            assignment_id: identity.task_id.clone(),
            in_flight_action_id: None,
        })
    }

    pub(crate) fn finalize_after_child_exit(&self) -> Result<()> {
        self.plane
            .finalize_assignment_execution_pending(&self.run_id, &self.assignment_id)
    }
}

impl GrokAcpSteering for GrokAcpSteeringBridge {
    fn next_correction(&mut self) -> Result<Option<GrokAcpCorrection>, String> {
        if self.in_flight_action_id.is_some() {
            return Ok(None);
        }

        let poll_started = Instant::now();
        let now_unix_ms = self
            .plane
            .current_unix_ms()
            .map_err(|error| error.to_string())?;
        self.plane
            .sweep_assignment_deadlines(&self.run_id, &self.assignment_id, now_unix_ms)
            .map_err(|error| error.to_string())?;

        let directives = self
            .plane
            .inbox(&self.run_id, &self.assignment_id)
            .map_err(|error| error.to_string())?;
        let mut ordered = directives;
        ordered.sort_by(|left, right| left.action_id.cmp(&right.action_id));

        for directive in ordered {
            if !matches!(
                directive.outcome,
                SteeringOutcome::Pending | SteeringOutcome::Delivered
            ) {
                continue;
            }
            if now_unix_ms > directive.deadline_unix_ms {
                continue;
            }
            match &directive.action {
                SteeringAction::InjectCorrectiveInput { message } => {
                    if directive.outcome != SteeringOutcome::Delivered {
                        continue;
                    }
                    let remaining_ms = directive.deadline_unix_ms - now_unix_ms;
                    let remaining = Duration::from_millis(remaining_ms);
                    let Some(deadline) = poll_started.checked_add(remaining) else {
                        continue;
                    };
                    if Instant::now() >= deadline {
                        continue;
                    }
                    self.in_flight_action_id = Some(directive.action_id.clone());
                    return Ok(Some(GrokAcpCorrection {
                        action_id: directive.action_id,
                        prompt: message.clone(),
                        deadline,
                    }));
                }
                _ => {
                    self.plane
                        .refuse_runtime_unsupported_live_action(
                            &self.run_id,
                            &self.assignment_id,
                            &directive.action_id,
                            now_unix_ms,
                        )
                        .map_err(|error| error.to_string())?;
                }
            }
        }

        Ok(None)
    }

    fn acknowledge(&mut self, action_id: &str) -> Result<(), String> {
        if self.in_flight_action_id.as_deref() != Some(action_id) {
            return Err(format!(
                "steering acknowledge for unexpected action {action_id}"
            ));
        }
        self.in_flight_action_id = None;
        let now_unix_ms = self
            .plane
            .current_unix_ms()
            .map_err(|error| error.to_string())?;
        let ack = self
            .plane
            .acknowledge(&self.run_id, &self.assignment_id, action_id, now_unix_ms)
            .map_err(|error| error.to_string())?;
        if ack.outcome != SteeringOutcome::Acknowledged || !ack.steered {
            return Err(format!(
                "steering action {action_id} was not durably steered (outcome={ack:?})"
            ));
        }
        Ok(())
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use crate::external_agent::{
        run_external_agent_nonpublishable_simulation, ExternalAgentCommand, ExternalAgentInvocation,
    };
    use crate::process_runner::WorkspaceAccess;
    use crate::runtime_adapter::{RuntimeAdapterConfig, RuntimeId};
    use crate::steering::{SteeringActor, SteeringRequest, STEERING_REQUEST_VERSION};
    use anyhow::{bail, Context, Result};
    use git2::Repository;
    use std::{
        fs,
        path::{Path, PathBuf},
        thread,
        time::{Duration, Instant},
    };

    const GROK_ACP_STEER_OPERATION_TIMEOUT: Duration = Duration::from_secs(10);
    const PERMANENT_CONTROL_ROOTS: &[&str] = &[".maco", ".maco-cache", ".codex"];
    const POLICY_CONTROL_ROOTS: &[&str] = &[".agents"];

    const STEERABLE_GROK_ACP_DRIVER_PY: &str = r#"import json, sys
from pathlib import Path

MODE = sys.argv[1]
SIGNAL = Path(sys.argv[2])
SESSION = "sess-steer"
XAI = "_x.ai/session_notification"

def send(v):
    sys.stdout.write(json.dumps(v, separators=(",", ":")) + "\n")
    sys.stdout.flush()

def recv():
    line = sys.stdin.readline()
    if not line:
        sys.exit(0)
    return json.loads(line)

def usage_payload():
    return {
        "inputTokens": 10,
        "outputTokens": 2,
        "costUsdTicks": 20000000,
    }

def prompt_result(msg, text, stop_reason="end_turn"):
    send({
        "jsonrpc": "2.0",
        "id": msg["id"],
        "result": {
            "stopReason": stop_reason,
            "text": text,
            "usage_is_incomplete": False,
            "cost_is_partial": False,
            "_meta": {"usage": usage_payload()},
        },
    })

msg = recv()
assert msg["method"] == "initialize"
send({"jsonrpc": "2.0", "id": msg["id"], "result": {"protocolVersion": 1}})
msg = recv()
assert msg["method"] == "session/new"
send({"jsonrpc": "2.0", "id": msg["id"], "result": {"sessionId": SESSION}})
msg = recv()
assert msg["method"] == "session/set_model"
send({
    "jsonrpc": "2.0",
    "method": XAI,
    "params": {
        "sessionId": SESSION,
        "update": {
            "sessionUpdate": "model_changed",
            "model_id": "grok-resolved-4",
            "reasoning_effort": "high",
        },
    },
})
send({"jsonrpc": "2.0", "id": msg["id"], "result": {"_meta": {"model": "grok-resolved-4"}}})

first_prompt = None
corrective_complete = False
while True:
    msg = recv()
    method = msg.get("method")
    if method == "session/prompt":
        if first_prompt is None:
            first_prompt = msg
            SIGNAL.write_text("started", encoding="utf-8")
            continue
        params = msg.get("params") or {}
        blocks = params.get("prompt") or []
        text = ""
        if blocks and isinstance(blocks[0], dict):
            text = blocks[0].get("text") or ""
        if "corrective-steer-token" not in text:
            raise SystemExit("corrective prompt missing expected token")
        prompt_result(msg, "corrected-terminal-text")
        corrective_complete = True
        continue
    if method == "session/cancel":
        if "id" in msg:
            send({"jsonrpc": "2.0", "id": msg["id"], "result": {}})
        if MODE == "eof_lost":
            sys.exit(0)
        if corrective_complete:
            sys.exit(0)
        if first_prompt is not None:
            prompt_result(first_prompt, "original-drained", "cancelled")
            continue
        continue
    if method == "terminal/create":
        if "id" in msg:
            send({
                "jsonrpc": "2.0",
                "id": msg["id"],
                "error": {"code": -32601, "message": "forbidden"},
            })
"#;

    fn create_mandatory_control_roots(workspace: &Path) -> Result<()> {
        fs::create_dir_all(workspace)?;
        fs::create_dir_all(workspace.join(".git"))?;
        for root in PERMANENT_CONTROL_ROOTS.iter().chain(POLICY_CONTROL_ROOTS) {
            fs::create_dir_all(workspace.join(root))?;
        }
        Ok(())
    }

    fn init_git_repo(path: &Path) -> Result<()> {
        Repository::init(path)?;
        create_mandatory_control_roots(path)?;
        Ok(())
    }

    fn write_steerable_provider(fixture_root: &Path, mode: &str, signal: &Path) -> Result<PathBuf> {
        let driver = fixture_root.join("steer-grok-acp-driver.py");
        fs::write(&driver, STEERABLE_GROK_ACP_DRIVER_PY)?;
        let provider = fixture_root.join(format!("steer-grok-acp-{mode}"));
        let signal = format!("'{}'", signal.to_string_lossy().replace('\'', "'\\''"));
        fs::write(
            &provider,
            format!(
                "#!/bin/sh\nset -eu\nMODE={mode}\nSIGNAL={signal}\ncase \" $* \" in *\" agent \"*) ;; *) exit 3;; esac\ncase \" $* \" in *\" --no-leader \"*) ;; *) exit 3;; esac\ncase \" $* \" in *\" stdio \"*) ;; *) exit 4;; esac\nexec python3 \"$(dirname \"$0\")/steer-grok-acp-driver.py\" \"$MODE\" \"$SIGNAL\"\n"
            ),
        )?;
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&provider, fs::Permissions::from_mode(0o755))?;
        Ok(provider)
    }

    fn grok_acp_command(
        provider: &Path,
        workspace: &Path,
        incoming: &Path,
        supervisor_repo: &Path,
        run_id: &str,
        task_id: &str,
    ) -> ExternalAgentCommand {
        fs::create_dir_all(incoming).expect("incoming");
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(incoming, fs::Permissions::from_mode(0o700)).expect("incoming mode");
        let mut config = RuntimeAdapterConfig::defaults(RuntimeId::Grok);
        config.grok_interaction_protocol =
            crate::runtime_adapter::GrokInteractionProtocol::AcpStdio;
        config.argument_template =
            crate::runtime_adapter::grok::GROK_ACP_RUNTIME_DESCRIPTOR.immutable_argument_template();
        let mut command = ExternalAgentCommand::codex(
            provider,
            workspace,
            workspace.join("prompt.md"),
            incoming.join("events.jsonl"),
            incoming.join("report.json"),
            GROK_ACP_STEER_OPERATION_TIMEOUT,
        );
        command.invocation = ExternalAgentInvocation::Grok;
        command.workspace_access = WorkspaceAccess::ReadOnly;
        command.runtime_adapter = Some(config);
        command.model = Some("grok-requested-4".to_string());
        command.reasoning_effort = Some("low".to_string());
        command.with_agent_lifecycle(supervisor_repo, "worker", run_id, task_id)
    }

    fn operator_inject(
        run_id: &str,
        assignment_id: &str,
        action_id: &str,
        message: &str,
        now_unix_ms: u64,
        operation_timeout: Duration,
    ) -> SteeringRequest {
        SteeringRequest {
            version: STEERING_REQUEST_VERSION,
            action_id: action_id.to_string(),
            run_id: run_id.to_string(),
            assignment_id: assignment_id.to_string(),
            actor: SteeringActor::Operator {
                agent_id: "operator".to_string(),
            },
            action: SteeringAction::InjectCorrectiveInput {
                message: message.to_string(),
            },
            deadline_unix_ms: now_unix_ms
                + u64::try_from(operation_timeout.as_millis())
                    .expect("operation timeout fits in unix milliseconds"),
        }
    }

    fn wait_for_signal(signal: &Path, readiness_deadline: Instant) -> Result<()> {
        while !signal.exists() {
            if Instant::now() >= readiness_deadline {
                bail!("timed out waiting for Grok ACP prompt-start signal");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        Ok(())
    }

    fn final_action_outcome(
        plane: &SteeringPlane,
        run_id: &str,
        action_id: &str,
    ) -> Result<(SteeringOutcome, bool)> {
        let evidence = plane.evidence(run_id)?;
        let record = evidence
            .iter()
            .filter(|record| record.action_id == action_id)
            .max_by_key(|record| record.sequence)
            .with_context(|| format!("missing steering evidence for action {action_id}"))?;
        Ok((record.outcome, record.steered))
    }

    #[test]
    fn grok_acp_stdio_steering_applies_corrective_input_and_durable_ack() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let supervisor_repo = temp.path().join("supervisor-repo");
        let fixture_root = temp.path().join("fixture-root");
        let child_workspace = fixture_root.join("child-worktree");
        let incoming = fixture_root.join("incoming");
        init_git_repo(&supervisor_repo)?;
        init_git_repo(&child_workspace)?;
        fs::write(
            child_workspace.join("prompt.md"),
            "original grok acp prompt\n",
        )?;

        let signal = incoming.join("grok-acp-prompt-started");
        let provider = write_steerable_provider(&fixture_root, "steer", &signal)?;
        let command = grok_acp_command(
            &provider,
            &child_workspace,
            &incoming,
            &supervisor_repo,
            "run-steer",
            "task-steer",
        );

        let operator_plane = SteeringPlane::open(&supervisor_repo)?;
        let readiness_deadline = Instant::now() + GROK_ACP_STEER_OPERATION_TIMEOUT;
        let runner = thread::spawn(move || run_external_agent_nonpublishable_simulation(&command));
        let interaction = (|| -> Result<()> {
            wait_for_signal(&signal, readiness_deadline)?;
            let now = operator_plane.current_unix_ms()?;
            let request = operator_inject(
                "run-steer",
                "task-steer",
                "act-steer",
                "corrective-steer-token: tighten scope",
                now,
                GROK_ACP_STEER_OPERATION_TIMEOUT,
            );
            let decision = operator_plane.submit(request, now)?;
            assert_eq!(decision.ack().outcome, SteeringOutcome::Delivered);
            Ok(())
        })();
        let report = runner
            .join()
            .map_err(|_| anyhow::anyhow!("grok acp steering runner panicked"))?;
        interaction?;
        assert!(
            report.simulation_succeeded(),
            "steered grok acp run failed: {report:#?}"
        );
        let parent = report
            .grok_acp_parent_evidence
            .as_ref()
            .context("parent evidence")?;
        assert_eq!(
            parent.final_text.as_deref(),
            Some("corrected-terminal-text")
        );

        let reopened = SteeringPlane::open(&supervisor_repo)?;
        let (outcome, steered) = final_action_outcome(&reopened, "run-steer", "act-steer")?;
        assert_eq!(outcome, SteeringOutcome::Acknowledged);
        assert!(steered);
        Ok(())
    }

    #[test]
    fn grok_acp_stdio_eof_lost_child_leaves_correction_unsteered() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let supervisor_repo = temp.path().join("supervisor-repo");
        let fixture_root = temp.path().join("fixture-root");
        let child_workspace = fixture_root.join("child-worktree");
        let incoming = fixture_root.join("incoming");
        init_git_repo(&supervisor_repo)?;
        init_git_repo(&child_workspace)?;
        fs::write(
            child_workspace.join("prompt.md"),
            "original grok acp prompt\n",
        )?;

        let signal = incoming.join("grok-acp-prompt-started");
        let provider = write_steerable_provider(&fixture_root, "eof_lost", &signal)?;
        let command = grok_acp_command(
            &provider,
            &child_workspace,
            &incoming,
            &supervisor_repo,
            "run-lost",
            "task-lost",
        );

        let operator_plane = SteeringPlane::open(&supervisor_repo)?;
        let readiness_deadline = Instant::now() + GROK_ACP_STEER_OPERATION_TIMEOUT;
        let runner = thread::spawn(move || run_external_agent_nonpublishable_simulation(&command));
        let interaction = (|| -> Result<()> {
            wait_for_signal(&signal, readiness_deadline)?;
            let now = operator_plane.current_unix_ms()?;
            let request = operator_inject(
                "run-lost",
                "task-lost",
                "act-lost",
                "corrective-steer-token: too late",
                now,
                GROK_ACP_STEER_OPERATION_TIMEOUT,
            );
            let decision = operator_plane.submit(request, now)?;
            assert_eq!(decision.ack().outcome, SteeringOutcome::Delivered);
            Ok(())
        })();
        let report = runner
            .join()
            .map_err(|_| anyhow::anyhow!("grok acp lost-child runner panicked"))?;
        interaction?;
        assert!(
            !report.simulation_succeeded(),
            "lost child must not report simulation success: {report:#?}"
        );

        let reopened = SteeringPlane::open(&supervisor_repo)?;
        let (outcome, steered) = final_action_outcome(&reopened, "run-lost", "act-lost")?;
        assert_eq!(outcome, SteeringOutcome::LostChild);
        assert!(!steered);
        Ok(())
    }
}
