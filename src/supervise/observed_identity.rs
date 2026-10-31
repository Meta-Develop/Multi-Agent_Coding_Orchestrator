//! Descriptive served identity from authenticated, dispatch-bound native receipts.
//! This readback grants no execution, acceptance, pricing, or selection authority.
use super::*;
use crate::external_agent::CodexParentEvidence;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RuntimeIdentityObservation {
    requested_model: Option<String>,
    requested_effort: Option<String>,
    model: Option<String>,
    effort: Option<String>,
}

impl RuntimeIdentityObservation {
    pub(super) fn capture(
        run: &ExternalAgentRun,
        command: &ExternalAgentCommand,
        runtime: SupervisorRuntime,
    ) -> Self {
        let mut identity = Self {
            requested_model: command.model.clone(),
            requested_effort: command.reasoning_effort.clone(),
            model: None,
            effort: None,
        };
        match runtime {
            SupervisorRuntime::Codex => {
                if let Some(evidence) = run.authenticated_codex_evidence().filter(|evidence| {
                    Some(*evidence) == run.codex_parent_evidence.as_ref()
                        && evidence.requested_model == command.model
                        && evidence.requested_effort == command.reasoning_effort
                }) {
                    (identity.model, identity.effort) = codex_identity(evidence);
                }
            }
            SupervisorRuntime::Grok => {
                identity.model = run.authenticated_grok_model(command).map(str::to_owned);
                // ACP client-resolved configuration and native request effort are not served effort.
            }
            SupervisorRuntime::ClaudeCode => {
                if run.authenticated_claude_usage_complete() {
                    identity.model = run.authenticated_claude_model().map(str::to_owned);
                    identity.effort = run.authenticated_claude_effort().map(str::to_owned);
                }
            }
            SupervisorRuntime::GeminiCli => {
                if let Some(evidence) = run
                    .gemini_bridge_evidence()
                    .filter(|evidence| evidence.usage_for_command(command).is_some())
                {
                    identity.model = evidence.actual_model().map(str::to_owned);
                    // The private bridge observes modelVersion, but no served thinking effort.
                }
            }
            // Cursor's public peer/client configuration is not private served-identity custody.
            SupervisorRuntime::Cursor | SupervisorRuntime::Fake => {}
        }
        identity
    }
}

fn codex_identity(evidence: &CodexParentEvidence) -> (Option<String>, Option<String>) {
    if evidence.resolution_status != "complete"
        || evidence.thread_id.as_ref().is_none_or(|id| id.is_empty())
        || evidence.model_mismatch
    {
        return (None, None);
    }
    // A reroute cannot establish one identity for all work in a cumulative turn.
    let model = evidence.usage_model().map(str::to_owned);
    let effort = model
        .as_ref()
        .and(evidence.observed_effort.known())
        .map(str::to_owned);
    (model, effort)
}

/// All retained dispatches for this role must bind the same requested selection
/// and agree on each observed field. A good attempt cannot hide an unknown retry.
pub(crate) fn observed_role_identity(
    reader: &ArtifactRunReader,
    role: AgentRole,
    runtime: SupervisorRuntime,
    requested_model: Option<&str>,
    requested_effort: Option<&str>,
) -> Result<(Option<String>, Option<String>)> {
    // Interrupted retention may leave a receipt with no summary. Do not let a
    // remaining good attempt hide that missing dispatch observation.
    for file in &reader.finalization().files {
        if !file
            .path
            .to_string_lossy()
            .ends_with(".target-containment.json")
        {
            continue;
        }
        if file.bytes > MAX_RECEIPT_BYTES as u64
            || file.disposition != ArtifactFileDisposition::PrivateEvidence
        {
            bail!("identity target receipt must be bounded private evidence");
        }
        let receipt: TargetContainmentReceipt = serde_json::from_slice(&reader.read(&file.path)?)?;
        if receipt_path(&receipt.binding.command_summary) != file.path
            || !reader
                .finalization()
                .files
                .iter()
                .any(|summary| summary.path == receipt.binding.command_summary)
        {
            bail!("identity target receipt lacks its bound process summary");
        }
    }
    let mut identities = Vec::new();
    for file in &reader.finalization().files {
        let name = file
            .path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("");
        if !(name.ends_with(".summary.json")
            || file.path.starts_with("nested") && name == "command.json")
        {
            continue;
        }
        let relative = receipt_path(&file.path);
        let record = reader
            .finalization()
            .files
            .iter()
            .find(|file| file.path == relative)
            .context("process summary lacks its source-bound target receipt")?;
        if record.bytes > MAX_RECEIPT_BYTES as u64
            || record.disposition != ArtifactFileDisposition::PrivateEvidence
        {
            bail!("identity target receipt must be bounded private evidence");
        }
        let receipt: TargetContainmentReceipt = serde_json::from_slice(&reader.read(&relative)?)?;
        let binding = &receipt.binding;
        if binding.run_id != reader.finalization().run_id
            || binding.command_summary != file.path
            || binding.attempt == 0
            || normalize_agent_id(&binding.task_id)? != binding.task_id
        {
            bail!("identity receipt run, task, attempt, or summary binding mismatch");
        }
        let plain = PathBuf::from("logs").join(format!("{}.summary.json", binding.task_id));
        let numbered = PathBuf::from("logs").join(format!(
            "{}.attempt-{}.summary.json",
            binding.task_id, binding.attempt
        ));
        let nested = binding.parent.as_ref().map(|parent| {
            PathBuf::from("nested")
                .join(parent)
                .join(format!("attempt-{}", binding.attempt))
                .join(&binding.task_id)
                .join("command.json")
        });
        if (file.path != plain && file.path != numbered && nested.as_ref() != Some(&file.path))
            || ![
                AgentRole::Supervisor,
                AgentRole::ChildOrchestrator,
                AgentRole::Worker,
                AgentRole::Researcher,
                AgentRole::GateClassifier,
                AgentRole::Auditor,
            ]
            .iter()
            .any(|role| role.as_str() == binding.role)
        {
            bail!("identity receipt role or lifecycle path mismatch");
        }
        // Authenticate even other roles' receipts, so an unbound summary cannot
        // disappear from the population merely by changing its role label.
        read(reader, binding)?;
        if binding.role != role.as_str() {
            continue;
        }
        if binding.runtime != runtime {
            bail!("observed role dispatch runtime differs from the requested runtime");
        }
        let summary: Value = serde_json::from_slice(&reader.read(&file.path)?)?;
        let identity = if let Some(value) = summary.get("runtime_identity") {
            serde_json::from_value::<RuntimeIdentityObservation>(value.clone())?
        } else if runtime == SupervisorRuntime::Codex {
            // Historical parent summaries already retained the native Codex receipt.
            // This is never read from child reports, arbitrary logs, or usage labels.
            let evidence = summary
                .get("codex_parent_evidence")
                .filter(|value| !value.is_null())
                .map(|value| serde_json::from_value::<CodexParentEvidence>(value.clone()))
                .transpose()?;
            let Some(evidence) = evidence else {
                identities.push((None, None));
                continue;
            };
            let (model, effort) = codex_identity(&evidence);
            RuntimeIdentityObservation {
                requested_model: evidence.requested_model,
                requested_effort: evidence.requested_effort,
                model,
                effort,
            }
        } else {
            identities.push((None, None));
            continue;
        };
        if identity.requested_model.as_deref() != requested_model
            || identity.requested_effort.as_deref() != requested_effort
        {
            bail!("native identity receipt requested selection differs from the role dispatch");
        }
        if let Some(model) = &identity.model {
            let matches = if runtime == SupervisorRuntime::Grok {
                requested_model.is_some_and(|requested| {
                    crate::runtime_adapter::grok::identity::served_model_matches(requested, model)
                })
            } else {
                requested_model.is_none_or(|requested| requested == model)
            };
            if !matches {
                bail!("observed model differs from the role dispatch selection");
            }
        }
        if identity
            .effort
            .as_deref()
            .is_some_and(|effort| requested_effort.is_some_and(|requested| requested != effort))
        {
            bail!("observed effort differs from the role dispatch selection");
        }
        if receipt.target_launch_attempted {
            identities.push((identity.model, identity.effort));
        } else {
            identities.push((None, None));
        }
    }
    fn unanimous(values: impl Iterator<Item = Option<String>>) -> Option<String> {
        let values = values.collect::<Option<Vec<_>>>()?;
        let first = values.first()?;
        values
            .iter()
            .all(|value| value == first)
            .then(|| first.clone())
    }
    Ok((
        unanimous(identities.iter().map(|identity| identity.0.clone())),
        unanimous(identities.into_iter().map(|identity| identity.1)),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{external_agent::ExternalAgentInvocation, process_runner::CapturedBytes};

    fn command() -> ExternalAgentCommand {
        ExternalAgentCommand::codex(
            "unused",
            ".",
            "prompt",
            "log",
            "report",
            Duration::from_secs(1),
        )
        .with_model_selection(Some("gpt-6.1-sol".into()), Some("xhigh".into()))
    }

    #[test]
    fn native_identity_capture_requires_private_codex_custody_and_exact_request() {
        let command = command();
        let mut run = deterministic_fake_run(&command, Vec::new());
        run.codex_parent_evidence = Some(serde_json::from_value(json!({
            "codex_version":"0.162.0", "thread_id":"thread",
            "requested_model":"gpt-6.1-sol", "requested_effort":"xhigh",
            "rollout_model":"unknown", "rollout_effort":"unknown",
            "observed_model":{"known":"gpt-6.1-sol"}, "observed_effort":{"known":"xhigh"},
            "server_rerouted_model":null, "model_mismatch":false,
            "turn_usage":{"status":"known","input_tokens":10,"output_tokens":4,"cached_input_tokens":0,"reasoning_output_tokens":1},
            "resolution_status":"complete"
        })).unwrap());
        assert!(
            RuntimeIdentityObservation::capture(&run, &command, SupervisorRuntime::Codex)
                .model
                .is_none()
        );
        run.retain_app_server_parent_evidence_for_test();
        let identity =
            RuntimeIdentityObservation::capture(&run, &command, SupervisorRuntime::Codex);
        assert_eq!(identity.model.as_deref(), Some("gpt-6.1-sol"));
        assert_eq!(identity.effort.as_deref(), Some("xhigh"));
        let mut changed = command.clone();
        changed.reasoning_effort = Some("low".into());
        assert!(
            RuntimeIdentityObservation::capture(&run, &changed, SupervisorRuntime::Codex)
                .model
                .is_none()
        );
        let restored = serde_json::from_slice(&serde_json::to_vec(&run).unwrap()).unwrap();
        assert!(
            RuntimeIdentityObservation::capture(&restored, &command, SupervisorRuntime::Codex)
                .model
                .is_none()
        );
    }

    #[test]
    fn native_grok_capture_preserves_model_only_and_refuses_rebinding_or_wire_copies() {
        let mut command =
            command().with_model_selection(Some("grok-4.6".into()), Some("xhigh".into()));
        command.invocation = ExternalAgentInvocation::Grok;
        let mut run = deterministic_fake_run(&command, Vec::new());
        let stdout = CapturedBytes::from_bytes_for_test(
            b"{\"type\":\"end\",\"stopReason\":\"end_turn\",\"sessionId\":\"s\",\"requestId\":\"r\",\"modelUsage\":{\"grok-4.6-build\":{}},\"effort\":\"xhigh\",\"usage\":{\"input_tokens\":9,\"output_tokens\":3,\"total_tokens\":12}}\n".to_vec());
        run.retain_grok_native_usage_for_test(&command, &stdout, true);
        let identity = RuntimeIdentityObservation::capture(&run, &command, SupervisorRuntime::Grok);
        assert_eq!(identity.model.as_deref(), Some("grok-4.6-build"));
        assert!(identity.effort.is_none());
        let mut changed = command.clone();
        changed.reasoning_effort = Some("low".into());
        assert!(
            RuntimeIdentityObservation::capture(&run, &changed, SupervisorRuntime::Grok)
                .model
                .is_none()
        );
        let restored = serde_json::from_slice(&serde_json::to_vec(&run).unwrap()).unwrap();
        assert!(
            RuntimeIdentityObservation::capture(&restored, &command, SupervisorRuntime::Grok)
                .model
                .is_none()
        );
    }
}
