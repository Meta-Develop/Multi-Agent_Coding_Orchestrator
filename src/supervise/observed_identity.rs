//! Descriptive served identity from authenticated, dispatch-bound native receipts.
//! This readback grants no execution, acceptance, pricing, or selection authority.
use super::*;
use crate::external_agent::CodexParentEvidence;

use crate::runtime_adapter::IdentityBasis;
pub use crate::runtime_adapter::RuntimeIdentityObservation;

impl RuntimeIdentityObservation {
    pub(crate) fn capture(
        run: &ExternalAgentRun,
        command: &ExternalAgentCommand,
        runtime: SupervisorRuntime,
    ) -> Self {
        let mut identity = Self {
            requested_model: command.model.clone(),
            requested_effort: command.reasoning_effort.clone(),
            model: None,
            effort: None,
            model_basis: None,
            effort_basis: None,
        };
        match runtime {
            SupervisorRuntime::Codex => {
                if let Some(evidence) = run.authenticated_codex_evidence().filter(|evidence| {
                    Some(*evidence) == run.codex_parent_evidence.as_ref()
                        && evidence.requested_model == command.model
                        && evidence.requested_effort == command.reasoning_effort
                }) {
                    (identity.model, identity.effort) = codex_identity(evidence);
                    if evidence.identity_matches_request() {
                        identity.model_basis = Some(if identity.model.is_some() {
                            IdentityBasis::ProviderReported
                        } else {
                            IdentityBasis::Requested
                        });
                        identity.effort_basis = command.reasoning_effort.as_ref().map(|_| {
                            if identity.effort.is_some() {
                                IdentityBasis::ProviderReported
                            } else {
                                IdentityBasis::Requested
                            }
                        });
                    }
                }
            }
            SupervisorRuntime::Grok => {
                identity.model = run.authenticated_grok_model(command).map(str::to_owned);
                // ACP acknowledges client settings, not served effort. Only the
                // original launch/output custody can bind that requested basis.
                if command.runtime_adapter.as_ref().is_some_and(|config| {
                    config.grok_interaction_protocol()
                        == crate::runtime_adapter::GrokInteractionProtocol::AcpStdio
                }) && run.stdout.target_launch_attempted
                    && run.output_last_message().is_some()
                    && crate::runtime_adapter::TypedRuntime::from_launch(
                        crate::runtime_adapter::AdapterId::Grok,
                        command.model.as_deref(),
                        command.reasoning_effort.as_deref(),
                    )
                    .is_some()
                {
                    if let Some(evidence) =
                        run.grok_acp_parent_evidence.as_ref().filter(|evidence| {
                            evidence.protocol == "grok_acp_stdio"
                                && evidence.resolution_status == "complete"
                                && !evidence.permission_escalation_refused
                                && evidence.requested_model == command.model
                                && evidence.requested_effort == command.reasoning_effort
                        })
                    {
                        if matches!(
                            &evidence.client_resolved_effort,
                            crate::runtime_adapter::grok::GrokAcpParentResolvedField::Known(effort)
                                if Some(effort.as_str()) == command.reasoning_effort.as_deref()
                        ) {
                            identity.effort_basis = Some(IdentityBasis::Requested);
                        }
                    }
                }
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
            SupervisorRuntime::Cursor => {
                if run
                    .cursor_managed_parent_evidence
                    .as_ref()
                    .is_some_and(|evidence| {
                        evidence.peer_verified
                            && evidence.admitted_attempts > 0
                            && evidence.admitted_attempts == evidence.completed_attempts
                            && evidence.client_selected_model == command.model
                            && evidence.client_selected_effort == command.reasoning_effort
                    })
                {
                    identity.model_basis = command.model.as_ref().map(|_| IdentityBasis::Requested);
                    identity.effort_basis = command
                        .reasoning_effort
                        .as_ref()
                        .map(|_| IdentityBasis::Requested);
                }
            }
            SupervisorRuntime::Fake => {}
        }
        if identity.model.is_some() {
            identity.model_basis = Some(IdentityBasis::ProviderReported);
            if identity.effort.is_some() {
                identity.effort_basis = Some(IdentityBasis::ProviderReported);
            } else if runtime != SupervisorRuntime::GeminiCli {
                identity.effort_basis = command
                    .reasoning_effort
                    .as_ref()
                    .map(|_| IdentityBasis::Requested);
            }
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
    let model = evidence
        .usage_model()
        .and(evidence.observed_model.known())
        .map(str::to_owned);
    let effort = evidence.observed_effort.known().map(str::to_owned);
    (model, effort)
}

// Older Codex summaries called rollout/thread settings "observed". Without
// explicit provenance, retain only the matching launch request, never a served claim.
fn legacy_codex_identity(evidence: CodexParentEvidence) -> Result<RuntimeIdentityObservation> {
    let mut identity = RuntimeIdentityObservation {
        requested_model: evidence.requested_model.clone(),
        requested_effort: evidence.requested_effort.clone(),
        model: None,
        effort: None,
        model_basis: None,
        effort_basis: None,
    };
    if evidence.resolution_status != "complete"
        || evidence.thread_id.as_ref().is_none_or(|id| id.is_empty())
        || evidence.model_mismatch
        || evidence.server_rerouted_model.is_some()
    {
        return Ok(identity);
    }
    let models = [
        evidence.rollout_model.known(),
        evidence.observed_model.known(),
    ];
    if models
        .into_iter()
        .flatten()
        .any(|model| Some(model) != evidence.requested_model.as_deref())
    {
        bail!("legacy Codex model settings contradict the launch request");
    }
    if models.into_iter().any(|model| model.is_some()) {
        identity.model_basis = evidence
            .requested_model
            .as_deref()
            .filter(|model| !model.trim().is_empty())
            .map(|_| IdentityBasis::Requested);
    }
    if [
        evidence.rollout_effort.known(),
        evidence.observed_effort.known(),
    ]
    .into_iter()
    .flatten()
    .any(|effort| Some(effort) != evidence.requested_effort.as_deref())
    {
        bail!("legacy Codex effort settings contradict the launch request");
    }
    identity.effort_basis =
        crate::runtime_adapter::effort_matches_request(evidence.requested_effort.as_deref(), None)
            .then_some(IdentityBasis::Requested);
    Ok(identity)
}

/// All retained dispatches for this role must bind the same requested selection
/// and agree on each observed field. A good attempt cannot hide an unknown retry.
pub(crate) fn observed_role_identity(
    reader: &ArtifactRunReader,
    role: AgentRole,
    runtime: SupervisorRuntime,
    requested_model: Option<&str>,
    requested_effort: Option<&str>,
) -> Result<RuntimeIdentityObservation> {
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
        let mut identity = if let Some(value) = summary.get("runtime_identity") {
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
                identities.push(None);
                continue;
            };
            legacy_codex_identity(evidence)?
        } else {
            identities.push(None);
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
        if runtime == SupervisorRuntime::Codex
            && identity.model_basis.is_none()
            && identity.effort_basis.is_none()
            && identity.model.is_some()
        {
            // Legacy generic summaries also lacked provenance. The comparisons
            // above reject contradictions before clearing their client settings.
            identity.model_basis = identity
                .requested_model
                .as_ref()
                .filter(|model| !model.trim().is_empty())
                .map(|_| IdentityBasis::Requested);
            identity.effort_basis = crate::runtime_adapter::effort_matches_request(
                identity.requested_effort.as_deref(),
                None,
            )
            .then_some(IdentityBasis::Requested);
        } else if matches!(
            runtime,
            SupervisorRuntime::Grok | SupervisorRuntime::ClaudeCode | SupervisorRuntime::GeminiCli
        ) && identity.model_basis.is_none()
            && identity.effort_basis.is_none()
            && identity.model.is_some()
        {
            // These older model-only captures already required original native
            // model custody. Their pins never reported effort.
            identity.model_basis = Some(IdentityBasis::ProviderReported);
            if runtime != SupervisorRuntime::GeminiCli {
                identity.effort_basis = crate::runtime_adapter::effort_matches_request(
                    identity.requested_effort.as_deref(),
                    None,
                )
                .then_some(IdentityBasis::Requested);
            }
        }
        if identity.model_basis != Some(IdentityBasis::ProviderReported) {
            identity.model = None;
        }
        if identity.effort_basis != Some(IdentityBasis::ProviderReported) {
            identity.effort = None;
        }
        if receipt.target_launch_attempted {
            identities.push(Some(identity));
        } else {
            identities.push(None);
        }
    }
    fn unanimous<T: Clone + PartialEq>(values: impl Iterator<Item = Option<T>>) -> Option<T> {
        let values = values.collect::<Option<Vec<_>>>()?;
        let first = values.first()?;
        values
            .iter()
            .all(|value| value == first)
            .then(|| first.clone())
    }
    fn aggregate_basis(
        values: impl Iterator<Item = Option<IdentityBasis>>,
    ) -> Option<IdentityBasis> {
        let values = values.collect::<Option<Vec<_>>>()?;
        if values.is_empty() {
            return None;
        }
        Some(if values.contains(&IdentityBasis::Requested) {
            IdentityBasis::Requested
        } else {
            IdentityBasis::ProviderReported
        })
    }
    Ok(RuntimeIdentityObservation {
        requested_model: requested_model.map(str::to_owned),
        requested_effort: requested_effort.map(str::to_owned),
        model: unanimous(
            identities
                .iter()
                .map(|identity| identity.as_ref().and_then(|i| i.model.clone())),
        ),
        effort: unanimous(
            identities
                .iter()
                .map(|identity| identity.as_ref().and_then(|i| i.effort.clone())),
        ),
        model_basis: aggregate_basis(
            identities
                .iter()
                .map(|identity| identity.as_ref().and_then(|i| i.model_basis)),
        ),
        effort_basis: aggregate_basis(
            identities
                .iter()
                .map(|identity| identity.as_ref().and_then(|i| i.effort_basis)),
        ),
    })
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
    fn codex_client_settings_record_requested_basis_without_provider_observations() {
        let command = command();
        let mut run = deterministic_fake_run(&command, Vec::new());
        run.codex_parent_evidence = Some(serde_json::from_value(json!({
            "codex_version":"0.162.0", "thread_id":"thread",
            "requested_model":"gpt-6.1-sol", "requested_effort":"xhigh",
            "rollout_model":{"known":"gpt-6.1-sol"}, "rollout_effort":{"known":"xhigh"},
            "observed_model":"unknown", "observed_effort":"unknown",
            "server_rerouted_model":null, "model_mismatch":false,
            "turn_usage":{"status":"known","input_tokens":10,"output_tokens":4,"cached_input_tokens":0,"reasoning_output_tokens":1},
            "resolution_status":"complete"
        })).unwrap());
        run.retain_app_server_parent_evidence_for_test();
        let identity =
            RuntimeIdentityObservation::capture(&run, &command, SupervisorRuntime::Codex);
        assert_eq!(identity.model_basis, Some(IdentityBasis::Requested));
        assert_eq!(identity.effort_basis, Some(IdentityBasis::Requested));
        assert!(identity.model.is_none() && identity.effort.is_none());
    }

    #[test]
    fn grok_acp_requested_effort_requires_original_launch_output_and_exact_acknowledgement() {
        let mut config =
            serde_json::to_value(crate::runtime_adapter::RuntimeAdapterConfig::defaults(
                crate::runtime_adapter::RuntimeId::Grok,
            ))
            .unwrap();
        config["grok_interaction_protocol"] = json!("acp_stdio");
        let command = command()
            .with_runtime_adapter(
                crate::runtime_adapter::RuntimeId::Grok,
                serde_json::from_value(config).unwrap(),
            )
            .with_model_selection(Some("grok-4.6".into()), Some("low".into()));
        let mut run = deterministic_fake_run(&command, Vec::new());
        run.stdout.target_launch_attempted = true;
        run.output_last_message = Some(b"native structured output".to_vec());
        run.grok_acp_parent_evidence = Some(serde_json::from_value(json!({
            "protocol":"grok_acp_stdio", "session_id":"session",
            "requested_model":"grok-4.6", "requested_effort":"low",
            "client_resolved_model":{"known":"grok-4.6"}, "client_resolved_effort":{"known":"low"},
            "resolution_status":"complete", "terminal_usage":null,
            "native_cost_equivalent_microunits":{"status":"unknown","reason":"not measured"},
            "permission_escalation_refused":false
        })).unwrap());
        let identity = RuntimeIdentityObservation::capture(&run, &command, SupervisorRuntime::Grok);
        assert_eq!(identity.effort_basis, Some(IdentityBasis::Requested));
        assert!(identity.model.is_none() && identity.effort.is_none());
        let changed = command
            .clone()
            .with_model_selection(Some("grok-4.6".into()), Some("xhigh".into()));
        assert!(
            RuntimeIdentityObservation::capture(&run, &changed, SupervisorRuntime::Grok)
                .effort_basis
                .is_none()
        );
        let restored: ExternalAgentRun =
            serde_json::from_slice(&serde_json::to_vec(&run).unwrap()).unwrap();
        assert!(
            RuntimeIdentityObservation::capture(&restored, &command, SupervisorRuntime::Grok)
                .effort_basis
                .is_none()
        );
        run.grok_acp_parent_evidence
            .as_mut()
            .unwrap()
            .client_resolved_effort =
            crate::runtime_adapter::grok::GrokAcpParentResolvedField::Known("xhigh".into());
        assert!(
            RuntimeIdentityObservation::capture(&run, &command, SupervisorRuntime::Grok)
                .effort_basis
                .is_none()
        );
    }

    #[test]
    fn cursor_records_requested_basis_without_inventing_provider_observations() {
        let command = command();
        let mut run = deterministic_fake_run(&command, Vec::new());
        run.cursor_managed_parent_evidence =
            Some(crate::runtime_adapter::CursorManagedParentEvidence {
                peer_verified: true,
                admitted_attempts: 1,
                completed_attempts: 1,
                client_selected_model: command.model.clone(),
                client_selected_effort: command.reasoning_effort.clone(),
                ..Default::default()
            });
        let identity =
            RuntimeIdentityObservation::capture(&run, &command, SupervisorRuntime::Cursor);
        assert_eq!(identity.model_basis, Some(IdentityBasis::Requested));
        assert_eq!(identity.effort_basis, Some(IdentityBasis::Requested));
        assert!(identity.model.is_none() && identity.effort.is_none());
        assert_eq!(
            serde_json::to_value(identity).unwrap()["effort_basis"],
            "requested"
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
        assert_eq!(identity.effort_basis, Some(IdentityBasis::Requested));
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
