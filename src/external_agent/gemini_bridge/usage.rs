//! Complete response accounting from the source-bound private bridge only.
use super::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct UsageBinding {
    cwd: PathBuf,
    prompt: PathBuf,
    output: PathBuf,
    model: Option<String>,
    effort: Option<String>,
    selected: Option<FrozenGeminiSelectedBinding>,
}

impl UsageBinding {
    pub(super) fn bind(command: &ExternalAgentCommand) -> Self {
        Self {
            cwd: command.cwd.clone(),
            prompt: command.prompt.clone(),
            output: command.output_last_message.clone(),
            model: command.model.clone(),
            effort: command.reasoning_effort.clone(),
            selected: command.gemini_run_account_binding.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct InvocationUsage {
    model: String,
    // Preserve every native bucket; cached input is already included in prompt.
    counters: [u64; 6],
}

impl InvocationUsage {
    fn usage(&self) -> Option<Usage> {
        let input_tokens = usize::try_from(self.counters[0].checked_add(self.counters[5])?).ok()?;
        let output_tokens =
            usize::try_from(self.counters[1].checked_add(self.counters[4])?).ok()?;
        let total_tokens = usize::try_from(self.counters[2]).ok()?;
        // UsageMetadata defines total as prompt + tool-use prompt + candidates
        // + thoughts. Cached input is a prompt subset, not another charge.
        if input_tokens.checked_add(output_tokens)? != total_tokens {
            return None;
        }
        Some(Usage {
            input_tokens,
            output_tokens,
            total_tokens,
        })
    }
}

pub(super) fn complete_invocation(attempts: &BTreeMap<u64, WireEvent>) -> Option<InvocationUsage> {
    let mut invocation: Option<InvocationUsage> = None;
    for attempt in attempts.values() {
        if attempt.request_class != "generation" {
            // Startup and authentication traffic are not generation tokens.
            // An unfinished physical request cannot establish run completeness.
            if attempt.terminal.as_deref() != Some("eof") {
                return None;
            }
            continue;
        }
        if !attempt.released
            || attempt.terminal.as_deref() != Some("eof")
            || attempt.frames == 0
            || !attempt.usage_snapshot_complete
        {
            return None;
        }
        let usage = attempt.usage.as_ref()?;
        usage.validate(None).ok()?;
        let counters: [u64; 6] = usage
            .counters()
            .into_iter()
            .collect::<Option<Vec<_>>>()?
            .try_into()
            .ok()?;
        let model = attempt.observed_model_version.as_ref()?;
        // Refuse inconsistent individual attempts even if their discrepancies
        // could cancel in an aggregate.
        let current = InvocationUsage {
            model: model.clone(),
            counters,
        };
        current.usage()?;
        match &mut invocation {
            Some(total) => {
                if &total.model != model {
                    return None;
                }
                for (total, count) in total.counters.iter_mut().zip(counters) {
                    *total = total.checked_add(count)?;
                }
            }
            None => {
                invocation = Some(current);
            }
        }
    }
    let invocation = invocation?;
    invocation.usage()?;
    Some(invocation)
}

impl HeldEvidence {
    pub(crate) fn complete_usage(&self) -> Option<Usage> {
        self.usage_binding.as_ref()?;
        self.invocation_usage.as_ref()?.usage()
    }

    pub(crate) fn usage_for_command(&self, command: &ExternalAgentCommand) -> Option<Usage> {
        if !command.uses_gemini_bridge()
            || self.usage_binding.as_ref()? != &UsageBinding::bind(command)
        {
            return None;
        }
        self.complete_usage()
    }

    pub(crate) fn actual_model(&self) -> Option<&str> {
        self.complete_usage()?;
        Some(&self.invocation_usage.as_ref()?.model)
    }

    pub(crate) fn identity_matches_launch(&self) -> bool {
        let Some(binding) = &self.usage_binding else {
            return false;
        };
        // 0.41.2 projects response.modelVersion and usageMetadata, but exposes
        // no served thinking/effort field. Request configuration is not proof.
        binding.effort.is_none()
            && binding.model.as_deref().is_some()
            && binding.model.as_deref() == self.actual_model()
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    fn command() -> ExternalAgentCommand {
        ExternalAgentCommand::codex(
            Descriptor::GEMINI,
            "candidate",
            "prompt",
            "log",
            "result",
            Duration::from_secs(1),
        )
        .with_runtime_adapter(
            RuntimeId::GeminiCli,
            RuntimeAdapterConfig::defaults(RuntimeId::GeminiCli),
        )
        .with_model_selection(Some("gemini-2.5-pro".into()), None)
    }

    fn protocol(command: &ExternalAgentCommand) -> Protocol {
        let mut p = Protocol::new("a".repeat(64), "b".repeat(64), None);
        p.hello = true;
        p.evidence.ready = true;
        p.evidence.usage_binding = Some(UsageBinding::bind(command));
        p.release_authority = ReleaseAuthority::DeterministicTransport;
        p
    }

    fn event(kind: &str, id: u64) -> WireEvent {
        serde_json::from_value(serde_json::json!({
            "kind": kind, "callId": id, "attemptId": id, "mode": "stream", "requestClass": "generation",
            "released": matches!(kind, "observation" | "terminal"),
            "terminal": (kind == "terminal").then_some("eof"), "terminalAck": (kind == "terminal").then_some("pending"),
            "frames": 0, "wireBytes": 0, "usage": null, "usageSnapshotComplete": false,
            "observedModelVersion": null, "usageLowerBound": null, "usageCoverage": "observed_lower_bound_only",
            "identityAuthority": "unverified_response_field", "actualEffort": null, "cost": null,
            "qualified": false, "quiescence": "unproven",
            "envelopeSha256": (kind == "observation").then(|| "c".repeat(64))
        })).unwrap()
    }

    fn observation(id: u64) -> WireEvent {
        let mut e = event("observation", id);
        e.frames = 1;
        e.wire_bytes = 512;
        e.usage = Some(WireUsage {
            prompt_token_count: Some(10),
            candidates_token_count: Some(5),
            total_token_count: Some(17),
            cached_content_token_count: Some(4),
            thoughts_token_count: Some(2),
            tool_use_prompt_token_count: Some(0),
        });
        e.usage_snapshot_complete = true;
        e.usage_lower_bound = Some(17);
        e.observed_model_version = Some("gemini-2.5-pro".into());
        e
    }

    fn send(p: &mut Protocol, e: WireEvent) -> Result<()> {
        // Pass the same strict private message decoder as the online receiver.
        // WireEvent is intentionally not serializable. Build the exact bridge
        // whitelist rather than adding a restorable authority format.
        let value = serde_json::json!({
            "kind": e.kind, "callId": e.call_id, "attemptId": e.attempt_id, "mode": e.mode,
            "requestClass": e.request_class, "released": e.released, "terminal": e.terminal,
            "terminalAck": e.terminal_ack, "frames": e.frames, "wireBytes": e.wire_bytes,
            "usage": e.usage.map(|u| serde_json::json!({
                "promptTokenCount": u.prompt_token_count, "candidatesTokenCount": u.candidates_token_count,
                "totalTokenCount": u.total_token_count, "cachedContentTokenCount": u.cached_content_token_count,
                "thoughtsTokenCount": u.thoughts_token_count, "toolUsePromptTokenCount": u.tool_use_prompt_token_count,
            })), "usageSnapshotComplete": e.usage_snapshot_complete, "observedModelVersion": e.observed_model_version,
            "usageLowerBound": e.usage_lower_bound, "usageCoverage": e.usage_coverage,
            "identityAuthority": e.identity_authority, "actualEffort": e.actual_effort, "cost": e.cost,
            "qualified": e.qualified, "quiescence": e.quiescence, "envelopeSha256": e.envelope_sha256,
        });
        p.receive(&serde_json::to_vec(&serde_json::json!({
            "nonce": "a".repeat(64), "sequence": p.sequence + 1,
            "message": { "type": "event", "event": value },
        }))?)
    }

    fn attempt(p: &mut Protocol, id: u64, observation: WireEvent) -> Result<()> {
        send(p, event("admission", id))?;
        send(p, event("release", id))?;
        let mut terminal = observation.clone();
        send(p, observation)?;
        terminal.kind = "terminal".into();
        terminal.terminal = Some("eof".into());
        terminal.terminal_ack = Some("pending".into());
        terminal.envelope_sha256 = None;
        send(p, terminal)
    }

    #[test]
    fn gemini_complete_usage_counts_distinct_attempts_and_invalidates_on_next_admission(
    ) -> Result<()> {
        let command = command();
        let mut p = protocol(&command);
        attempt(&mut p, 1, observation(1))?;
        assert_eq!(
            p.evidence.usage_for_command(&command),
            Some(Usage {
                input_tokens: 10,
                output_tokens: 7,
                total_tokens: 17
            })
        );
        assert_eq!(p.evidence.actual_model(), Some("gemini-2.5-pro"));
        assert!(p.evidence.identity_matches_launch());
        attempt(&mut p, 2, observation(2))?;
        assert_eq!(
            p.evidence.usage_for_command(&command).unwrap().total_tokens,
            34
        );
        send(&mut p, event("admission", 3))?;
        assert!(p.evidence.complete_usage().is_none());
        assert_eq!(p.evidence.tokens, Some(34));
        let mut p = protocol(&command);
        let mut e = observation(1);
        e.usage.as_mut().unwrap().tool_use_prompt_token_count = Some(3);
        e.usage.as_mut().unwrap().total_token_count = Some(20);
        e.usage_lower_bound = Some(20);
        attempt(&mut p, 1, e)?;
        assert_eq!(
            p.evidence.usage_for_command(&command),
            Some(Usage {
                input_tokens: 13,
                output_tokens: 7,
                total_tokens: 20,
            })
        );
        Ok(())
    }

    #[test]
    fn gemini_missing_and_partial_usage_never_become_complete_or_zero() -> Result<()> {
        let command = command();
        for missing in 0..7 {
            let mut p = protocol(&command);
            let mut e = observation(1);
            e.usage_snapshot_complete = false;
            if missing == 6 {
                e.usage = None;
                e.usage_lower_bound = None;
            } else {
                let u = e.usage.as_mut().unwrap();
                match missing {
                    0 => u.prompt_token_count = None,
                    1 => u.candidates_token_count = None,
                    2 => {
                        u.total_token_count = None;
                        e.usage_lower_bound = None;
                    }
                    3 => u.cached_content_token_count = None,
                    4 => u.thoughts_token_count = None,
                    5 => u.tool_use_prompt_token_count = None,
                    _ => unreachable!(),
                }
                if missing == 0 {
                    u.cached_content_token_count = None;
                }
            }
            attempt(&mut p, 1, e)?;
            assert!(p.evidence.usage_for_command(&command).is_none());
            assert!(!p.evidence.identity_matches_launch());
            assert_eq!(
                p.evidence.tokens,
                if missing == 2 || missing == 6 {
                    None
                } else {
                    Some(17)
                }
            );
        }
        let mut p = protocol(&command);
        let mut e = observation(1);
        e.usage.as_mut().unwrap().total_token_count = Some(18);
        e.usage_lower_bound = Some(18);
        attempt(&mut p, 1, e)?;
        assert!(p.evidence.complete_usage().is_none());
        assert_eq!(p.evidence.tokens, Some(18));
        Ok(())
    }

    #[test]
    fn gemini_model_fallback_mismatch_and_unobserved_effort_refuse_identity() -> Result<()> {
        for model in [None, Some("gemini-2.5-flash")] {
            let command = command();
            let mut p = protocol(&command);
            let mut e = observation(1);
            e.observed_model_version = model.map(str::to_owned);
            attempt(&mut p, 1, e)?;
            assert!(!p.evidence.identity_matches_launch());
            assert_eq!(p.evidence.actual_model(), model);
        }
        let mut command = command();
        command.reasoning_effort = Some("high".into());
        let mut p = protocol(&command);
        attempt(&mut p, 1, observation(1))?;
        assert!(!p.evidence.identity_matches_launch());
        command.reasoning_effort = None;
        assert!(p.evidence.usage_for_command(&command).is_none());
        Ok(())
    }

    #[test]
    fn gemini_forged_terminal_and_complete_claim_without_counters_are_rejected() -> Result<()> {
        let command = command();
        let mut p = protocol(&command);
        send(&mut p, event("admission", 1))?;
        send(&mut p, event("release", 1))?;
        let mut forged = observation(1);
        forged.kind = "terminal".into();
        forged.terminal = Some("eof".into());
        forged.terminal_ack = Some("pending".into());
        assert!(send(&mut p, forged).is_err());
        assert!(p.stopped);
        assert!(p.evidence.complete_usage().is_none());
        let mut p = protocol(&command);
        send(&mut p, event("admission", 1))?;
        send(&mut p, event("release", 1))?;
        let mut forged = observation(1);
        forged.usage.as_mut().unwrap().thoughts_token_count = None;
        assert!(send(&mut p, forged).is_err());
        assert!(p.evidence.complete_usage().is_none());
        Ok(())
    }
}
