//! Operator-bound validation authority carried by the parent, not by worker output.
use super::*;
use crate::merge::{
    held_out::CommandObservation, held_out::CommandObservationStatus, MergeApplyReviewIntent,
    MergeForceOptions, MergePreviewOptions,
};
use std::time::Instant;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeldOutRunBinding {
    pub manifest_sha256: String,
    pub profile_sha256: String,
    pub profile_id: String,
    pub repetition: u32,
    pub experiment_run_id: String,
    pub supervisor_run_id: String,
    pub assignment_id: String,
    pub baseline_head: String,
    pub baseline_tree: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeldOutCommandEvidence {
    pub id: String,
    pub argv: Vec<String>,
    pub command_sha256: String,
    pub observation: CommandObservation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeldOutCandidateEvidence {
    pub version: u32,
    pub run: HeldOutRunBinding,
    pub candidate: Option<CandidateValidationBinding>,
    pub candidate_revalidated: bool,
    pub commands: Vec<HeldOutCommandEvidence>,
}

impl HeldOutCandidateEvidence {
    pub fn passed(&self) -> bool {
        self.candidate_revalidated
            && self.candidate.is_some()
            && !self.commands.is_empty()
            && self
                .commands
                .iter()
                .all(|command| command.observation.status == CommandObservationStatus::Passed)
    }
}

#[derive(Debug)]
struct ValidationState {
    dispatches: u32,
    validation_started: bool,
    evidence: Option<HeldOutCandidateEvidence>,
}

#[derive(Clone)]
pub(crate) struct ParentValidationAuthority {
    pub(crate) binding: HeldOutRunBinding,
    commands: Vec<crate::evaluation::HeldOutValidation>,
    deadline: Instant,
    max_dispatches: u32,
    state: Arc<Mutex<ValidationState>>,
    writer: Arc<Mutex<ArtifactRunWriter>>,
}

impl std::fmt::Debug for ParentValidationAuthority {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ParentValidationAuthority")
            .field("binding", &self.binding)
            .finish_non_exhaustive()
    }
}

impl PartialEq for ParentValidationAuthority {
    fn eq(&self, other: &Self) -> bool {
        self.binding == other.binding
            && self.commands == other.commands
            && self.deadline == other.deadline
            && self.max_dispatches == other.max_dispatches
            && Arc::ptr_eq(&self.state, &other.state)
            && Arc::ptr_eq(&self.writer, &other.writer)
    }
}
impl Eq for ParentValidationAuthority {}

impl ParentValidationAuthority {
    pub(crate) fn new(
        binding: HeldOutRunBinding,
        commands: Vec<crate::evaluation::HeldOutValidation>,
        deadline: Instant,
        max_dispatches: u32,
        writer: Arc<Mutex<ArtifactRunWriter>>,
    ) -> Self {
        Self {
            binding,
            commands,
            deadline,
            max_dispatches,
            writer,
            state: Arc::new(Mutex::new(ValidationState {
                dispatches: 0,
                validation_started: false,
                evidence: None,
            })),
        }
    }

    /// Includes every MACO child/auditor dispatch and every held-out command;
    /// local Git preparation is part of the same elapsed-time budget.
    pub(crate) fn admit(&self, node: &str, cancellation: &ProcessCancellation) -> Result<Duration> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow!("held-out admission lock poisoned"))?;
        let remaining = self.deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() || cancellation.is_cancelled() {
            bail!("experiment deadline or cancellation prevents dispatch");
        }
        if state.dispatches >= self.max_dispatches {
            bail!("experiment max_dispatches exhausted");
        }
        state.dispatches += 1;
        self.writer
            .lock()
            .map_err(|_| anyhow!("experiment artifact lock poisoned"))?
            .append_json_line(
                "held-out/dispatches.jsonl",
                &json!({
                    "run": self.binding, "dispatch": state.dispatches, "node": node,
                    "state": "started_or_unknown", "replay_permitted": false,
                }),
                ArtifactFileDisposition::PrivateEvidence,
            )?;
        let remaining = self.deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() || cancellation.is_cancelled() {
            bail!("experiment deadline or cancellation observed after durable admission");
        }
        Ok(remaining)
    }

    pub(crate) fn evidence(&self) -> Result<HeldOutCandidateEvidence> {
        let state = self
            .state
            .lock()
            .map_err(|_| anyhow!("held-out state lock poisoned"))?;
        state
            .evidence
            .clone()
            .map(Ok)
            .unwrap_or_else(|| self.unknown(None, "candidate validation was not reached"))
    }

    pub(crate) fn dispatches(&self) -> Result<u32> {
        Ok(self
            .state
            .lock()
            .map_err(|_| anyhow!("held-out state lock poisoned"))?
            .dispatches)
    }

    fn unknown(
        &self,
        candidate: Option<CandidateValidationBinding>,
        reason: &str,
    ) -> Result<HeldOutCandidateEvidence> {
        Ok(HeldOutCandidateEvidence {
            version: 1,
            run: self.binding.clone(),
            candidate,
            candidate_revalidated: false,
            commands: self
                .commands
                .iter()
                .map(|command| {
                    Ok(HeldOutCommandEvidence {
                        id: command.id.clone(),
                        argv: command.command.clone(),
                        command_sha256: crate::artifacts::state_auth::sha256_hex(
                            &serde_json::to_vec(command)
                                .context("serialize parent held-out command binding")?,
                        ),
                        observation: CommandObservation::unknown(reason),
                    })
                })
                .collect::<Result<Vec<_>>>()?,
        })
    }

    fn retain(&self, evidence: &HeldOutCandidateEvidence) -> Result<()> {
        self.writer
            .lock()
            .map_err(|_| anyhow!("experiment artifact lock poisoned"))?
            .append_json_line(
                "held-out/observations.jsonl",
                evidence,
                ArtifactFileDisposition::PrivateEvidence,
            )?;
        self.state
            .lock()
            .map_err(|_| anyhow!("held-out state lock poisoned"))?
            .evidence = Some(evidence.clone());
        Ok(())
    }

    fn begin_validation(&self, supervisor_run_id: &str, assignment_id: &str) -> Result<()> {
        if self.binding.supervisor_run_id != supervisor_run_id
            || self.binding.assignment_id != assignment_id
        {
            bail!("held-out authority belongs to another run or assignment");
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow!("held-out state lock poisoned"))?;
        if state.validation_started {
            bail!("held-out command replay is forbidden");
        }
        state.validation_started = true;
        Ok(())
    }

    pub(super) fn validate_candidate(
        &self,
        context: &AssignmentExecutionContext<'_, '_>,
        preflight: &AssignmentExecutionPreflight<'_>,
        candidate: Option<&SupervisorCandidateInspection>,
    ) -> Result<HeldOutCandidateEvidence> {
        self.begin_validation(context.options.run_id.as_str(), &preflight.assignment.id)?;
        let mut evidence = self.unknown(
            candidate.map(|candidate| candidate.binding.clone()),
            "validation not dispatched",
        )?;
        // Commit unknown first. A crash can never upgrade an unfinished command to passed.
        self.retain(&evidence)?;
        let Some(candidate) = candidate else {
            return Ok(evidence);
        };
        let lease = preflight
            .worktree_write_lease
            .as_ref()
            .context("held-out candidate has no write lease")?;
        let preview = crate::merge::preview_merge_apply_with_evidence_and_write_lease(
            MergePreviewOptions {
                collect: MergeCollectOptions {
                    repo: context.repo.into(),
                    agent_id: preflight.assignment.id.clone(),
                    claimed_paths: preflight.assignment.assigned_paths.clone(),
                    include_full_diff: true,
                    diff_summary_char_limit: 1,
                    validations: Vec::new(),
                },
                forces: MergeForceOptions::default(),
                require_validation: false,
                review_intent: MergeApplyReviewIntent::default(),
            },
            ValidationEvidenceBundle::default(),
            lease,
        )?;
        if preview.candidate.validation_binding != candidate.binding
            || candidate.binding.primary_head.as_deref() != Some(&self.binding.baseline_head)
        {
            bail!("held-out candidate differs from the parent-captured baseline or diff");
        }
        for index in 0..evidence.commands.len() {
            match self.admit(&format!("held-out:{}", index), &context.cancellation) {
                Ok(_) => {
                    evidence.commands[index].observation = crate::merge::held_out::run(
                        &preview,
                        &evidence.commands[index].argv,
                        self.deadline,
                        &context.cancellation,
                    );
                }
                Err(_) => {
                    evidence.commands[index].observation = CommandObservation::unknown("experiment dispatch budget, deadline, cancellation or durable admission unavailable");
                }
            }
            self.retain(&evidence)?;
        }
        let after = inspect_assignment_candidate(context, preflight)?;
        if after.binding != candidate.binding {
            for command in &mut evidence.commands {
                command.observation.status = CommandObservationStatus::Failed;
                command.observation.message =
                    Some("parent candidate changed during validation".into());
            }
        }
        evidence.candidate_revalidated = after.binding == candidate.binding
            && Instant::now() < self.deadline
            && !context.cancellation.is_cancelled();
        self.retain(&evidence)?;
        Ok(evidence)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn held_out_parent_review_rejects_a_verdict_reused_after_any_authority_change() -> Result<()> {
        use crate::review::{
            aggregate_review_lenses_against_requests, build_bounded_review_lens_request,
            BoundedReviewLensRequestSources, ReviewCoverageRequirement, ReviewLensCoverage,
            ReviewLensEvidenceKind, ReviewLensVerdict, ReviewLensVerdictStatus,
        };
        let assignment: OrchestratorAssignment = serde_json::from_value(json!({
            "id":"child-a", "phase":"execution", "assigned_paths":["README.md"]
        }))?;
        let child: OrchestratorReviewReport = serde_json::from_value(json!({
            "id":"child-a", "role":"child_orchestrator", "status":"succeeded", "accepted":true, "rejected":false
        }))?;
        let evidence: HeldOutCandidateEvidence = serde_json::from_value(json!({
            "version":1, "run":{
                "manifest_sha256":"a".repeat(64), "profile_sha256":"b".repeat(64), "profile_id":"profile", "repetition":0,
                "experiment_run_id":"experiment", "supervisor_run_id":"supervisor", "assignment_id":"child-a",
                "baseline_head":"c".repeat(40), "baseline_tree":"d".repeat(40)
            },
            "candidate": {"version":1, "agent_id":"child-a", "primary_head":"c".repeat(40),
                "agent_head":"e".repeat(40), "merge_base":"c".repeat(40), "diff_oid":"f".repeat(40)},
            "candidate_revalidated":true,
            "commands":[{"id":"check", "argv":["true"], "command_sha256":"1".repeat(64),
                "observation":{"status":"passed", "exit_code":0, "timed_out":false, "duration_ms":1, "message":null}}]
        }))?;
        let candidate = SupervisorCandidateInspection {
            binding: evidence.candidate.clone().unwrap(),
            changed_paths: vec!["README.md".into()],
        };
        let lenses = default_supervisor_review_lenses();
        let request =
            |evidence: &HeldOutCandidateEvidence| -> Result<crate::review::ReviewLensRequest> {
                let bindings = assignment_execution::supervisor_review_lens_binding_material(
                    &assignment,
                    &child,
                    Some(&candidate),
                    Some(evidence),
                )?;
                build_bounded_review_lens_request(
                    &lenses[0],
                    BoundedReviewLensRequestSources {
                        child_transcript: "retained fixture transcript",
                        authoritative_transcript_path: Path::new("reports/child-transcript.txt"),
                        diff: "fixture candidate diff",
                        output_report: "{}",
                        bindings: &bindings,
                    },
                )
            };
        let original = request(&evidence)?;
        let verdict = ReviewLensVerdict::for_lens(
            &lenses[0],
            original.request_binding.clone(),
            ReviewLensVerdictStatus::Accept,
            ReviewLensCoverage::default(),
            vec![(
                ReviewLensEvidenceKind::ModelReview,
                "synthetic review fixture".into(),
            )],
        )?;
        assert_eq!(
            aggregate_review_lenses_against_requests(
                &lenses,
                std::slice::from_ref(&original),
                ReviewAggregationPolicy::AllMustAccept,
                ReviewCoverageRequirement::default(),
                vec![verdict.clone()]
            )?
            .decision,
            crate::review::ReviewAggregationDecision::Accept
        );
        for change in 0..10 {
            let mut changed = evidence.clone();
            match change {
                0 => changed.run.manifest_sha256 = "2".repeat(64),
                1 => changed.run.profile_sha256 = "3".repeat(64),
                2 => changed.run.repetition = 1,
                3 => changed.run.supervisor_run_id = "another-run".into(),
                4 => changed.run.baseline_head = "4".repeat(40),
                5 => changed.candidate.as_mut().unwrap().diff_oid = "5".repeat(40),
                6 => changed.commands[0].argv = vec!["false".into()],
                7 => changed.commands[0].observation.status = CommandObservationStatus::Failed,
                8 => changed.candidate_revalidated = false,
                _ => changed.run.experiment_run_id = "another-experiment".into(),
            }
            let updated = request(&changed)?;
            assert_ne!(
                original.request_binding, updated.request_binding,
                "unbound authority dimension {change}"
            );
            assert_ne!(
                aggregate_review_lenses_against_requests(
                    &lenses,
                    &[updated],
                    ReviewAggregationPolicy::AllMustAccept,
                    ReviewCoverageRequirement::default(),
                    vec![verdict.clone()]
                )?
                .decision,
                crate::review::ReviewAggregationDecision::Accept
            );
        }
        Ok(())
    }

    #[test]
    fn held_out_authority_refuses_replay_foreign_identity_and_exhausted_admission() -> Result<()> {
        let temp = tempfile::TempDir::new()?;
        git2::Repository::init(temp.path())?;
        let writer = Arc::new(Mutex::new(ArtifactRunWriter::reserve(
            temp.path(),
            RunArtifactFamily::Supervise,
            RunId::new("held-out-authority")?,
            "held-out-test",
        )?));
        let binding = HeldOutRunBinding {
            manifest_sha256: "a".repeat(64),
            profile_sha256: "b".repeat(64),
            profile_id: "profile".into(),
            repetition: 0,
            experiment_run_id: "experiment".into(),
            supervisor_run_id: "supervisor".into(),
            assignment_id: "child-a".into(),
            baseline_head: "c".repeat(40),
            baseline_tree: "d".repeat(40),
        };
        let deadline = Instant::now() + Duration::from_secs(120); // Existing fixture manifest bound.
        let authority = ParentValidationAuthority::new(
            binding.clone(),
            vec![crate::evaluation::HeldOutValidation {
                id: "validation".into(),
                command: vec!["true".into()],
            }],
            deadline,
            1,
            Arc::clone(&writer),
        );
        assert!(authority
            .begin_validation("foreign-run", "child-a")
            .is_err());
        assert!(authority
            .begin_validation("supervisor", "foreign-child")
            .is_err());
        authority.begin_validation("supervisor", "child-a")?;
        assert!(authority
            .clone()
            .begin_validation("supervisor", "child-a")
            .is_err());
        let cancellation = ProcessCancellation::new();
        authority.admit("child-a", &cancellation)?;
        assert!(authority.admit("held-out:0", &cancellation).is_err());
        assert_eq!(authority.dispatches()?, 1);
        let expired =
            ParentValidationAuthority::new(binding, Vec::new(), Instant::now(), 1, writer);
        assert!(expired.admit("child-a", &cancellation).is_err());
        assert_eq!(expired.dispatches()?, 0);
        assert!(!authority.evidence()?.passed());
        Ok(())
    }
}
