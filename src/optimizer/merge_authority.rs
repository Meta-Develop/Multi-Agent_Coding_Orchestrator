//! Merge authority for an independent reviewer (issue #208).
//!
//! Separation of duties is the invariant: a producer cannot accept its own
//! work. Merging by an independent reviewer is reachable only when every
//! recorded gate passes. The always-false `auto_merge_performed` pin is
//! replaced by these checks.
//!
//! # Caller-trusted inputs
//!
//! This library does not observe CI, simulate merges, or recover lens
//! provenance. The following [`MergeRequest`] fields are caller-trusted.
//! Integration that later wires [`decide_merge`] must derive them from ground
//! truth, not from the requesting agent:
//!
//! - [`MergeRequest::certified`] — recorded CI or certification status
//! - [`MergeRequest::branch_merges_cleanly`] — an actual merge simulation
//! - [`MergeRequest::lenses`] — recorded lens provenance (identity, framing,
//!   information scope, and decision)
//! - [`MergeRequest::checks`] — recorded CI or required-check status
//! - [`MergeRequest::changed_paths`] — the actual reviewable change set
//!
//! Empty or denied evidence fails closed. A caller that cannot attest a field
//! must leave it in the denying state (`certified = false`,
//! `branch_merges_cleanly = false`, empty lenses, or empty checks).

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use super::error::OptimizerError;
use super::ids::TimestampMillis;

/// Stable producer or reviewer identity. A new model or session does not mint
/// a new identity — re-running the same agent is still the same agent.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AgentIdentity {
    pub stable_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SessionId {
    pub id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MergeActor {
    pub agent: AgentIdentity,
    pub session: SessionId,
    pub model_label: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProducerFingerprint {
    pub actor: MergeActor,
    pub commit_authors: Vec<String>,
    pub commit_committers: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndependenceReport {
    pub independent: bool,
    pub producer_agent: String,
    pub reviewer_agent: String,
    pub same_agent: bool,
    pub same_session: bool,
    pub same_model: bool,
    pub author_overlap: Vec<String>,
    pub committer_overlap: Vec<String>,
    pub notes: Vec<String>,
}

pub fn assess_independence(
    producer: &ProducerFingerprint,
    reviewer: &MergeActor,
) -> IndependenceReport {
    let same_agent = producer.actor.agent == reviewer.agent;
    let same_session = producer.actor.session == reviewer.session;
    let same_model = producer.actor.model_label == reviewer.model_label;
    let author_overlap = overlap(&producer.commit_authors, &reviewer.agent.stable_id);
    let committer_overlap = overlap(&producer.commit_committers, &reviewer.agent.stable_id);
    let mut notes = Vec::new();
    if same_agent {
        notes.push("reviewer agent matches the producing agent".to_string());
    }
    if same_session {
        notes.push("reviewer session matches the producing session".to_string());
    }
    if same_model && same_agent {
        notes.push(
            "a different model does not create independence when the agent is the same".to_string(),
        );
    }
    if !author_overlap.is_empty() {
        notes.push("reviewer is a commit author on the branch".to_string());
    }
    if !committer_overlap.is_empty() {
        notes.push("reviewer is a commit committer on the branch".to_string());
    }
    if same_agent && !same_session {
        notes.push("a fresh session for the same producer is not independence".to_string());
    }
    let independent =
        !same_agent && !same_session && author_overlap.is_empty() && committer_overlap.is_empty();
    IndependenceReport {
        independent,
        producer_agent: producer.actor.agent.stable_id.clone(),
        reviewer_agent: reviewer.agent.stable_id.clone(),
        same_agent,
        same_session,
        same_model,
        author_overlap,
        committer_overlap,
        notes,
    }
}

fn overlap(people: &[String], reviewer: &str) -> Vec<String> {
    people
        .iter()
        .filter(|person| person.as_str() == reviewer)
        .cloned()
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LensDecision {
    Accept,
    Reject,
    Uncertain,
    CannotVerify,
    LacksContext,
}

impl LensDecision {
    pub fn blocks_completion(self) -> bool {
        !matches!(self, Self::Accept)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LensVerdict {
    pub lens_id: String,
    pub model_label: String,
    pub framing: String,
    pub information_scope: String,
    pub decision: LensDecision,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LensAgreement {
    pub distinct_lenses: usize,
    pub required_distinct: usize,
    pub unanimous_accept: bool,
    pub blocking_lenses: Vec<String>,
    pub duplicate_collapsed: usize,
}

pub fn aggregate_lenses(lenses: &[LensVerdict]) -> LensAgreement {
    let mut distinct = BTreeSet::new();
    for lens in lenses {
        distinct.insert((
            lens.model_label.as_str(),
            lens.framing.as_str(),
            lens.information_scope.as_str(),
        ));
    }
    let blocking: Vec<String> = lenses
        .iter()
        .filter(|lens| lens.decision.blocks_completion())
        .map(|lens| lens.lens_id.clone())
        .collect();
    LensAgreement {
        distinct_lenses: distinct.len(),
        required_distinct: 2,
        unanimous_accept: blocking.is_empty() && !lenses.is_empty(),
        blocking_lenses: blocking,
        duplicate_collapsed: lenses.len().saturating_sub(distinct.len()),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckStatus {
    Passed,
    Failed,
    Missing,
    Skipped,
    Stale,
    Uncertain,
}

impl CheckStatus {
    pub fn counts_as_failure(self) -> bool {
        !matches!(self, Self::Passed)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationCheck {
    pub name: String,
    pub status: CheckStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompletionMode {
    MergeCommit,
    FastForward,
    Squash,
    Rebase,
}

impl CompletionMode {
    pub fn history_flattening(self) -> bool {
        matches!(self, Self::Squash | Self::Rebase)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NeverAutoMergeClass {
    ReviewOrMergePolicy,
    CiCdDefinition,
    PermissionsOrCredentials,
    ProtectedPath,
}

pub fn never_auto_merge_reason(paths: &[PathBuf]) -> Option<NeverAutoMergeClass> {
    for path in paths {
        if let Some(class) = classify_never_auto_merge(path) {
            return Some(class);
        }
    }
    None
}

fn classify_never_auto_merge(path: &Path) -> Option<NeverAutoMergeClass> {
    let rendered = path.to_string_lossy().replace('\\', "/");
    let lower = rendered.to_ascii_lowercase();
    if is_repository_policy_path(&lower)
        || lower.contains("src/review.rs")
        || lower.contains("src/optimizer/merge_authority.rs")
        || lower.contains("review_aggregation")
        || lower.contains("merge_authority")
    {
        return Some(NeverAutoMergeClass::ReviewOrMergePolicy);
    }
    if lower.contains(".github/")
        || lower.contains("flake.nix")
        || lower.contains("flake.lock")
        || lower.contains("deny.toml")
        || lower.contains(".cargo/audit")
    {
        return Some(NeverAutoMergeClass::CiCdDefinition);
    }
    if lower.contains("credential")
        || lower.contains("secret")
        || lower.contains(".env")
        || lower.contains("id_rsa")
        || lower.contains("permissions")
        || lower.contains("codeowners")
    {
        return Some(NeverAutoMergeClass::PermissionsOrCredentials);
    }
    if lower.contains("protected_path") || lower.contains("src/protected_path.rs") {
        return Some(NeverAutoMergeClass::ProtectedPath);
    }
    None
}

fn is_repository_policy_path(lower: &str) -> bool {
    let trimmed = lower.trim_start_matches("./");
    let file_name = trimmed.rsplit('/').next().unwrap_or(trimmed);
    matches!(file_name, "agents.md" | "claude.md")
        || trimmed == ".agents"
        || trimmed.starts_with(".agents/")
        || trimmed.contains("/.agents/")
}

fn failed_verification_checks(checks: &[VerificationCheck]) -> Vec<String> {
    if checks.is_empty() {
        return vec!["required-verification-checks:Missing".to_string()];
    }
    checks
        .iter()
        .filter(|check| check.status.counts_as_failure())
        .map(|check| format!("{}:{:?}", check.name, check.status))
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MergeRequest {
    pub requested: bool,
    pub producer: ProducerFingerprint,
    pub reviewer: MergeActor,
    /// Caller-trusted lens verdicts. Integration must supply recorded lens
    /// provenance, not a self-report from the requesting agent.
    pub lenses: Vec<LensVerdict>,
    /// Caller-trusted required-check results. Integration must derive these
    /// from recorded CI or gate status. An empty list is missing evidence.
    pub checks: Vec<VerificationCheck>,
    /// Caller-trusted clean-merge flag. Integration must derive this from an
    /// actual merge simulation.
    pub branch_merges_cleanly: bool,
    pub completion_mode: CompletionMode,
    pub changed_paths: Vec<PathBuf>,
    /// Caller-trusted certification flag. Integration must derive this from
    /// recorded CI or certification status.
    pub certified: bool,
    pub decided_at: TimestampMillis,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MergeDecision {
    pub auto_merge_requested: bool,
    pub auto_merge_performed: bool,
    pub independence: IndependenceReport,
    pub lenses: LensAgreement,
    pub failed_checks: Vec<String>,
    pub never_auto_merge: Option<NeverAutoMergeClass>,
    pub blockers: Vec<MergeBlocker>,
    pub explanation: String,
}

/// Machine-readable reasons that deny merge authority.
///
/// Explanations remain useful for humans, but callers must authorize only from
/// this closed blocker set and `auto_merge_performed`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "blocker", content = "details", rename_all = "snake_case")]
pub enum MergeBlocker {
    AutoMergeNotRequested,
    CandidateNotCertified,
    ReviewerNotIndependent,
    InsufficientDecorrelatedLenses {
        required_distinct: usize,
        observed_distinct: usize,
    },
    NoAcceptedReviewLens,
    BlockingReviewLenses {
        lens_ids: Vec<String>,
    },
    RequiredVerificationChecks {
        checks: Vec<String>,
    },
    MergeSimulationFailed,
    HistoryFlatteningCompletionMode {
        mode: CompletionMode,
    },
    NeverAutoMerge {
        class: NeverAutoMergeClass,
    },
}

/// Default-deny merge authority. `auto_merge_performed` is true only when
/// every recorded gate passes for an independent reviewer.
pub fn decide_merge(request: &MergeRequest) -> Result<MergeDecision, OptimizerError> {
    let independence = assess_independence(&request.producer, &request.reviewer);
    let lenses = aggregate_lenses(&request.lenses);
    let never_auto_merge = never_auto_merge_reason(&request.changed_paths);
    let failed_checks = failed_verification_checks(&request.checks);

    let mut blockers = Vec::new();
    let mut blocked = Vec::new();
    if !request.requested {
        blockers.push(MergeBlocker::AutoMergeNotRequested);
        blocked.push("auto-merge was not requested".to_string());
    }
    if !request.certified {
        blockers.push(MergeBlocker::CandidateNotCertified);
        blocked.push("candidate is not certified".to_string());
    }
    if !independence.independent {
        blockers.push(MergeBlocker::ReviewerNotIndependent);
        if independence.notes.is_empty() {
            blocked.push("reviewer is not independent of the producer".to_string());
        } else {
            blocked.extend(independence.notes.iter().cloned());
        }
    }
    if lenses.distinct_lenses < lenses.required_distinct {
        blockers.push(MergeBlocker::InsufficientDecorrelatedLenses {
            required_distinct: lenses.required_distinct,
            observed_distinct: lenses.distinct_lenses,
        });
        blocked.push(format!(
            "need {} decorrelated lenses, found {}",
            lenses.required_distinct, lenses.distinct_lenses
        ));
    }
    if !lenses.unanimous_accept {
        if lenses.blocking_lenses.is_empty() {
            blockers.push(MergeBlocker::NoAcceptedReviewLens);
            blocked.push("no review lens accepted".to_string());
        } else {
            blockers.push(MergeBlocker::BlockingReviewLenses {
                lens_ids: lenses.blocking_lenses.clone(),
            });
            blocked.push(format!(
                "lens rejection/uncertainty blocks completion: {}",
                lenses.blocking_lenses.join(", ")
            ));
        }
    }
    if !failed_checks.is_empty() {
        blockers.push(MergeBlocker::RequiredVerificationChecks {
            checks: failed_checks.clone(),
        });
        blocked.push(format!(
            "required checks missing, skipped, or failed: {}",
            failed_checks.join(", ")
        ));
    }
    if !request.branch_merges_cleanly {
        blockers.push(MergeBlocker::MergeSimulationFailed);
        blocked.push("branch does not merge cleanly".to_string());
    }
    if request.completion_mode.history_flattening() {
        blockers.push(MergeBlocker::HistoryFlatteningCompletionMode {
            mode: request.completion_mode,
        });
        blocked.push("history-flattening completion modes are prohibited".to_string());
    }
    if let Some(class) = never_auto_merge {
        blockers.push(MergeBlocker::NeverAutoMerge { class });
        blocked.push(format!("change is in the never-auto-merge set ({class:?})"));
    }

    let auto_merge_performed = blockers.is_empty();
    let explanation = if auto_merge_performed {
        format!(
            "independent reviewer {} accepted under {} distinct lenses; checks: {}",
            independence.reviewer_agent,
            lenses.distinct_lenses,
            request
                .checks
                .iter()
                .map(|check| check.name.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        )
    } else {
        blocked.join("; ")
    };

    Ok(MergeDecision {
        auto_merge_requested: request.requested,
        auto_merge_performed,
        independence,
        lenses,
        failed_checks,
        never_auto_merge,
        blockers,
        explanation,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn producer() -> ProducerFingerprint {
        ProducerFingerprint {
            actor: MergeActor {
                agent: AgentIdentity {
                    stable_id: "producer-1".to_string(),
                },
                session: SessionId {
                    id: "sess-a".to_string(),
                },
                model_label: "worker-a".to_string(),
            },
            commit_authors: vec!["producer-1".to_string()],
            commit_committers: vec!["producer-1".to_string()],
        }
    }

    fn reviewer(id: &str) -> MergeActor {
        MergeActor {
            agent: AgentIdentity {
                stable_id: id.to_string(),
            },
            session: SessionId {
                id: "sess-review".to_string(),
            },
            model_label: "reviewer-b".to_string(),
        }
    }

    fn two_lenses() -> Vec<LensVerdict> {
        vec![
            LensVerdict {
                lens_id: "diff".to_string(),
                model_label: "reviewer-b".to_string(),
                framing: "adversarial-diff".to_string(),
                information_scope: "diff-only".to_string(),
                decision: LensDecision::Accept,
            },
            LensVerdict {
                lens_id: "tests".to_string(),
                model_label: "reviewer-c".to_string(),
                framing: "tests-as-spec".to_string(),
                information_scope: "tests-only".to_string(),
                decision: LensDecision::Accept,
            },
        ]
    }

    fn passing_checks() -> Vec<VerificationCheck> {
        vec![
            VerificationCheck {
                name: "unit".to_string(),
                status: CheckStatus::Passed,
            },
            VerificationCheck {
                name: "lint".to_string(),
                status: CheckStatus::Passed,
            },
        ]
    }

    fn allowed_request() -> MergeRequest {
        MergeRequest {
            requested: true,
            producer: producer(),
            reviewer: reviewer("reviewer-1"),
            lenses: two_lenses(),
            checks: passing_checks(),
            branch_merges_cleanly: true,
            completion_mode: CompletionMode::MergeCommit,
            changed_paths: vec![PathBuf::from("src/optimizer/evidence_pool.rs")],
            certified: true,
            decided_at: TimestampMillis::from_millis(9),
        }
    }

    #[test]
    fn self_acceptance_is_refused() {
        let mut request = allowed_request();
        request.reviewer = request.producer.actor.clone();
        let decision = decide_merge(&request).expect("decide");
        assert!(request.requested);
        assert!(!decision.auto_merge_performed);
        assert!(!decision.independence.independent);
        assert!(decision.explanation.contains("producing agent"));
    }

    #[test]
    fn new_model_or_session_does_not_create_independence() {
        let mut request = allowed_request();
        request.reviewer = MergeActor {
            agent: request.producer.actor.agent.clone(),
            session: SessionId {
                id: "fresh-session".to_string(),
            },
            model_label: "different-model".to_string(),
        };
        let decision = decide_merge(&request).expect("decide");
        assert!(!decision.auto_merge_performed);
        assert!(decision.independence.same_agent);
        assert!(!decision.independence.same_session);
        assert!(!decision.independence.same_model);
    }

    #[test]
    fn independent_reviewer_with_unanimous_lenses_can_merge() {
        let decision = decide_merge(&allowed_request()).expect("decide");
        assert!(decision.auto_merge_requested);
        assert!(decision.auto_merge_performed);
        assert!(decision.independence.independent);
        assert_eq!(decision.lenses.distinct_lenses, 2);
        assert!(decision.explanation.contains("independent reviewer"));
    }

    #[test]
    fn duplicate_lenses_count_as_one() {
        let mut request = allowed_request();
        request.lenses = vec![
            LensVerdict {
                lens_id: "a".to_string(),
                model_label: "same".to_string(),
                framing: "same".to_string(),
                information_scope: "same".to_string(),
                decision: LensDecision::Accept,
            },
            LensVerdict {
                lens_id: "b".to_string(),
                model_label: "same".to_string(),
                framing: "same".to_string(),
                information_scope: "same".to_string(),
                decision: LensDecision::Accept,
            },
        ];
        let decision = decide_merge(&request).expect("decide");
        assert_eq!(decision.lenses.distinct_lenses, 1);
        assert_eq!(decision.lenses.duplicate_collapsed, 1);
        assert!(!decision.auto_merge_performed);
    }

    #[test]
    fn uncertain_or_unverified_lens_blocks_completion() {
        for decision_kind in [
            LensDecision::Uncertain,
            LensDecision::CannotVerify,
            LensDecision::LacksContext,
            LensDecision::Reject,
        ] {
            let mut request = allowed_request();
            request.lenses[0].decision = decision_kind;
            let decision = decide_merge(&request).expect("decide");
            assert!(
                !decision.auto_merge_performed,
                "{decision_kind:?} must block"
            );
        }
    }

    #[test]
    fn missing_or_skipped_check_counts_as_failure() {
        let mut request = allowed_request();
        request.checks[1].status = CheckStatus::Missing;
        let missing = decide_merge(&request).expect("missing");
        assert!(!missing.auto_merge_performed);
        assert!(missing
            .failed_checks
            .iter()
            .any(|check| check.contains("lint")));

        request.checks[1].status = CheckStatus::Skipped;
        let skipped = decide_merge(&request).expect("skipped");
        assert!(!skipped.auto_merge_performed);
    }

    #[test]
    fn empty_checks_list_fails_closed() {
        let mut request = allowed_request();
        request.checks.clear();
        let decision = decide_merge(&request).expect("decide");
        assert!(!decision.auto_merge_performed);
        assert!(
            decision
                .failed_checks
                .iter()
                .any(|check| check.contains("required-verification-checks")),
            "empty checks must count as a missing required check: {:?}",
            decision.failed_checks
        );
        assert!(decision.explanation.contains("required checks"));
    }

    #[test]
    fn different_agent_same_session_is_not_independent() {
        let mut request = allowed_request();
        request.reviewer.session = request.producer.actor.session.clone();
        let decision = decide_merge(&request).expect("decide");
        assert!(!decision.independence.same_agent);
        assert!(decision.independence.same_session);
        assert!(!decision.independence.independent);
        assert!(!decision.auto_merge_performed);
        assert!(decision.explanation.contains("producing session"));
    }

    #[test]
    fn caller_trusted_certification_inputs_fail_closed_when_denied() {
        let mut request = allowed_request();
        request.certified = false;
        let uncertified = decide_merge(&request).expect("uncertified");
        assert!(!uncertified.auto_merge_performed);
        assert!(uncertified.explanation.contains("not certified"));

        request.certified = true;
        request.lenses.clear();
        let no_lenses = decide_merge(&request).expect("no lenses");
        assert!(!no_lenses.auto_merge_performed);
        assert!(no_lenses.explanation.contains("no review lens accepted"));
    }

    #[test]
    fn never_auto_merge_set_is_reviewed_but_not_completed() {
        let mut request = allowed_request();
        request.changed_paths = vec![PathBuf::from(".github/workflows/ci.yml")];
        let decision = decide_merge(&request).expect("decide");
        assert!(!decision.auto_merge_performed);
        assert_eq!(
            decision.never_auto_merge,
            Some(NeverAutoMergeClass::CiCdDefinition)
        );

        request.changed_paths = vec![PathBuf::from("src/optimizer/merge_authority.rs")];
        let policy = decide_merge(&request).expect("policy");
        assert_eq!(
            policy.never_auto_merge,
            Some(NeverAutoMergeClass::ReviewOrMergePolicy)
        );

        request.changed_paths = vec![PathBuf::from("secrets/prod.env")];
        let creds = decide_merge(&request).expect("creds");
        assert_eq!(
            creds.never_auto_merge,
            Some(NeverAutoMergeClass::PermissionsOrCredentials)
        );

        request.changed_paths = vec![PathBuf::from("src/protected_path.rs")];
        let protected = decide_merge(&request).expect("protected");
        assert_eq!(
            protected.never_auto_merge,
            Some(NeverAutoMergeClass::ProtectedPath)
        );
        assert!(!protected.auto_merge_performed);

        request.changed_paths = vec![PathBuf::from("AGENTS.md")];
        let agents = decide_merge(&request).expect("agents");
        assert_eq!(
            agents.never_auto_merge,
            Some(NeverAutoMergeClass::ReviewOrMergePolicy)
        );
        assert!(!agents.auto_merge_performed);

        request.changed_paths = vec![PathBuf::from("CLAUDE.md")];
        let claude = decide_merge(&request).expect("claude");
        assert_eq!(
            claude.never_auto_merge,
            Some(NeverAutoMergeClass::ReviewOrMergePolicy)
        );

        request.changed_paths = vec![PathBuf::from(".agents/skills/core-agent-skills/SKILL.md")];
        let agents_dir = decide_merge(&request).expect("agents-dir");
        assert_eq!(
            agents_dir.never_auto_merge,
            Some(NeverAutoMergeClass::ReviewOrMergePolicy)
        );
    }

    #[test]
    fn history_flattening_and_dirty_merges_are_prohibited() {
        let mut request = allowed_request();
        request.completion_mode = CompletionMode::Squash;
        assert!(!decide_merge(&request).expect("squash").auto_merge_performed);
        request.completion_mode = CompletionMode::MergeCommit;
        request.branch_merges_cleanly = false;
        assert!(!decide_merge(&request).expect("dirty").auto_merge_performed);
    }
}
