//! Local-first authenticated intake for independent PR/candidate merge audits.
//!
//! This module performs no network access and launches no process. Callers must
//! inject both a trusted event authenticator and a provider-neutral audit lane.

use crate::external_agent::CodexRuntimeModelCatalog;
use crate::inbox::review_loop_entry::{
    compact_independent_auditor_selection, independent_auditor_actor,
    independent_auditor_stable_id, producer_auditor_separation_blocker,
    InboxIndependentAuditorSelectionEvidence,
};
use crate::inbox::{
    preflight_inbox_pr_event, run_inbox_for_pr_event, GithubCheckSummary, GithubPrSourceTrust,
    InboxIndependentAuditMergeLaneTask, InboxPrIntakeTaskKind, InboxRunOptions,
};
use crate::selection::ReasoningEffort;
use crate::supervise::PhaseModelPolicyDecision;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::{Component, Path, PathBuf};

const INTAKE_VERSION: u32 = 1;
const MAX_EVENT_BYTES: usize = 64 * 1024;
const MAX_IDENTIFIER_BYTES: usize = 512;
const MAX_DETAIL_CHARS: usize = 256;
const MAX_CHANGED_PATHS: usize = 256;
const MAX_CHECKS: usize = 512;
const MAX_PATH_BYTES: usize = 4 * 1024;

/// Opaque caller-supplied authentication material. Only the injected trusted
/// authenticator decides whether it proves the exact envelope payload.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IntakeAuthentication {
    pub scheme: String,
    pub key_id: String,
    pub proof: String,
}

/// A bounded local envelope whose `payload_json` is authenticated before it is
/// decoded or matched on event kind.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IntakeEventEnvelope {
    pub version: u32,
    pub delivery_id: String,
    pub authentication: IntakeAuthentication,
    pub payload_json: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum AuthenticationFailure {
    Rejected { detail: String },
    VerifierUnavailable { detail: String },
}

/// Trusted boundary for authenticating the exact local envelope. Implementors
/// are responsible for binding the proof to `delivery_id` and `payload_json`.
pub trait IntakeAuthenticator {
    fn authenticate(&self, envelope: &IntakeEventEnvelope) -> Result<(), AuthenticationFailure>;
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IntakeCandidateEvidence {
    pub event_id: String,
    pub source_snapshot_digest: String,
    pub source_updated_at: String,
    pub producer_identity: String,
    pub expected_head_oid: String,
    pub observed_head_oid: String,
    pub base_oid: String,
    pub changed_paths: Vec<PathBuf>,
    pub checks: Vec<GithubCheckSummary>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PullRequestIntakeEvent {
    pub number: u64,
    pub repository: String,
    pub is_draft: bool,
    pub source_trust: GithubPrSourceTrust,
    pub evidence: IntakeCandidateEvidence,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateBranchRegisteredIntakeEvent {
    pub repository: String,
    pub branch: String,
    pub evidence: IntakeCandidateEvidence,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UnsupportedIntakeEvent {
    pub event_kind: String,
}

/// Strict supported event set with an explicit unknown representation for
/// deterministic fail-closed handling.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(tag = "kind", content = "payload", rename_all = "snake_case")]
pub enum IntakeEvent {
    PullRequest(PullRequestIntakeEvent),
    CandidateBranchRegistered(CandidateBranchRegisteredIntakeEvent),
    Unknown(UnsupportedIntakeEvent),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SupportedIntakeEventKind {
    PullRequest,
    CandidateBranchRegistered,
}

/// Canonical source identity retained across authentication, selection, and
/// launch. Providers must use this identity for their fresh source query.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum IntakeCandidateIdentity {
    PullRequest { repository: String, number: u64 },
    CandidateBranch { repository: String, branch: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MergeAuditorLaneLaunchRequest {
    pub version: u32,
    pub delivery_id: String,
    pub event_id: String,
    pub event_kind: SupportedIntakeEventKind,
    pub candidate: IntakeCandidateIdentity,
    pub source_key: String,
    pub task_sha256: String,
    pub task: InboxIndependentAuditMergeLaneTask,
    pub auditor_identity: String,
    pub auditor_session_id: String,
    pub selection: InboxIndependentAuditorSelectionEvidence,
    pub authority: PhaseModelPolicyDecision,
    pub grants_merge_permission: bool,
    pub auto_merge_performed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MergeAuditorLaneLaunchReceipt {
    pub version: u32,
    pub launch_id: String,
    pub delivery_id: String,
    pub event_id: String,
    pub event_kind: SupportedIntakeEventKind,
    pub candidate: IntakeCandidateIdentity,
    pub source_key: String,
    pub task_sha256: String,
    pub source_snapshot_digest: String,
    pub head_oid: String,
    pub auditor_identity: String,
    pub auditor_session_id: String,
    pub runtime: String,
    pub model: String,
    pub effort: ReasoningEffort,
    pub authority: PhaseModelPolicyDecision,
    pub launched: bool,
    pub source_revalidated: bool,
    pub ci_revalidated: bool,
    pub safely_executed: bool,
    pub read_only: bool,
    pub merge_receipt_present: bool,
    pub grants_merge_permission: bool,
    pub auto_merge_performed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum MergeAuditorLaneProviderError {
    Unavailable { detail: String },
    Refused { detail: String },
    Failed { detail: String },
}

/// Provider-neutral launch seam. Implementations must launch at most the one
/// request supplied by [`handle_intake_event`].
pub trait MergeAuditorLaneProvider {
    fn launch(
        &mut self,
        request: &MergeAuditorLaneLaunchRequest,
    ) -> Result<MergeAuditorLaneLaunchReceipt, MergeAuditorLaneProviderError>;
}

/// Production adapter into the existing Inbox independent-audit and
/// authenticated-publication pipeline. It performs a fresh provider scan for
/// the exact PR identity and head carried by the authenticated event.
struct InboxMergeAuditorLaneProvider {
    options: InboxRunOptions,
}

impl MergeAuditorLaneProvider for InboxMergeAuditorLaneProvider {
    fn launch(
        &mut self,
        request: &MergeAuditorLaneLaunchRequest,
    ) -> Result<MergeAuditorLaneLaunchReceipt, MergeAuditorLaneProviderError> {
        let IntakeCandidateIdentity::PullRequest { number, .. } = &request.candidate else {
            return Err(MergeAuditorLaneProviderError::Refused {
                detail: "registered branch intake requires a branch-capable provider".to_string(),
            });
        };
        let mut options = self.options.clone();
        let observed_task = preflight_inbox_pr_event(&options, *number, &request.task.head_oid)
            .map_err(|error| MergeAuditorLaneProviderError::Refused {
                detail: bounded_detail(&format!("Inbox event preflight failed: {error:#}")),
            })?;
        if !same_source_task(&observed_task, &request.task) {
            return Err(MergeAuditorLaneProviderError::Refused {
                detail: "fresh Inbox task differed from authenticated event evidence".to_string(),
            });
        }
        options.run_id =
            crate::orchestrator::RunId::new(format!("{}-dispatch", request.auditor_session_id))
                .map_err(|error| MergeAuditorLaneProviderError::Failed {
                    detail: bounded_detail(&format!("event run id was invalid: {error:#}")),
                })?;
        let report =
            run_inbox_for_pr_event(options, *number, &request.task.head_oid, &observed_task)
                .map_err(|error| MergeAuditorLaneProviderError::Failed {
                    detail: bounded_detail(&format!("Inbox event dispatch failed: {error:#}")),
                })?;
        let item = report.item_reports.into_iter().next().ok_or_else(|| {
            MergeAuditorLaneProviderError::Refused {
                detail: "fresh Inbox scan produced no dispatchable event target".to_string(),
            }
        })?;
        let dispatched_task = item
            .pr_intake
            .as_ref()
            .and_then(|intake| intake.task.as_ref())
            .ok_or_else(|| MergeAuditorLaneProviderError::Refused {
                detail: "fresh Inbox scan produced no source-bound audit task".to_string(),
            })?;
        if !same_source_task(dispatched_task, &request.task) {
            return Err(MergeAuditorLaneProviderError::Refused {
                detail: "fresh Inbox task differed from authenticated event evidence".to_string(),
            });
        }
        let lane =
            item.independent_audit_lane
                .ok_or_else(|| MergeAuditorLaneProviderError::Refused {
                    detail: "Inbox event target produced no independent-audit lane report"
                        .to_string(),
                })?;
        if lane.number != *number
            || lane.source_key != request.source_key
            || lane.head_oid != request.task.head_oid
            || lane.source_snapshot_digest != request.task.source_snapshot_digest
        {
            return Err(MergeAuditorLaneProviderError::Refused {
                detail: "Inbox lane result did not match the authenticated event target"
                    .to_string(),
            });
        }
        if lane.blockers.iter().any(|blocker| {
            matches!(
                blocker,
                crate::inbox::review_loop_entry::InboxIndependentAuditLaneBlocker::StaleHead { .. }
                    | crate::inbox::review_loop_entry::InboxIndependentAuditLaneBlocker::MissingEvidence { .. }
                    | crate::inbox::review_loop_entry::InboxIndependentAuditLaneBlocker::MissingEligibility { .. }
            )
        }) {
            return Err(MergeAuditorLaneProviderError::Refused {
                detail: "Inbox refused stale or incomplete event ground truth".to_string(),
            });
        }
        let selection = lane
            .selection
            .ok_or_else(|| MergeAuditorLaneProviderError::Refused {
                detail: "Inbox lane omitted selector evidence".to_string(),
            })?;
        let launch = lane
            .launch
            .ok_or_else(|| MergeAuditorLaneProviderError::Refused {
                detail: "Inbox lane did not launch an independent auditor".to_string(),
            })?;
        if selection != request.selection {
            return Err(MergeAuditorLaneProviderError::Refused {
                detail: "Inbox lane selection differed from the authenticated dispatch".to_string(),
            });
        }
        if !launch.safely_executed || !launch.publishable {
            return Err(MergeAuditorLaneProviderError::Refused {
                detail: "Inbox auditor did not complete its screened execution boundary"
                    .to_string(),
            });
        }
        Ok(MergeAuditorLaneLaunchReceipt {
            version: INTAKE_VERSION,
            launch_id: launch.auditor_session_id.clone(),
            delivery_id: request.delivery_id.clone(),
            event_id: request.event_id.clone(),
            event_kind: request.event_kind,
            candidate: request.candidate.clone(),
            source_key: lane.source_key,
            task_sha256: request.task_sha256.clone(),
            source_snapshot_digest: lane.source_snapshot_digest,
            head_oid: lane.head_oid,
            auditor_identity: launch.auditor_identity,
            auditor_session_id: launch.auditor_session_id,
            runtime: selection.runtime,
            model: selection.model,
            effort: selection.effort,
            authority: request.authority,
            launched: true,
            source_revalidated: true,
            ci_revalidated: true,
            safely_executed: true,
            read_only: launch.permission_profile
                == crate::inbox::review_loop_entry::independent_auditor_permission_profile(),
            merge_receipt_present: lane.merge_receipt.is_some(),
            grants_merge_permission: false,
            auto_merge_performed: lane.auto_merge_performed,
        })
    }
}

fn same_source_task(
    observed: &InboxIndependentAuditMergeLaneTask,
    authenticated: &InboxIndependentAuditMergeLaneTask,
) -> bool {
    observed.source_snapshot_digest == authenticated.source_snapshot_digest
        && observed.source_updated_at == authenticated.source_updated_at
        && observed.head_oid == authenticated.head_oid
        && observed.base_oid == authenticated.base_oid
        && observed.producer_login == authenticated.producer_login
        && observed.is_draft == authenticated.is_draft
        && observed.source_trust == authenticated.source_trust
        && observed.head_repository == authenticated.head_repository
        && observed.changed_files == authenticated.changed_files
        && observed.checks == authenticated.checks
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(tag = "cause", rename_all = "snake_case")]
pub enum PrIntakeRefusalCause {
    Unauthenticated {
        failure: AuthenticationFailure,
    },
    InvalidEnvelope {
        field: String,
        detail: String,
    },
    MalformedEvent {
        detail: String,
    },
    UnknownEvent {
        event_kind: String,
    },
    InvalidGateEvidence {
        field: String,
        detail: String,
    },
    DraftPullRequest,
    UntrustedSource {
        source_trust: GithubPrSourceTrust,
    },
    StaleHead {
        expected_head_oid: String,
        observed_head_oid: String,
    },
    MissingChangedPaths,
    MissingCiEvidence,
    CiNotGreen {
        check_name: String,
    },
    SelectionFailure {
        detail: String,
    },
    IndependenceConflict {
        producer_identity: String,
        auditor_identity: String,
    },
    ProviderLaunchFailure {
        error: MergeAuditorLaneProviderError,
    },
    InvalidReceipt {
        field: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PrIntakeReport {
    pub version: u32,
    pub delivery_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_kind: Option<String>,
    pub success: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task: Option<InboxIndependentAuditMergeLaneTask>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selection: Option<InboxIndependentAuditorSelectionEvidence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority: Option<PhaseModelPolicyDecision>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub launch_receipt: Option<MergeAuditorLaneLaunchReceipt>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refusal: Option<PrIntakeRefusalCause>,
    pub grants_merge_permission: bool,
    pub auto_merge_performed: bool,
}

impl PrIntakeReport {
    fn new(envelope: &IntakeEventEnvelope) -> Self {
        Self {
            version: INTAKE_VERSION,
            delivery_id: bounded_detail(&envelope.delivery_id),
            event_id: None,
            event_kind: None,
            success: false,
            task: None,
            selection: None,
            authority: None,
            launch_receipt: None,
            refusal: None,
            grants_merge_permission: false,
            auto_merge_performed: false,
        }
    }

    fn refuse(mut self, cause: PrIntakeRefusalCause) -> Self {
        self.success = false;
        self.launch_receipt = None;
        self.refusal = Some(cause);
        self.grants_merge_permission = false;
        self.auto_merge_performed = false;
        self
    }
}

struct NormalizedIntake {
    event_id: String,
    event_kind: SupportedIntakeEventKind,
    candidate: IntakeCandidateIdentity,
    source_key: String,
    task: InboxIndependentAuditMergeLaneTask,
}

/// Authenticate, preflight, select, and launch exactly one independent audit
/// lane, returning a serializable success or typed refusal report.
pub fn handle_intake_event<A, P, I, S>(
    envelope: &IntakeEventEnvelope,
    observed_available_model_slugs: I,
    authenticator: &A,
    provider: &mut P,
) -> PrIntakeReport
where
    A: IntakeAuthenticator,
    P: MergeAuditorLaneProvider,
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let mut report = PrIntakeReport::new(envelope);

    // Authentication deliberately precedes version checks, JSON decoding, and
    // any event-kind or payload interpretation.
    if let Err(failure) = authenticator.authenticate(envelope) {
        return report.refuse(PrIntakeRefusalCause::Unauthenticated {
            failure: bounded_authentication_failure(failure),
        });
    }

    if envelope.version != INTAKE_VERSION {
        return report.refuse(PrIntakeRefusalCause::InvalidEnvelope {
            field: "version".to_string(),
            detail: "unsupported intake envelope version".to_string(),
        });
    }
    if let Err(cause) = validate_identifier("delivery_id", &envelope.delivery_id) {
        return report.refuse(cause);
    }
    if envelope.payload_json.is_empty() || envelope.payload_json.len() > MAX_EVENT_BYTES {
        return report.refuse(PrIntakeRefusalCause::InvalidEnvelope {
            field: "payload_json".to_string(),
            detail: "event payload is empty or exceeds the local intake bound".to_string(),
        });
    }

    let raw_event = match serde_json::from_str::<serde_json::Value>(&envelope.payload_json) {
        Ok(event) => event,
        Err(error) => {
            return report.refuse(PrIntakeRefusalCause::MalformedEvent {
                detail: bounded_detail(&error.to_string()),
            });
        }
    };
    let Some(raw_kind) = raw_event.get("kind").and_then(serde_json::Value::as_str) else {
        return report.refuse(PrIntakeRefusalCause::MalformedEvent {
            detail: "event omitted its string kind discriminator".to_string(),
        });
    };
    if !matches!(
        raw_kind,
        "pull_request" | "candidate_branch_registered" | "unknown"
    ) {
        report.event_kind = Some(bounded_detail(raw_kind));
        return report.refuse(PrIntakeRefusalCause::UnknownEvent {
            event_kind: bounded_detail(raw_kind),
        });
    }
    let event = match serde_json::from_value::<IntakeEvent>(raw_event) {
        Ok(event) => event,
        Err(error) => {
            return report.refuse(PrIntakeRefusalCause::MalformedEvent {
                detail: bounded_detail(&error.to_string()),
            });
        }
    };
    let normalized = match normalize_event(event) {
        Ok(normalized) => normalized,
        Err((event_id, event_kind, cause)) => {
            report.event_id = event_id.map(|value| bounded_detail(&value));
            report.event_kind = event_kind;
            return report.refuse(cause);
        }
    };
    report.event_id = Some(normalized.event_id.clone());
    report.event_kind = Some(event_kind_name(normalized.event_kind).to_string());
    report.task = Some(normalized.task.clone());

    let catalog = match CodexRuntimeModelCatalog::from_slugs(observed_available_model_slugs) {
        Ok(catalog) => catalog,
        Err(error) => {
            return report.refuse(PrIntakeRefusalCause::SelectionFailure {
                detail: bounded_detail(&format!("{error:#}")),
            });
        }
    };
    let selected = match catalog.select_executable_review_auditor() {
        Ok(selected) => selected,
        Err(error) => {
            return report.refuse(PrIntakeRefusalCause::SelectionFailure {
                detail: bounded_detail(&format!("{error:#}")),
            });
        }
    };
    let selection = match compact_independent_auditor_selection(&selected.provenance) {
        Ok(selection) => selection,
        Err(error) => {
            return report.refuse(PrIntakeRefusalCause::SelectionFailure {
                detail: bounded_detail(&format!("{error:#}")),
            });
        }
    };
    report.selection = Some(selection.clone());
    report.authority = Some(selected.authority);

    let session_id = independent_auditor_session_id(
        &envelope.delivery_id,
        &normalized.event_id,
        &normalized.task.head_oid,
    );
    let auditor = independent_auditor_actor(&session_id, &selection.model);
    if let Some(blocker) = producer_auditor_separation_blocker(
        &normalized.task.producer_login,
        &auditor,
        &normalized.task.head_oid,
    ) {
        let cause = match blocker {
            crate::inbox::review_loop_entry::InboxIndependentAuditLaneBlocker::ProducerAuditorIdentityConflict {
                producer_identity,
                auditor_identity,
            } => PrIntakeRefusalCause::IndependenceConflict {
                producer_identity,
                auditor_identity,
            },
            _ => PrIntakeRefusalCause::IndependenceConflict {
                producer_identity: normalized.task.producer_login.clone(),
                auditor_identity: auditor.agent.stable_id.clone(),
            },
        };
        return report.refuse(cause);
    }

    let task_sha256 = match task_sha256(&normalized.task) {
        Ok(digest) => digest,
        Err(detail) => {
            return report.refuse(PrIntakeRefusalCause::InvalidGateEvidence {
                field: "task".to_string(),
                detail,
            });
        }
    };
    let request = MergeAuditorLaneLaunchRequest {
        version: INTAKE_VERSION,
        delivery_id: envelope.delivery_id.clone(),
        event_id: normalized.event_id,
        event_kind: normalized.event_kind,
        candidate: normalized.candidate,
        source_key: normalized.source_key,
        task_sha256,
        task: normalized.task,
        auditor_identity: independent_auditor_stable_id().to_string(),
        auditor_session_id: session_id,
        selection,
        authority: selected.authority,
        grants_merge_permission: false,
        auto_merge_performed: false,
    };
    let receipt = match provider.launch(&request) {
        Ok(receipt) => receipt,
        Err(error) => {
            return report.refuse(PrIntakeRefusalCause::ProviderLaunchFailure {
                error: bounded_provider_error(error),
            });
        }
    };
    if let Some(field) = invalid_receipt_field(&request, &receipt) {
        return report.refuse(PrIntakeRefusalCause::InvalidReceipt {
            field: field.to_string(),
        });
    }

    report.success = true;
    report.auto_merge_performed = receipt.auto_merge_performed;
    report.launch_receipt = Some(receipt);
    report.refusal = None;
    report.grants_merge_permission = false;
    report
}

/// Authenticate one event and dispatch it through the existing production
/// Inbox lane. The Inbox adapter performs the fresh provider scan, exact-head
/// filtering, screened auditor launch, output validation, and authenticated
/// publication gates.
pub fn handle_inbox_intake_event<A, I, S>(
    envelope: &IntakeEventEnvelope,
    observed_available_model_slugs: I,
    authenticator: &A,
    options: InboxRunOptions,
) -> PrIntakeReport
where
    A: IntakeAuthenticator,
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let mut provider = InboxMergeAuditorLaneProvider { options };
    handle_intake_event(
        envelope,
        observed_available_model_slugs,
        authenticator,
        &mut provider,
    )
}

fn normalize_event(
    event: IntakeEvent,
) -> Result<NormalizedIntake, (Option<String>, Option<String>, PrIntakeRefusalCause)> {
    match event {
        IntakeEvent::Unknown(unknown) => Err((
            None,
            Some("unknown".to_string()),
            PrIntakeRefusalCause::UnknownEvent {
                event_kind: bounded_detail(&unknown.event_kind),
            },
        )),
        IntakeEvent::PullRequest(event) => {
            let event_id = event.evidence.event_id.clone();
            let kind = Some("pull_request".to_string());
            if event.number == 0 {
                return Err((
                    Some(event_id),
                    kind,
                    invalid_evidence("number", "pull request number must be greater than zero"),
                ));
            }
            if let Err(cause) = validate_identifier("repository", &event.repository) {
                return Err((Some(event_id), kind, cause));
            }
            if event.is_draft {
                return Err((Some(event_id), kind, PrIntakeRefusalCause::DraftPullRequest));
            }
            if event.source_trust != GithubPrSourceTrust::TrustedTargetRepository {
                return Err((
                    Some(event_id),
                    kind,
                    PrIntakeRefusalCause::UntrustedSource {
                        source_trust: event.source_trust,
                    },
                ));
            }
            let candidate = IntakeCandidateIdentity::PullRequest {
                repository: event.repository.clone(),
                number: event.number,
            };
            normalize_supported(
                SupportedIntakeEventKind::PullRequest,
                event.repository,
                false,
                event.source_trust,
                event.evidence,
                candidate,
            )
            .map_err(|cause| (Some(event_id), kind, cause))
        }
        IntakeEvent::CandidateBranchRegistered(event) => {
            let event_id = event.evidence.event_id.clone();
            let kind = Some("candidate_branch_registered".to_string());
            if let Err(cause) = validate_identifier("repository", &event.repository) {
                return Err((Some(event_id), kind, cause));
            }
            if let Err(cause) = validate_identifier("branch", &event.branch) {
                return Err((Some(event_id), kind, cause));
            }
            let candidate = IntakeCandidateIdentity::CandidateBranch {
                repository: event.repository.clone(),
                branch: event.branch,
            };
            normalize_supported(
                SupportedIntakeEventKind::CandidateBranchRegistered,
                event.repository,
                false,
                GithubPrSourceTrust::TrustedTargetRepository,
                event.evidence,
                candidate,
            )
            .map_err(|cause| (Some(event_id), kind, cause))
        }
    }
}

fn normalize_supported(
    event_kind: SupportedIntakeEventKind,
    repository: String,
    is_draft: bool,
    source_trust: GithubPrSourceTrust,
    evidence: IntakeCandidateEvidence,
    candidate: IntakeCandidateIdentity,
) -> Result<NormalizedIntake, PrIntakeRefusalCause> {
    validate_identifier("event_id", &evidence.event_id)?;
    validate_identifier("producer_identity", &evidence.producer_identity)?;
    validate_bounded_text("source_updated_at", &evidence.source_updated_at)?;
    validate_digest("source_snapshot_digest", &evidence.source_snapshot_digest)?;
    validate_oid("expected_head_oid", &evidence.expected_head_oid)?;
    validate_oid("observed_head_oid", &evidence.observed_head_oid)?;
    validate_oid("base_oid", &evidence.base_oid)?;
    if evidence.expected_head_oid != evidence.observed_head_oid {
        return Err(PrIntakeRefusalCause::StaleHead {
            expected_head_oid: evidence.expected_head_oid,
            observed_head_oid: evidence.observed_head_oid,
        });
    }
    validate_changed_paths(&evidence.changed_paths)?;
    validate_checks(&evidence.checks)?;

    let task = InboxIndependentAuditMergeLaneTask {
        version: INTAKE_VERSION,
        task_kind: InboxPrIntakeTaskKind::IndependentAuditMergeLane,
        source_snapshot_digest: evidence.source_snapshot_digest,
        source_updated_at: evidence.source_updated_at,
        head_oid: evidence.observed_head_oid,
        base_oid: evidence.base_oid,
        producer_login: evidence.producer_identity,
        is_draft,
        source_trust,
        head_repository: Some(repository),
        changed_files: evidence.changed_paths,
        checks: evidence.checks,
        requires_trusted_actor_binding: true,
        requires_fresh_source_revalidation: true,
        requires_passing_ci: true,
        requires_independent_auditor: true,
        grants_merge_permission: false,
        auto_merge_performed: false,
        next_action: "launch one independent read-only merge auditor; do not merge".to_string(),
    };
    Ok(NormalizedIntake {
        event_id: evidence.event_id,
        event_kind,
        source_key: match &candidate {
            IntakeCandidateIdentity::PullRequest { number, .. } => {
                format!("github_pr:{number}")
            }
            IntakeCandidateIdentity::CandidateBranch { repository, branch } => {
                let material = format!("{repository}\0{branch}");
                let digest = crate::artifacts::state_auth::sha256_hex(material.as_bytes());
                format!("candidate_branch:{}", &digest[..24])
            }
        },
        candidate,
        task,
    })
}

fn validate_identifier(field: &str, value: &str) -> Result<(), PrIntakeRefusalCause> {
    if value.is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || value.trim() != value
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/' | b'@')
        })
    {
        return Err(invalid_evidence(
            field,
            "identifier must be bounded, trimmed, and contain only safe ASCII token characters",
        ));
    }
    Ok(())
}

fn validate_bounded_text(field: &str, value: &str) -> Result<(), PrIntakeRefusalCause> {
    if value.is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(invalid_evidence(
            field,
            "text evidence is empty or malformed",
        ));
    }
    Ok(())
}

fn validate_digest(field: &str, value: &str) -> Result<(), PrIntakeRefusalCause> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(invalid_evidence(
            field,
            "digest must be 64 hexadecimal characters",
        ));
    }
    Ok(())
}

fn validate_oid(field: &str, value: &str) -> Result<(), PrIntakeRefusalCause> {
    if !matches!(value.len(), 40 | 64) || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(invalid_evidence(
            field,
            "object id must be 40 or 64 hexadecimal characters",
        ));
    }
    Ok(())
}

fn validate_changed_paths(paths: &[PathBuf]) -> Result<(), PrIntakeRefusalCause> {
    if paths.is_empty() {
        return Err(PrIntakeRefusalCause::MissingChangedPaths);
    }
    if paths.len() > MAX_CHANGED_PATHS {
        return Err(invalid_evidence("changed_paths", "too many changed paths"));
    }
    let mut seen = BTreeSet::new();
    for path in paths {
        if !valid_relative_path(path) || !seen.insert(path.clone()) {
            return Err(invalid_evidence(
                "changed_paths",
                "paths must be unique bounded relative repository paths",
            ));
        }
    }
    Ok(())
}

fn valid_relative_path(path: &Path) -> bool {
    let Some(text) = path.to_str() else {
        return false;
    };
    !text.is_empty()
        && text.len() <= MAX_PATH_BYTES
        && path
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
}

fn validate_checks(checks: &[GithubCheckSummary]) -> Result<(), PrIntakeRefusalCause> {
    if checks.is_empty() {
        return Err(PrIntakeRefusalCause::MissingCiEvidence);
    }
    if checks.len() > MAX_CHECKS {
        return Err(invalid_evidence("checks", "too many CI checks"));
    }
    let mut names = BTreeSet::new();
    for check in checks {
        validate_bounded_text("check_name", &check.name)?;
        if !names.insert(check.name.clone()) {
            return Err(invalid_evidence("checks", "duplicate CI check name"));
        }
        if check.summary.len() > MAX_EVENT_BYTES
            || check
                .details_url
                .as_ref()
                .is_some_and(|url| url.len() > MAX_IDENTIFIER_BYTES * 4)
        {
            return Err(invalid_evidence(
                "checks",
                "CI check detail exceeds intake bounds",
            ));
        }
        let completed = check
            .status
            .as_deref()
            .is_some_and(|status| status.eq_ignore_ascii_case("completed"));
        let green = check
            .conclusion
            .as_deref()
            .is_some_and(|conclusion| conclusion.eq_ignore_ascii_case("success"));
        if !completed || !green {
            return Err(PrIntakeRefusalCause::CiNotGreen {
                check_name: bounded_detail(&check.name),
            });
        }
    }
    Ok(())
}

fn task_sha256(task: &InboxIndependentAuditMergeLaneTask) -> Result<String, String> {
    serde_json::to_vec(task)
        .map(|bytes| crate::artifacts::state_auth::sha256_hex(&bytes))
        .map_err(|error| bounded_detail(&error.to_string()))
}

fn independent_auditor_session_id(delivery_id: &str, event_id: &str, head_oid: &str) -> String {
    let material = format!("{delivery_id}\0{event_id}\0{head_oid}");
    let digest = crate::artifacts::state_auth::sha256_hex(material.as_bytes());
    format!("pr-intake-{}", &digest[..24])
}

fn invalid_receipt_field(
    request: &MergeAuditorLaneLaunchRequest,
    receipt: &MergeAuditorLaneLaunchReceipt,
) -> Option<&'static str> {
    if receipt.version != INTAKE_VERSION {
        return Some("version");
    }
    if validate_identifier("launch_id", &receipt.launch_id).is_err() {
        return Some("launch_id");
    }
    if receipt.delivery_id != request.delivery_id {
        return Some("delivery_id");
    }
    if receipt.event_id != request.event_id {
        return Some("event_id");
    }
    if receipt.event_kind != request.event_kind {
        return Some("event_kind");
    }
    if receipt.candidate != request.candidate {
        return Some("candidate");
    }
    if receipt.source_key != request.source_key {
        return Some("source_key");
    }
    if receipt.task_sha256 != request.task_sha256 {
        return Some("task_sha256");
    }
    if receipt.source_snapshot_digest != request.task.source_snapshot_digest {
        return Some("source_snapshot_digest");
    }
    if receipt.head_oid != request.task.head_oid {
        return Some("head_oid");
    }
    if receipt.auditor_identity != request.auditor_identity {
        return Some("auditor_identity");
    }
    if receipt.auditor_session_id != request.auditor_session_id {
        return Some("auditor_session_id");
    }
    if receipt.runtime != request.selection.runtime {
        return Some("runtime");
    }
    if receipt.model != request.selection.model {
        return Some("model");
    }
    if receipt.effort != request.selection.effort {
        return Some("effort");
    }
    if receipt.authority != request.authority {
        return Some("authority");
    }
    if !receipt.launched {
        return Some("launched");
    }
    if !receipt.source_revalidated {
        return Some("source_revalidated");
    }
    if !receipt.ci_revalidated {
        return Some("ci_revalidated");
    }
    if !receipt.safely_executed {
        return Some("safely_executed");
    }
    if !receipt.read_only {
        return Some("read_only");
    }
    if receipt.grants_merge_permission {
        return Some("grants_merge_permission");
    }
    if receipt.auto_merge_performed != receipt.merge_receipt_present {
        return Some("merge_receipt_present");
    }
    None
}

fn invalid_evidence(field: &str, detail: &str) -> PrIntakeRefusalCause {
    PrIntakeRefusalCause::InvalidGateEvidence {
        field: field.to_string(),
        detail: bounded_detail(detail),
    }
}

fn event_kind_name(kind: SupportedIntakeEventKind) -> &'static str {
    match kind {
        SupportedIntakeEventKind::PullRequest => "pull_request",
        SupportedIntakeEventKind::CandidateBranchRegistered => "candidate_branch_registered",
    }
}

fn bounded_detail(detail: &str) -> String {
    detail.chars().take(MAX_DETAIL_CHARS).collect()
}

fn bounded_authentication_failure(failure: AuthenticationFailure) -> AuthenticationFailure {
    match failure {
        AuthenticationFailure::Rejected { detail } => AuthenticationFailure::Rejected {
            detail: bounded_detail(&detail),
        },
        AuthenticationFailure::VerifierUnavailable { detail } => {
            AuthenticationFailure::VerifierUnavailable {
                detail: bounded_detail(&detail),
            }
        }
    }
}

fn bounded_provider_error(error: MergeAuditorLaneProviderError) -> MergeAuditorLaneProviderError {
    match error {
        MergeAuditorLaneProviderError::Unavailable { detail } => {
            MergeAuditorLaneProviderError::Unavailable {
                detail: bounded_detail(&detail),
            }
        }
        MergeAuditorLaneProviderError::Refused { detail } => {
            MergeAuditorLaneProviderError::Refused {
                detail: bounded_detail(&detail),
            }
        }
        MergeAuditorLaneProviderError::Failed { detail } => MergeAuditorLaneProviderError::Failed {
            detail: bounded_detail(&detail),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::supervise::{AgentRole, ModelCapabilityClass, OrchestrationPhase};
    use std::cell::Cell;

    struct FakeAuthenticator {
        accept: bool,
        calls: Cell<usize>,
    }

    impl FakeAuthenticator {
        fn accepting() -> Self {
            Self {
                accept: true,
                calls: Cell::new(0),
            }
        }

        fn rejecting() -> Self {
            Self {
                accept: false,
                calls: Cell::new(0),
            }
        }
    }

    impl IntakeAuthenticator for FakeAuthenticator {
        fn authenticate(
            &self,
            _envelope: &IntakeEventEnvelope,
        ) -> Result<(), AuthenticationFailure> {
            self.calls.set(self.calls.get() + 1);
            if self.accept {
                Ok(())
            } else {
                Err(AuthenticationFailure::Rejected {
                    detail: "bad_signature".to_string(),
                })
            }
        }
    }

    #[derive(Default)]
    struct FakeProvider {
        requests: Vec<MergeAuditorLaneLaunchRequest>,
        corrupt_field: Option<&'static str>,
        fail: bool,
    }

    impl MergeAuditorLaneProvider for FakeProvider {
        fn launch(
            &mut self,
            request: &MergeAuditorLaneLaunchRequest,
        ) -> Result<MergeAuditorLaneLaunchReceipt, MergeAuditorLaneProviderError> {
            self.requests.push(request.clone());
            if self.fail {
                return Err(MergeAuditorLaneProviderError::Failed {
                    detail: "deterministic_failure".to_string(),
                });
            }
            let mut receipt = matching_receipt(request);
            if self.corrupt_field == Some("model") {
                receipt.model = "provider-substitution".to_string();
            }
            Ok(receipt)
        }
    }

    fn matching_receipt(request: &MergeAuditorLaneLaunchRequest) -> MergeAuditorLaneLaunchReceipt {
        MergeAuditorLaneLaunchReceipt {
            version: INTAKE_VERSION,
            launch_id: "fake-launch-1".to_string(),
            delivery_id: request.delivery_id.clone(),
            event_id: request.event_id.clone(),
            event_kind: request.event_kind,
            candidate: request.candidate.clone(),
            source_key: request.source_key.clone(),
            task_sha256: request.task_sha256.clone(),
            source_snapshot_digest: request.task.source_snapshot_digest.clone(),
            head_oid: request.task.head_oid.clone(),
            auditor_identity: request.auditor_identity.clone(),
            auditor_session_id: request.auditor_session_id.clone(),
            runtime: request.selection.runtime.clone(),
            model: request.selection.model.clone(),
            effort: request.selection.effort,
            authority: request.authority,
            launched: true,
            source_revalidated: true,
            ci_revalidated: true,
            safely_executed: true,
            read_only: true,
            merge_receipt_present: false,
            grants_merge_permission: false,
            auto_merge_performed: false,
        }
    }

    fn green_check() -> GithubCheckSummary {
        GithubCheckSummary {
            name: "test".to_string(),
            status: Some("completed".to_string()),
            conclusion: Some("success".to_string()),
            details_url: None,
            summary: "green".to_string(),
        }
    }

    fn evidence() -> IntakeCandidateEvidence {
        IntakeCandidateEvidence {
            event_id: "event-1".to_string(),
            source_snapshot_digest: "a".repeat(64),
            source_updated_at: "2026-09-03T00:00:00Z".to_string(),
            producer_identity: "producer".to_string(),
            expected_head_oid: "b".repeat(40),
            observed_head_oid: "b".repeat(40),
            base_oid: "c".repeat(40),
            changed_paths: vec![PathBuf::from("src/lib.rs")],
            checks: vec![green_check()],
        }
    }

    fn pull_request_event() -> IntakeEvent {
        IntakeEvent::PullRequest(PullRequestIntakeEvent {
            number: 17,
            repository: "Meta-Develop/MACO".to_string(),
            is_draft: false,
            source_trust: GithubPrSourceTrust::TrustedTargetRepository,
            evidence: evidence(),
        })
    }

    fn candidate_branch_event() -> IntakeEvent {
        let mut evidence = evidence();
        evidence.event_id = "candidate-event-1".to_string();
        IntakeEvent::CandidateBranchRegistered(CandidateBranchRegisteredIntakeEvent {
            repository: "Meta-Develop/MACO".to_string(),
            branch: "maco/candidate".to_string(),
            evidence,
        })
    }

    fn envelope(event: IntakeEvent) -> IntakeEventEnvelope {
        IntakeEventEnvelope {
            version: INTAKE_VERSION,
            delivery_id: "delivery-1".to_string(),
            authentication: IntakeAuthentication {
                scheme: "test".to_string(),
                key_id: "local-test".to_string(),
                proof: "trusted".to_string(),
            },
            payload_json: serde_json::to_string(&event).expect("serialize event"),
        }
    }

    fn sol_catalog() -> Vec<String> {
        vec!["gpt-5.6-sol".to_string()]
    }

    #[test]
    fn authenticated_pull_request_launches_one_bound_independent_auditor() {
        let envelope = envelope(pull_request_event());
        let authenticator = FakeAuthenticator::accepting();
        let mut provider = FakeProvider::default();

        let report = handle_intake_event(&envelope, sol_catalog(), &authenticator, &mut provider);

        assert!(report.success);
        assert_eq!(authenticator.calls.get(), 1);
        assert_eq!(provider.requests.len(), 1);
        let request = &provider.requests[0];
        let task = report.task.as_ref().expect("source-bound task");
        assert_eq!(&request.task, task);
        assert_eq!(task.head_oid, "b".repeat(40));
        assert_eq!(task.source_snapshot_digest, "a".repeat(64));
        assert!(task.requires_trusted_actor_binding);
        assert!(task.requires_fresh_source_revalidation);
        assert!(task.requires_passing_ci);
        assert!(task.requires_independent_auditor);
        assert!(!task.grants_merge_permission);
        assert!(!task.auto_merge_performed);
        assert_eq!(request.selection.model, "gpt-5.6-sol");
        assert!(request.selection.effort >= ReasoningEffort::Xhigh);
        assert_eq!(request.authority.role, AgentRole::Auditor);
        assert_eq!(request.authority.phase, OrchestrationPhase::Audit);
        assert_eq!(
            request.authority.required_capability,
            ModelCapabilityClass::CriticalJudgment
        );
        assert_eq!(
            request.authority.selected_capability,
            ModelCapabilityClass::CriticalJudgment
        );
        assert_ne!(request.auditor_identity, task.producer_login);
        assert_eq!(
            report
                .launch_receipt
                .as_ref()
                .expect("validated receipt")
                .task_sha256,
            request.task_sha256
        );
        assert!(!report.grants_merge_permission);
        assert!(!report.auto_merge_performed);
        serde_json::to_string(&report).expect("serializable report");
    }

    #[test]
    fn authenticated_candidate_branch_is_supported_and_launched() {
        let envelope = envelope(candidate_branch_event());
        let authenticator = FakeAuthenticator::accepting();
        let mut provider = FakeProvider::default();

        let report = handle_intake_event(&envelope, sol_catalog(), &authenticator, &mut provider);

        assert!(report.success);
        assert_eq!(provider.requests.len(), 1);
        assert_eq!(
            provider.requests[0].event_kind,
            SupportedIntakeEventKind::CandidateBranchRegistered
        );
        assert_eq!(
            provider.requests[0].candidate,
            IntakeCandidateIdentity::CandidateBranch {
                repository: "Meta-Develop/MACO".to_string(),
                branch: "maco/candidate".to_string(),
            }
        );
        assert_eq!(
            report.task.expect("candidate task").head_repository,
            Some("Meta-Develop/MACO".to_string())
        );
    }

    #[test]
    fn unauthenticated_payload_refuses_before_parsing_and_never_launches() {
        let mut envelope = envelope(pull_request_event());
        envelope.payload_json = "not-json".to_string();
        let authenticator = FakeAuthenticator::rejecting();
        let mut provider = FakeProvider::default();

        let report = handle_intake_event(&envelope, sol_catalog(), &authenticator, &mut provider);

        assert_eq!(
            report.refusal,
            Some(PrIntakeRefusalCause::Unauthenticated {
                failure: AuthenticationFailure::Rejected {
                    detail: "bad_signature".to_string()
                }
            })
        );
        assert!(provider.requests.is_empty());
        assert!(report.launch_receipt.is_none());
    }

    #[test]
    fn authenticated_unknown_event_refuses_without_launch() {
        let mut envelope = envelope(IntakeEvent::Unknown(UnsupportedIntakeEvent {
            event_kind: "repository_deleted".to_string(),
        }));
        envelope.payload_json = r#"{"kind":"repository_deleted","payload":{}}"#.to_string();
        let authenticator = FakeAuthenticator::accepting();
        let mut provider = FakeProvider::default();

        let report = handle_intake_event(&envelope, sol_catalog(), &authenticator, &mut provider);

        assert_eq!(
            report.refusal,
            Some(PrIntakeRefusalCause::UnknownEvent {
                event_kind: "repository_deleted".to_string()
            })
        );
        assert!(provider.requests.is_empty());
    }

    #[test]
    fn stale_head_and_failed_ci_refuse_without_launch() {
        let mut stale = evidence();
        stale.observed_head_oid = "d".repeat(40);
        let stale_event = IntakeEvent::PullRequest(PullRequestIntakeEvent {
            number: 17,
            repository: "Meta-Develop/MACO".to_string(),
            is_draft: false,
            source_trust: GithubPrSourceTrust::TrustedTargetRepository,
            evidence: stale,
        });
        let authenticator = FakeAuthenticator::accepting();
        let mut provider = FakeProvider::default();
        let report = handle_intake_event(
            &envelope(stale_event),
            sol_catalog(),
            &authenticator,
            &mut provider,
        );
        assert!(matches!(
            report.refusal,
            Some(PrIntakeRefusalCause::StaleHead { .. })
        ));
        assert!(provider.requests.is_empty());

        let mut failed = evidence();
        failed.checks[0].conclusion = Some("failure".to_string());
        let failed_event = IntakeEvent::PullRequest(PullRequestIntakeEvent {
            number: 17,
            repository: "Meta-Develop/MACO".to_string(),
            is_draft: false,
            source_trust: GithubPrSourceTrust::TrustedTargetRepository,
            evidence: failed,
        });
        let mut provider = FakeProvider::default();
        let report = handle_intake_event(
            &envelope(failed_event),
            sol_catalog(),
            &authenticator,
            &mut provider,
        );
        assert_eq!(
            report.refusal,
            Some(PrIntakeRefusalCause::CiNotGreen {
                check_name: "test".to_string()
            })
        );
        assert!(provider.requests.is_empty());
    }

    #[test]
    fn empty_and_ineligible_catalogs_fail_closed_without_launch() {
        for catalog in [
            Vec::<String>::new(),
            vec!["gpt-5.6-luna".to_string()],
            vec!["gpt-5.6-terra".to_string()],
            vec!["unknown-model".to_string()],
        ] {
            let envelope = envelope(pull_request_event());
            let authenticator = FakeAuthenticator::accepting();
            let mut provider = FakeProvider::default();
            let report = handle_intake_event(&envelope, catalog, &authenticator, &mut provider);

            assert!(matches!(
                report.refusal,
                Some(PrIntakeRefusalCause::SelectionFailure { .. })
            ));
            assert!(provider.requests.is_empty());
        }
    }

    #[test]
    fn provider_failure_and_invalid_receipt_are_typed_refusals() {
        let envelope = envelope(pull_request_event());
        let authenticator = FakeAuthenticator::accepting();
        let mut failed_provider = FakeProvider {
            fail: true,
            ..FakeProvider::default()
        };
        let failed = handle_intake_event(
            &envelope,
            sol_catalog(),
            &authenticator,
            &mut failed_provider,
        );
        assert!(matches!(
            failed.refusal,
            Some(PrIntakeRefusalCause::ProviderLaunchFailure { .. })
        ));
        assert_eq!(failed_provider.requests.len(), 1);
        assert!(failed.launch_receipt.is_none());

        let mut corrupt_provider = FakeProvider {
            corrupt_field: Some("model"),
            ..FakeProvider::default()
        };
        let invalid = handle_intake_event(
            &envelope,
            sol_catalog(),
            &authenticator,
            &mut corrupt_provider,
        );
        assert_eq!(
            invalid.refusal,
            Some(PrIntakeRefusalCause::InvalidReceipt {
                field: "model".to_string()
            })
        );
        assert_eq!(corrupt_provider.requests.len(), 1);
        assert!(invalid.launch_receipt.is_none());
    }

    #[test]
    fn producer_identity_conflict_refuses_before_provider_launch() {
        let mut event = pull_request_event();
        let IntakeEvent::PullRequest(ref mut pull_request) = event else {
            panic!("pull request fixture")
        };
        pull_request.evidence.producer_identity = independent_auditor_stable_id().to_string();
        let envelope = envelope(event);
        let authenticator = FakeAuthenticator::accepting();
        let mut provider = FakeProvider::default();

        let report = handle_intake_event(&envelope, sol_catalog(), &authenticator, &mut provider);

        assert!(matches!(
            report.refusal,
            Some(PrIntakeRefusalCause::IndependenceConflict { .. })
        ));
        assert!(provider.requests.is_empty());
    }
}
