//! Authenticated intake for independent PR/candidate merge audits.
//!
//! The generic handler remains provider-neutral. The production producer uses
//! the existing trusted Inbox GitHub and auditor boundaries, authenticates the
//! resulting local envelope, and records replay-safe durable effect state.

use crate::artifacts::{
    repository_auth_writer,
    state_auth::{AuthenticationDomain, AuthenticationTag, RepositoryAuthenticator},
};
use crate::effect_wal::{EffectPhase, EffectWal};
use crate::external_agent::{load_codex_runtime_model_catalog, CodexRuntimeModelCatalog};
use crate::inbox::review_loop_entry::{
    compact_independent_auditor_selection, independent_auditor_actor,
    independent_auditor_stable_id, producer_auditor_separation_blocker,
    InboxIndependentAuditorSelectionEvidence,
};
use crate::inbox::{
    bind_approved_github_actor, observe_inbox_pr_event, preflight_inbox_pr_event,
    run_inbox_for_pr_event, sanitize_pr_intake_provider_detail, GithubCheckSummary,
    GithubPrSourceTrust, InboxApprovedGithubActorBinding, InboxApprovedGithubActorError,
    InboxApprovedGithubActorFailure, InboxIndependentAuditMergeLaneTask, InboxItem, InboxItemKind,
    InboxPrIntakeTaskKind, InboxPrObservationError, InboxPrObservationFailureClass,
    InboxRunOptions, InboxSourceProvider,
};
use crate::selection::ReasoningEffort;
use crate::supervise::PhaseModelPolicyDecision;
use anyhow::Context;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::{
    path::{Component, Path, PathBuf},
    time::Duration,
};

const INTAKE_VERSION: u32 = 1;
const MAX_EVENT_BYTES: usize = 64 * 1024;
const MAX_IDENTIFIER_BYTES: usize = 512;
const MAX_DETAIL_CHARS: usize = 256;
const MAX_CHANGED_PATHS: usize = 256;
const MAX_CHECKS: usize = 512;
const MAX_PATH_BYTES: usize = 4 * 1024;
const PRODUCTION_CATALOG_TIMEOUT: Duration = Duration::from_secs(600);
const INTAKE_ENVELOPE_AUTH_DOMAIN: AuthenticationDomain =
    AuthenticationDomain::new(b"MACO\0pr-intake-envelope\0v1\0");
const PRODUCER_EFFECT_VERSION: u32 = 1;
const REPOSITORY_HMAC_SCHEME: &str = "repository_hmac_sha256_v1";

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

type BeforeIrreversibleLaunch<'a> =
    &'a mut dyn FnMut(&MergeAuditorLaneLaunchRequest) -> Result<(), MergeAuditorLaneProviderError>;

/// Provider-neutral launch seam. Implementations must launch at most the one
/// request supplied by [`handle_intake_event`].
pub trait MergeAuditorLaneProvider {
    fn launch(
        &mut self,
        request: &MergeAuditorLaneLaunchRequest,
    ) -> Result<MergeAuditorLaneLaunchReceipt, MergeAuditorLaneProviderError>;

    /// Callback-aware compatibility extension used by durable producers. The
    /// default records the start immediately before entering the legacy launch
    /// method; providers with a later exact process seam may override it.
    fn launch_with_persisted_start(
        &mut self,
        request: &MergeAuditorLaneLaunchRequest,
        before_irreversible_launch: &mut dyn FnMut(
            &MergeAuditorLaneLaunchRequest,
        )
            -> Result<(), MergeAuditorLaneProviderError>,
    ) -> Result<MergeAuditorLaneLaunchReceipt, MergeAuditorLaneProviderError> {
        before_irreversible_launch(request)?;
        self.launch(request)
    }
}

/// Production adapter into the existing Inbox independent-audit and
/// authenticated-publication pipeline. It performs a fresh provider scan for
/// the exact PR identity and head carried by the authenticated event.
struct InboxMergeAuditorLaneProvider {
    options: InboxRunOptions,
}

impl InboxMergeAuditorLaneProvider {
    fn launch_inbox(
        &mut self,
        request: &MergeAuditorLaneLaunchRequest,
        before_irreversible_launch: Option<BeforeIrreversibleLaunch<'_>>,
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
        let inbox_run_id = independent_auditor_run_id(
            &request.delivery_id,
            &request.event_id,
            &request.task.head_oid,
        );
        options.run_id = crate::orchestrator::RunId::new(inbox_run_id).map_err(|error| {
            MergeAuditorLaneProviderError::Failed {
                detail: bounded_detail(&format!("event run id was invalid: {error:#}")),
            }
        })?;
        let report = match before_irreversible_launch {
            Some(before_irreversible_launch) => {
                let expected_session_id = request.auditor_session_id.clone();
                let expected_selection = request.selection.clone();
                let mut start = |actual_session_id: &str,
                                 actual_selection: &InboxIndependentAuditorSelectionEvidence|
                 -> anyhow::Result<()> {
                    persist_bound_inbox_prelaunch_start(
                        request,
                        &expected_session_id,
                        &expected_selection,
                        actual_session_id,
                        actual_selection,
                        before_irreversible_launch,
                    )
                };
                run_inbox_for_pr_event(
                    options,
                    *number,
                    &request.task.head_oid,
                    &observed_task,
                    Some(&mut start),
                )
            }
            None => run_inbox_for_pr_event(
                options,
                *number,
                &request.task.head_oid,
                &observed_task,
                None,
            ),
        }
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

fn persist_bound_inbox_prelaunch_start(
    request: &MergeAuditorLaneLaunchRequest,
    expected_session_id: &str,
    expected_selection: &InboxIndependentAuditorSelectionEvidence,
    actual_session_id: &str,
    actual_selection: &InboxIndependentAuditorSelectionEvidence,
    before_irreversible_launch: &mut dyn FnMut(
        &MergeAuditorLaneLaunchRequest,
    ) -> Result<(), MergeAuditorLaneProviderError>,
) -> anyhow::Result<()> {
    if actual_session_id != expected_session_id {
        anyhow::bail!("Inbox derived an unexpected independent-auditor session identity");
    }
    if actual_selection != expected_selection {
        anyhow::bail!("Inbox prelaunch selection differed from the authenticated dispatch");
    }
    before_irreversible_launch(request).map_err(|error| {
        anyhow::anyhow!(
            "authenticated intake ledger refused auditor start: {}",
            provider_error_class(&error)
        )
    })
}

impl MergeAuditorLaneProvider for InboxMergeAuditorLaneProvider {
    fn launch(
        &mut self,
        request: &MergeAuditorLaneLaunchRequest,
    ) -> Result<MergeAuditorLaneLaunchReceipt, MergeAuditorLaneProviderError> {
        self.launch_inbox(request, None)
    }

    fn launch_with_persisted_start(
        &mut self,
        request: &MergeAuditorLaneLaunchRequest,
        before_irreversible_launch: &mut dyn FnMut(
            &MergeAuditorLaneLaunchRequest,
        )
            -> Result<(), MergeAuditorLaneProviderError>,
    ) -> Result<MergeAuditorLaneLaunchReceipt, MergeAuditorLaneProviderError> {
        self.launch_inbox(request, Some(before_irreversible_launch))
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PrIntakeProducerDisposition {
    Launched,
    Replayed,
    Refused,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PrIntakeReplayPhase {
    Started,
    Observed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PrIntakePersistenceOperation {
    OpenOrCreate,
    Read,
    Start,
    Observe,
    Complete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PrIntakeObservationFailureClass {
    ProviderUnavailable,
    MalformedProviderResponse,
    InvalidProviderGroundTruth,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(tag = "cause", rename_all = "snake_case")]
pub enum PrIntakeProducerRefusalCause {
    ProviderObservation {
        classification: PrIntakeObservationFailureClass,
        detail: String,
    },
    Authentication {
        failure: AuthenticationFailure,
    },
    ApprovedGithubActor {
        failure: InboxApprovedGithubActorFailure,
        detail: String,
    },
    CatalogUnavailable {
        detail: String,
    },
    IntakeRefused {
        refusal: PrIntakeRefusalCause,
    },
    ReplayAmbiguous {
        phase: PrIntakeReplayPhase,
    },
    PersistenceFailure {
        operation: PrIntakePersistenceOperation,
        detail: String,
    },
    ContractMismatch {
        detail: String,
    },
}

/// Durable production disposition for one provider-observed PR delivery.
/// Refusal is health-neutral to the separate repair queue, but never hidden.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PrIntakeProducerReport {
    pub version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repository: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub number: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delivery_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub logical_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effect_id: Option<String>,
    pub disposition: PrIntakeProducerDisposition,
    pub success: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub intake_report: Option<PrIntakeReport>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refusal: Option<PrIntakeProducerRefusalCause>,
    pub grants_merge_permission: bool,
    pub auto_merge_performed: bool,
}

impl PrIntakeProducerReport {
    pub(crate) fn provider_observation_refusal(
        repo: &Path,
        number: Option<u64>,
        classification: PrIntakeObservationFailureClass,
        detail: &str,
    ) -> Self {
        Self {
            version: PRODUCER_EFFECT_VERSION,
            repository: None,
            number,
            delivery_id: None,
            logical_id: None,
            effect_id: None,
            disposition: PrIntakeProducerDisposition::Refused,
            success: false,
            intake_report: None,
            refusal: Some(PrIntakeProducerRefusalCause::ProviderObservation {
                classification,
                detail: detail.to_string(),
            }),
            grants_merge_permission: false,
            auto_merge_performed: false,
        }
        .sanitized_for_repository(repo)
    }

    fn for_contract(contract: &PrIntakeEffectContract) -> Self {
        Self {
            version: PRODUCER_EFFECT_VERSION,
            repository: Some(contract.repository.clone()),
            number: Some(contract.number),
            delivery_id: Some(contract.delivery_id.clone()),
            logical_id: Some(contract.logical_id.clone()),
            effect_id: Some(contract.effect_id.clone()),
            disposition: PrIntakeProducerDisposition::Refused,
            success: false,
            intake_report: None,
            refusal: None,
            grants_merge_permission: false,
            auto_merge_performed: false,
        }
    }

    fn refuse(mut self, repo: &Path, cause: PrIntakeProducerRefusalCause) -> Self {
        self.disposition = PrIntakeProducerDisposition::Refused;
        self.success = false;
        self.refusal = Some(cause);
        self.grants_merge_permission = false;
        self.auto_merge_performed = false;
        self.sanitized_for_repository(repo)
    }

    fn sanitized_for_repository(mut self, repo: &Path) -> Self {
        if let Some(report) = &mut self.intake_report {
            sanitize_pr_intake_report(repo, report);
        }
        if let Some(refusal) = &mut self.refusal {
            sanitize_producer_refusal(repo, refusal);
        }
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PrIntakeEffectContract {
    version: u32,
    repository: String,
    number: u64,
    delivery_id: String,
    event_id: String,
    logical_id: String,
    effect_id: String,
    source_snapshot_digest: String,
    source_updated_at: String,
    head_oid: String,
    action_revision_digest: String,
    envelope_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PrIntakeEffectRecord {
    version: u32,
    contract: PrIntakeEffectContract,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    request: Option<MergeAuditorLaneLaunchRequest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    report: Option<PrIntakeReport>,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct IntakeEnvelopeAuthenticationPayload<'a> {
    version: u32,
    delivery_id: &'a str,
    scheme: &'a str,
    key_id: &'a str,
    payload_json: &'a str,
}

struct RepositoryIntakeAuthenticator {
    authenticator: RepositoryAuthenticator,
}

impl IntakeAuthenticator for RepositoryIntakeAuthenticator {
    fn authenticate(&self, envelope: &IntakeEventEnvelope) -> Result<(), AuthenticationFailure> {
        if envelope.authentication.scheme != REPOSITORY_HMAC_SCHEME
            || envelope.authentication.key_id != self.authenticator.binding().repository_id
        {
            return Err(AuthenticationFailure::Rejected {
                detail: "repository envelope authentication binding did not match".to_string(),
            });
        }
        let tag = AuthenticationTag::parse(&envelope.authentication.proof).map_err(|_| {
            AuthenticationFailure::Rejected {
                detail: "repository envelope authentication proof was malformed".to_string(),
            }
        })?;
        let payload = intake_envelope_authentication_bytes(envelope).map_err(|_| {
            AuthenticationFailure::VerifierUnavailable {
                detail: "repository envelope authentication payload was unavailable".to_string(),
            }
        })?;
        self.authenticator
            .verify_tag(INTAKE_ENVELOPE_AUTH_DOMAIN, &payload, &tag)
            .map_err(|_| AuthenticationFailure::Rejected {
                detail: "repository envelope authentication failed".to_string(),
            })
    }
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
    handle_intake_event_with_catalog_loader(envelope, authenticator, provider, None, None, || {
        CodexRuntimeModelCatalog::from_slugs(observed_available_model_slugs)
    })
}

fn handle_intake_event_with_catalog_loader<A, P, F>(
    envelope: &IntakeEventEnvelope,
    authenticator: &A,
    provider: &mut P,
    trusted_head_repository: Option<&str>,
    before_irreversible_launch: Option<BeforeIrreversibleLaunch<'_>>,
    load_catalog: F,
) -> PrIntakeReport
where
    A: IntakeAuthenticator,
    P: MergeAuditorLaneProvider,
    F: FnOnce() -> anyhow::Result<CodexRuntimeModelCatalog>,
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
    let mut normalized = match normalize_event(event) {
        Ok(normalized) => normalized,
        Err((event_id, event_kind, cause)) => {
            report.event_id = event_id.map(|value| bounded_detail(&value));
            report.event_kind = event_kind;
            return report.refuse(cause);
        }
    };
    if let Some(trusted_head_repository) = trusted_head_repository {
        if let Err(cause) = bind_trusted_head_repository(&mut normalized, trusted_head_repository) {
            report.event_id = Some(normalized.event_id.clone());
            report.event_kind = Some(event_kind_name(normalized.event_kind).to_string());
            return report.refuse(cause);
        }
    }
    report.event_id = Some(normalized.event_id.clone());
    report.event_kind = Some(event_kind_name(normalized.event_kind).to_string());
    report.task = Some(normalized.task.clone());

    let catalog = match load_catalog() {
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

    let inbox_run_id = independent_auditor_run_id(
        &envelope.delivery_id,
        &normalized.event_id,
        &normalized.task.head_oid,
    );
    let session_id = independent_auditor_session_id(&inbox_run_id);
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
    let launch_result = match before_irreversible_launch {
        Some(before_irreversible_launch) => {
            provider.launch_with_persisted_start(&request, before_irreversible_launch)
        }
        None => provider.launch(&request),
    };
    let receipt = match launch_result {
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

fn handle_intake_event_with_observed_catalog_and_start<A, P>(
    envelope: &IntakeEventEnvelope,
    observed_catalog: CodexRuntimeModelCatalog,
    authenticator: &A,
    provider: &mut P,
    trusted_head_repository: &str,
    before_irreversible_launch: &mut dyn FnMut(
        &MergeAuditorLaneLaunchRequest,
    ) -> Result<(), MergeAuditorLaneProviderError>,
) -> PrIntakeReport
where
    A: IntakeAuthenticator,
    P: MergeAuditorLaneProvider,
{
    handle_intake_event_with_catalog_loader(
        envelope,
        authenticator,
        provider,
        Some(trusted_head_repository),
        Some(before_irreversible_launch),
        || Ok(observed_catalog),
    )
}

trait GithubPrObservationProvider {
    fn observe_pull_request(&mut self, number: u64) -> Result<InboxItem, InboxPrObservationError>;
}

struct InboxGithubPrObservationProvider {
    options: InboxRunOptions,
}

impl GithubPrObservationProvider for InboxGithubPrObservationProvider {
    fn observe_pull_request(&mut self, number: u64) -> Result<InboxItem, InboxPrObservationError> {
        observe_inbox_pr_event(&self.options, number)
    }
}

trait ApprovedGithubActorPreflight {
    fn verify(&mut self, repo: &Path) -> Result<(), InboxApprovedGithubActorError>;
}

#[derive(Default)]
struct InboxApprovedGithubActorPreflight {
    binding: Option<InboxApprovedGithubActorBinding>,
}

impl ApprovedGithubActorPreflight for InboxApprovedGithubActorPreflight {
    fn verify(&mut self, repo: &Path) -> Result<(), InboxApprovedGithubActorError> {
        match &self.binding {
            Some(binding) => binding.verify_fresh(),
            None => {
                self.binding = Some(bind_approved_github_actor(repo)?);
                Ok(())
            }
        }
    }
}

#[cfg(test)]
type PrObservationError = InboxPrObservationError;

#[cfg(test)]
struct TestApprovedGithubActorPreflight;

#[cfg(test)]
impl ApprovedGithubActorPreflight for TestApprovedGithubActorPreflight {
    fn verify(&mut self, _repo: &Path) -> Result<(), InboxApprovedGithubActorError> {
        Ok(())
    }
}

fn producer_observation_classification(
    classification: InboxPrObservationFailureClass,
) -> PrIntakeObservationFailureClass {
    match classification {
        InboxPrObservationFailureClass::ProviderUnavailable => {
            PrIntakeObservationFailureClass::ProviderUnavailable
        }
        InboxPrObservationFailureClass::MalformedProviderResponse => {
            PrIntakeObservationFailureClass::MalformedProviderResponse
        }
        InboxPrObservationFailureClass::InvalidProviderGroundTruth => {
            PrIntakeObservationFailureClass::InvalidProviderGroundTruth
        }
    }
}

struct PreparedRepositoryPrIntake {
    contract: PrIntakeEffectContract,
    envelope: IntakeEventEnvelope,
    authenticator: RepositoryIntakeAuthenticator,
    trusted_head_repository: String,
}

/// Produce one durable repository-authenticated event from an exact
/// provider-observed GitHub PR number. The provider fields and model catalog
/// are both loaded internally through trusted production boundaries.
pub fn produce_repository_pr_intake(
    options: InboxRunOptions,
    number: u64,
) -> PrIntakeProducerReport {
    let repo = options.repo.clone();
    let program = options
        .codex_bin
        .clone()
        .unwrap_or_else(|| PathBuf::from("codex"));
    let mut observer = InboxGithubPrObservationProvider {
        options: options.clone(),
    };
    let mut actor_preflight = InboxApprovedGithubActorPreflight::default();
    let mut provider = InboxMergeAuditorLaneProvider { options };
    produce_repository_pr_intake_with_actor_preflight(
        &repo,
        number,
        &mut observer,
        &mut actor_preflight,
        || {
            load_codex_runtime_model_catalog(&program, &repo, PRODUCTION_CATALOG_TIMEOUT)
                .map_err(|failure| failure.summary)
        },
        &mut provider,
    )
}

#[cfg(test)]
fn produce_repository_pr_intake_with<O, P, F>(
    repo: &Path,
    number: u64,
    observer: &mut O,
    load_catalog: F,
    provider: &mut P,
) -> PrIntakeProducerReport
where
    O: GithubPrObservationProvider,
    P: MergeAuditorLaneProvider,
    F: FnOnce() -> Result<CodexRuntimeModelCatalog, String>,
{
    let mut actor_preflight = TestApprovedGithubActorPreflight;
    produce_repository_pr_intake_with_actor_preflight(
        repo,
        number,
        observer,
        &mut actor_preflight,
        load_catalog,
        provider,
    )
}

fn produce_repository_pr_intake_with_actor_preflight<O, A, P, F>(
    repo: &Path,
    number: u64,
    observer: &mut O,
    actor_preflight: &mut A,
    load_catalog: F,
    provider: &mut P,
) -> PrIntakeProducerReport
where
    O: GithubPrObservationProvider,
    A: ApprovedGithubActorPreflight,
    P: MergeAuditorLaneProvider,
    F: FnOnce() -> Result<CodexRuntimeModelCatalog, String>,
{
    let item = match observer.observe_pull_request(number) {
        Ok(item) => item,
        Err(error) => {
            return PrIntakeProducerReport::provider_observation_refusal(
                repo,
                Some(number),
                producer_observation_classification(error.classification),
                &error.detail,
            );
        }
    };
    if item.source_snapshot.number() != number
        || item
            .pull_request
            .as_ref()
            .is_none_or(|pull_request| pull_request.number != number)
    {
        return PrIntakeProducerReport::provider_observation_refusal(
            repo,
            Some(number),
            PrIntakeObservationFailureClass::InvalidProviderGroundTruth,
            "provider returned a different pull-request identity",
        );
    }
    let prepared = match prepare_repository_pr_intake(repo, &item) {
        Ok(prepared) => prepared,
        Err(error) => {
            return PrIntakeProducerReport::provider_observation_refusal(
                repo,
                Some(number),
                PrIntakeObservationFailureClass::InvalidProviderGroundTruth,
                &format!("{error:#}"),
            );
        }
    };
    produce_authenticated_pr_intake_with(repo, prepared, actor_preflight, load_catalog, provider)
}

fn prepare_repository_pr_intake(
    repo: &Path,
    item: &InboxItem,
) -> anyhow::Result<PreparedRepositoryPrIntake> {
    let (event, delivery_id, event_id, logical_id, effect_id, trusted_head_repository) =
        production_event_from_item(item)?;
    let (envelope, authenticator) = repository_authenticated_envelope(repo, delivery_id, &event)?;
    let source_snapshot = &item.source_snapshot;
    let head_oid = source_snapshot
        .head_oid()
        .ok_or_else(|| anyhow::anyhow!("GitHub PR observation omitted head OID"))?
        .to_string();
    let contract = PrIntakeEffectContract {
        version: PRODUCER_EFFECT_VERSION,
        repository: source_snapshot.repository_selector().to_string(),
        number: source_snapshot.number(),
        delivery_id: envelope.delivery_id.clone(),
        event_id,
        logical_id,
        effect_id,
        source_snapshot_digest: source_snapshot.digest().to_string(),
        source_updated_at: source_snapshot.updated_at().to_string(),
        head_oid,
        action_revision_digest: source_snapshot.action_revision_digest().to_string(),
        envelope_sha256: envelope_sha256(&envelope)?,
    };
    Ok(PreparedRepositoryPrIntake {
        contract,
        envelope,
        authenticator,
        trusted_head_repository,
    })
}

fn produce_authenticated_pr_intake_with<A, P, F>(
    repo: &Path,
    prepared: PreparedRepositoryPrIntake,
    actor_preflight: &mut A,
    load_catalog: F,
    provider: &mut P,
) -> PrIntakeProducerReport
where
    A: ApprovedGithubActorPreflight,
    P: MergeAuditorLaneProvider,
    F: FnOnce() -> Result<CodexRuntimeModelCatalog, String>,
{
    let PreparedRepositoryPrIntake {
        contract,
        envelope,
        authenticator,
        trusted_head_repository,
    } = prepared;
    let mut producer_report = PrIntakeProducerReport::for_contract(&contract);
    if let Err(failure) = authenticator.authenticate(&envelope) {
        return producer_report.refuse(
            repo,
            PrIntakeProducerRefusalCause::Authentication { failure },
        );
    }

    let planned = PrIntakeEffectRecord {
        version: PRODUCER_EFFECT_VERSION,
        contract: contract.clone(),
        request: None,
        report: None,
    };
    let mut wal = match EffectWal::open_or_create_planned(
        || repository_auth_writer(repo)?.into_authenticator(),
        &contract.logical_id,
        &contract.effect_id,
        &planned,
    ) {
        Ok(wal) => wal,
        Err(error) => {
            return producer_report.refuse(
                repo,
                PrIntakeProducerRefusalCause::PersistenceFailure {
                    operation: PrIntakePersistenceOperation::OpenOrCreate,
                    detail: bounded_detail(&format!("{error:#}")),
                },
            );
        }
    };
    let (phase, current) = match latest_pr_intake_effect_record(&wal, &contract.effect_id) {
        Ok(value) => value,
        Err(error) => {
            return producer_report.refuse(
                repo,
                PrIntakeProducerRefusalCause::PersistenceFailure {
                    operation: PrIntakePersistenceOperation::Read,
                    detail: bounded_detail(&format!("{error:#}")),
                },
            );
        }
    };
    if current.contract != contract {
        return producer_report.refuse(
            repo,
            PrIntakeProducerRefusalCause::ContractMismatch {
                detail:
                    "authenticated PR intake effect contract did not match the provider delivery"
                        .to_string(),
            },
        );
    }
    match phase {
        EffectPhase::Completed => {
            let Some(report) = current.report else {
                return producer_report.refuse(
                    repo,
                    PrIntakeProducerRefusalCause::PersistenceFailure {
                        operation: PrIntakePersistenceOperation::Read,
                        detail: "completed PR intake effect omitted its validated report"
                            .to_string(),
                    },
                );
            };
            producer_report.disposition = PrIntakeProducerDisposition::Replayed;
            producer_report.success = true;
            producer_report.auto_merge_performed = report.auto_merge_performed;
            producer_report.intake_report = Some(report);
            return producer_report.sanitized_for_repository(repo);
        }
        EffectPhase::Started => {
            return producer_report.refuse(
                repo,
                PrIntakeProducerRefusalCause::ReplayAmbiguous {
                    phase: PrIntakeReplayPhase::Started,
                },
            );
        }
        EffectPhase::Observed => {
            return producer_report.refuse(
                repo,
                PrIntakeProducerRefusalCause::ReplayAmbiguous {
                    phase: PrIntakeReplayPhase::Observed,
                },
            );
        }
        EffectPhase::Planned => {}
    }

    if let Err(error) = actor_preflight.verify(repo) {
        return producer_report.refuse(
            repo,
            PrIntakeProducerRefusalCause::ApprovedGithubActor {
                failure: error.failure,
                detail: bounded_detail(&error.detail),
            },
        );
    }

    let catalog = match load_catalog() {
        Ok(catalog) => catalog,
        Err(detail) => {
            return producer_report.refuse(
                repo,
                PrIntakeProducerRefusalCause::CatalogUnavailable {
                    detail: bounded_detail(&detail),
                },
            );
        }
    };
    let mut started_request = None;
    let mut start_failure = None;
    let mut actor_failure = None;
    let intake_report = {
        let mut start = |request: &MergeAuditorLaneLaunchRequest| {
            if let Err(error) = actor_preflight.verify(repo) {
                actor_failure = Some(error);
                return Err(MergeAuditorLaneProviderError::Refused {
                    detail: "approved GitHub actor binding changed before auditor launch"
                        .to_string(),
                });
            }
            let started = PrIntakeEffectRecord {
                version: PRODUCER_EFFECT_VERSION,
                contract: contract.clone(),
                request: Some(request.clone()),
                report: None,
            };
            if let Err(error) = validate_pr_intake_effect_record(EffectPhase::Started, &started) {
                let detail = bounded_detail(&format!("{error:#}"));
                start_failure = Some(detail);
                return Err(MergeAuditorLaneProviderError::Refused {
                    detail: "authenticated PR intake start contract was invalid".to_string(),
                });
            }
            if let Err(error) = wal.started(&contract.effect_id, &started) {
                let detail = bounded_detail(&format!("{error:#}"));
                start_failure = Some(detail);
                return Err(MergeAuditorLaneProviderError::Unavailable {
                    detail: "authenticated PR intake start could not be persisted".to_string(),
                });
            }
            started_request = Some(request.clone());
            Ok(())
        };
        handle_intake_event_with_observed_catalog_and_start(
            &envelope,
            catalog,
            &authenticator,
            provider,
            &trusted_head_repository,
            &mut start,
        )
    };
    if let Some(error) = actor_failure {
        producer_report.intake_report = Some(intake_report);
        return producer_report.refuse(
            repo,
            PrIntakeProducerRefusalCause::ApprovedGithubActor {
                failure: error.failure,
                detail: bounded_detail(&error.detail),
            },
        );
    }
    if let Some(detail) = start_failure {
        producer_report.intake_report = Some(intake_report);
        return producer_report.refuse(
            repo,
            PrIntakeProducerRefusalCause::PersistenceFailure {
                operation: PrIntakePersistenceOperation::Start,
                detail,
            },
        );
    }
    if !intake_report.success {
        let refusal =
            intake_report
                .refusal
                .clone()
                .unwrap_or(PrIntakeRefusalCause::InvalidReceipt {
                    field: "missing_refusal".to_string(),
                });
        producer_report.intake_report = Some(intake_report);
        return producer_report.refuse(
            repo,
            PrIntakeProducerRefusalCause::IntakeRefused { refusal },
        );
    }
    let Some(request) = started_request else {
        producer_report.intake_report = Some(intake_report);
        return producer_report.refuse(
            repo,
            PrIntakeProducerRefusalCause::ContractMismatch {
                detail: "successful PR intake omitted its durable launch start".to_string(),
            },
        );
    };
    let observed = PrIntakeEffectRecord {
        version: PRODUCER_EFFECT_VERSION,
        contract: contract.clone(),
        request: Some(request),
        report: Some(intake_report.clone()),
    };
    if let Err(error) = validate_pr_intake_effect_record(EffectPhase::Observed, &observed) {
        producer_report.intake_report = Some(intake_report);
        return producer_report.refuse(
            repo,
            PrIntakeProducerRefusalCause::ContractMismatch {
                detail: bounded_detail(&format!("{error:#}")),
            },
        );
    }
    if let Err(error) = wal.observed(&contract.effect_id, &observed) {
        producer_report.intake_report = Some(intake_report);
        return producer_report.refuse(
            repo,
            PrIntakeProducerRefusalCause::PersistenceFailure {
                operation: PrIntakePersistenceOperation::Observe,
                detail: bounded_detail(&format!("{error:#}")),
            },
        );
    }
    if let Err(error) = wal.completed(&contract.effect_id, &observed) {
        producer_report.intake_report = Some(intake_report);
        return producer_report.refuse(
            repo,
            PrIntakeProducerRefusalCause::PersistenceFailure {
                operation: PrIntakePersistenceOperation::Complete,
                detail: bounded_detail(&format!("{error:#}")),
            },
        );
    }
    producer_report.disposition = PrIntakeProducerDisposition::Launched;
    producer_report.success = true;
    producer_report.auto_merge_performed = intake_report.auto_merge_performed;
    producer_report.intake_report = Some(intake_report);
    producer_report.sanitized_for_repository(repo)
}

type ProductionEventParts = (IntakeEvent, String, String, String, String, String);

fn production_event_from_item(item: &InboxItem) -> anyhow::Result<ProductionEventParts> {
    item.source_snapshot.validate()?;
    if item.kind != InboxItemKind::PullRequest
        || item.source_snapshot.kind() != InboxItemKind::PullRequest
        || item.source_snapshot.provider() != InboxSourceProvider::Github
    {
        anyhow::bail!("production PR intake requires a GitHub pull-request observation");
    }
    let pull_request = item
        .pull_request
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("GitHub PR observation omitted pull-request evidence"))?;
    if pull_request.number != item.source_snapshot.number()
        || item.source_key != item.source_snapshot.source_key()
    {
        anyhow::bail!("GitHub PR observation identity fields did not agree");
    }
    if !item.privacy.safe || !item.selected || item.skip_reason.is_some() {
        anyhow::bail!("GitHub PR observation was not an eligible provider listing item");
    }
    if pull_request.updated_at.as_deref() != Some(item.source_snapshot.updated_at()) {
        anyhow::bail!("GitHub PR observation updated-at fields did not agree");
    }
    let head_repository = pull_request
        .head_repository
        .as_deref()
        .filter(|repository| !repository.trim().is_empty())
        .ok_or_else(|| anyhow::anyhow!("GitHub PR observation omitted head repository"))?;
    let target_repository = canonical_github_target_repository(&item.source_snapshot)?;
    if pull_request.source_trust == GithubPrSourceTrust::TrustedTargetRepository
        && head_repository != target_repository
    {
        anyhow::bail!("trusted GitHub PR head repository differed from the target repository");
    }
    let head_oid = item
        .source_snapshot
        .head_oid()
        .ok_or_else(|| anyhow::anyhow!("GitHub PR observation omitted head OID"))?;
    let base_oid = item
        .source_snapshot
        .base_oid()
        .ok_or_else(|| anyhow::anyhow!("GitHub PR observation omitted base OID"))?;
    let delivery_material = serde_json::to_vec(&(
        "maco_github_pr_delivery_v1",
        item.source_snapshot.repository_selector(),
        pull_request.number,
        head_oid,
        item.source_snapshot.updated_at(),
        item.source_snapshot.action_revision_digest(),
        item.source_snapshot.digest(),
    ))?;
    let delivery_digest = crate::artifacts::state_auth::sha256_hex(&delivery_material);
    let delivery_id = format!("github-pr-{delivery_digest}");
    let event_id = format!("github-pr-event-{delivery_digest}");
    let logical_material = format!(
        "{}\0{}",
        item.source_snapshot.repository_selector(),
        pull_request.number
    );
    let logical_id = format!(
        "pr-intake-{}",
        crate::artifacts::state_auth::sha256_hex(logical_material.as_bytes())
    );
    let effect_id = format!("pr-delivery-{delivery_digest}");
    let event = IntakeEvent::PullRequest(PullRequestIntakeEvent {
        number: pull_request.number,
        repository: item.source_snapshot.repository_selector().to_string(),
        is_draft: pull_request.is_draft,
        source_trust: pull_request.source_trust,
        evidence: IntakeCandidateEvidence {
            event_id: event_id.clone(),
            source_snapshot_digest: item.source_snapshot.digest().to_string(),
            source_updated_at: item.source_snapshot.updated_at().to_string(),
            producer_identity: pull_request.author.clone().unwrap_or_default(),
            expected_head_oid: head_oid.to_string(),
            observed_head_oid: head_oid.to_string(),
            base_oid: base_oid.to_string(),
            changed_paths: pull_request.changed_files.clone(),
            checks: pull_request.checks.clone(),
        },
    });
    Ok((
        event,
        delivery_id,
        event_id,
        logical_id,
        effect_id,
        target_repository,
    ))
}

fn canonical_github_target_repository(
    snapshot: &crate::inbox::InboxSourceSnapshotBinding,
) -> anyhow::Result<String> {
    let prefix = format!("{}/", snapshot.repository_host());
    let repository = snapshot
        .repository_selector()
        .strip_prefix(&prefix)
        .ok_or_else(|| anyhow::anyhow!("GitHub repository selector did not match its host"))?;
    let mut parts = repository.split('/');
    let owner = parts.next();
    let name = parts.next();
    if owner.is_none()
        || name.is_none()
        || parts.next().is_some()
        || owner.is_some_and(str::is_empty)
        || name.is_some_and(str::is_empty)
    {
        anyhow::bail!("GitHub repository selector did not contain canonical owner/name");
    }
    Ok(repository.to_ascii_lowercase())
}

fn repository_authenticated_envelope(
    repo: &Path,
    delivery_id: String,
    event: &IntakeEvent,
) -> anyhow::Result<(IntakeEventEnvelope, RepositoryIntakeAuthenticator)> {
    let authenticator = repository_auth_writer(repo)?
        .into_authenticator()
        .context("failed to bind repository PR intake authentication")?;
    let key_id = authenticator.binding().repository_id.clone();
    let mut envelope = IntakeEventEnvelope {
        version: INTAKE_VERSION,
        delivery_id,
        authentication: IntakeAuthentication {
            scheme: REPOSITORY_HMAC_SCHEME.to_string(),
            key_id,
            proof: String::new(),
        },
        payload_json: serde_json::to_string(event)?,
    };
    let payload = intake_envelope_authentication_bytes(&envelope)?;
    envelope.authentication.proof = authenticator
        .sign(INTAKE_ENVELOPE_AUTH_DOMAIN, &payload)?
        .as_str()
        .to_string();
    Ok((envelope, RepositoryIntakeAuthenticator { authenticator }))
}

fn intake_envelope_authentication_bytes(envelope: &IntakeEventEnvelope) -> anyhow::Result<Vec<u8>> {
    serde_json::to_vec(&IntakeEnvelopeAuthenticationPayload {
        version: envelope.version,
        delivery_id: &envelope.delivery_id,
        scheme: &envelope.authentication.scheme,
        key_id: &envelope.authentication.key_id,
        payload_json: &envelope.payload_json,
    })
    .context("failed to serialize PR intake authentication payload")
}

fn envelope_sha256(envelope: &IntakeEventEnvelope) -> anyhow::Result<String> {
    let bytes = serde_json::to_vec(envelope).context("failed to serialize PR intake envelope")?;
    Ok(crate::artifacts::state_auth::sha256_hex(&bytes))
}

fn latest_pr_intake_effect_record(
    wal: &EffectWal,
    effect_id: &str,
) -> anyhow::Result<(EffectPhase, PrIntakeEffectRecord)> {
    let phase = wal
        .phase(effect_id)
        .ok_or_else(|| anyhow::anyhow!("authenticated PR intake WAL omitted its effect"))?;
    let event = wal
        .events()
        .iter()
        .rev()
        .find(|event| event.effect_id == effect_id)
        .ok_or_else(|| anyhow::anyhow!("authenticated PR intake WAL omitted its latest event"))?;
    let record: PrIntakeEffectRecord = serde_json::from_value(event.data.clone())
        .context("authenticated PR intake WAL payload was malformed")?;
    if event.phase != phase {
        anyhow::bail!("authenticated PR intake WAL phase did not match its latest event");
    }
    validate_pr_intake_effect_record(phase, &record)?;
    Ok((phase, record))
}

fn validate_pr_intake_effect_record(
    phase: EffectPhase,
    record: &PrIntakeEffectRecord,
) -> anyhow::Result<()> {
    if record.version != PRODUCER_EFFECT_VERSION
        || record.contract.version != PRODUCER_EFFECT_VERSION
    {
        anyhow::bail!("authenticated PR intake WAL version was unsupported");
    }
    validate_identifier("delivery_id", &record.contract.delivery_id)
        .map_err(|_| anyhow::anyhow!("authenticated PR intake delivery id was invalid"))?;
    validate_identifier("event_id", &record.contract.event_id)
        .map_err(|_| anyhow::anyhow!("authenticated PR intake event id was invalid"))?;
    validate_source_snapshot_digest(&record.contract.source_snapshot_digest)
        .map_err(|_| anyhow::anyhow!("authenticated PR intake snapshot digest was invalid"))?;
    validate_digest("envelope_sha256", &record.contract.envelope_sha256)
        .map_err(|_| anyhow::anyhow!("authenticated PR intake envelope digest was invalid"))?;
    validate_oid("head_oid", &record.contract.head_oid)
        .map_err(|_| anyhow::anyhow!("authenticated PR intake head OID was invalid"))?;
    match phase {
        EffectPhase::Planned if record.request.is_none() && record.report.is_none() => Ok(()),
        EffectPhase::Started if record.request.is_some() && record.report.is_none() => Ok(()),
        EffectPhase::Observed | EffectPhase::Completed => {
            let request = record.request.as_ref().ok_or_else(|| {
                anyhow::anyhow!("completed PR intake WAL omitted its launch request")
            })?;
            let report = record.report.as_ref().ok_or_else(|| {
                anyhow::anyhow!("completed PR intake WAL omitted its validated report")
            })?;
            let receipt = report.launch_receipt.as_ref().ok_or_else(|| {
                anyhow::anyhow!("completed PR intake WAL omitted its validated receipt")
            })?;
            if !report.success
                || report.refusal.is_some()
                || report.delivery_id != record.contract.delivery_id
                || report.event_id.as_deref() != Some(record.contract.event_id.as_str())
                || invalid_receipt_field(request, receipt).is_some()
            {
                anyhow::bail!("completed PR intake WAL report failed strict receipt validation");
            }
            Ok(())
        }
        _ => anyhow::bail!("authenticated PR intake WAL payload did not match its durable phase"),
    }
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

fn bind_trusted_head_repository(
    normalized: &mut NormalizedIntake,
    trusted_head_repository: &str,
) -> Result<(), PrIntakeRefusalCause> {
    validate_identifier("head_repository", trusted_head_repository)?;
    let mut trusted_parts = trusted_head_repository.split('/');
    let trusted_is_canonical = matches!(
        (
            trusted_parts.next(),
            trusted_parts.next(),
            trusted_parts.next()
        ),
        (Some(owner), Some(name), None) if !owner.is_empty() && !name.is_empty()
    );
    if !trusted_is_canonical {
        return Err(invalid_evidence(
            "head_repository",
            "trusted head repository must be canonical owner/name",
        ));
    }
    let IntakeCandidateIdentity::PullRequest { repository, .. } = &normalized.candidate else {
        return Err(invalid_evidence(
            "head_repository",
            "trusted head repository binding is PR-only",
        ));
    };
    let mut target_parts = repository.split('/');
    let target_matches = match (
        target_parts.next(),
        target_parts.next(),
        target_parts.next(),
        target_parts.next(),
    ) {
        (Some(host), Some(owner), Some(name), None) => {
            !host.is_empty()
                && !owner.is_empty()
                && !name.is_empty()
                && format!("{owner}/{name}").eq_ignore_ascii_case(trusted_head_repository)
        }
        _ => false,
    };
    if !target_matches {
        return Err(invalid_evidence(
            "head_repository",
            "trusted head repository did not match the target selector",
        ));
    }
    normalized.task.head_repository = Some(trusted_head_repository.to_string());
    Ok(())
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
    validate_source_snapshot_digest(&evidence.source_snapshot_digest)?;
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

fn validate_source_snapshot_digest(value: &str) -> Result<(), PrIntakeRefusalCause> {
    if value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Ok(());
    }
    let valid_checksum = value
        .strip_prefix("maco-v1-")
        .and_then(|rest| rest.split_once('-'))
        .is_some_and(|(checksum, length)| {
            checksum.len() == 32
                && checksum
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
                && !length.is_empty()
                && length.len() <= 20
                && length.bytes().all(|byte| byte.is_ascii_digit())
        });
    if valid_checksum {
        Ok(())
    } else {
        Err(invalid_evidence(
            "source_snapshot_digest",
            "snapshot digest must be SHA-256 or a canonical Inbox checksum",
        ))
    }
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

fn independent_auditor_run_id(delivery_id: &str, event_id: &str, head_oid: &str) -> String {
    let material = format!("{delivery_id}\0{event_id}\0{head_oid}");
    let digest = crate::artifacts::state_auth::sha256_hex(material.as_bytes());
    format!("pr-intake-{}", &digest[..24])
}

fn independent_auditor_session_id(inbox_run_id: &str) -> String {
    format!("{inbox_run_id}-item-1-auditor")
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

fn sanitize_authentication_failure(repo: &Path, failure: &mut AuthenticationFailure) {
    let detail = match failure {
        AuthenticationFailure::Rejected { detail }
        | AuthenticationFailure::VerifierUnavailable { detail } => detail,
    };
    *detail = sanitize_pr_intake_provider_detail(repo, detail);
}

fn sanitize_provider_error(repo: &Path, error: &mut MergeAuditorLaneProviderError) {
    let detail = match error {
        MergeAuditorLaneProviderError::Unavailable { detail }
        | MergeAuditorLaneProviderError::Refused { detail }
        | MergeAuditorLaneProviderError::Failed { detail } => detail,
    };
    *detail = sanitize_pr_intake_provider_detail(repo, detail);
}

fn sanitize_intake_refusal(repo: &Path, refusal: &mut PrIntakeRefusalCause) {
    match refusal {
        PrIntakeRefusalCause::Unauthenticated { failure } => {
            sanitize_authentication_failure(repo, failure);
        }
        PrIntakeRefusalCause::InvalidEnvelope { detail, .. }
        | PrIntakeRefusalCause::MalformedEvent { detail }
        | PrIntakeRefusalCause::InvalidGateEvidence { detail, .. }
        | PrIntakeRefusalCause::SelectionFailure { detail } => {
            *detail = sanitize_pr_intake_provider_detail(repo, detail);
        }
        PrIntakeRefusalCause::ProviderLaunchFailure { error } => {
            sanitize_provider_error(repo, error);
        }
        PrIntakeRefusalCause::UnknownEvent { .. }
        | PrIntakeRefusalCause::DraftPullRequest
        | PrIntakeRefusalCause::UntrustedSource { .. }
        | PrIntakeRefusalCause::StaleHead { .. }
        | PrIntakeRefusalCause::MissingChangedPaths
        | PrIntakeRefusalCause::MissingCiEvidence
        | PrIntakeRefusalCause::CiNotGreen { .. }
        | PrIntakeRefusalCause::IndependenceConflict { .. }
        | PrIntakeRefusalCause::InvalidReceipt { .. } => {}
    }
}

fn sanitize_pr_intake_report(repo: &Path, report: &mut PrIntakeReport) {
    if let Some(refusal) = &mut report.refusal {
        sanitize_intake_refusal(repo, refusal);
    }
}

fn sanitize_producer_refusal(repo: &Path, refusal: &mut PrIntakeProducerRefusalCause) {
    match refusal {
        PrIntakeProducerRefusalCause::ProviderObservation { detail, .. }
        | PrIntakeProducerRefusalCause::ApprovedGithubActor { detail, .. }
        | PrIntakeProducerRefusalCause::CatalogUnavailable { detail }
        | PrIntakeProducerRefusalCause::PersistenceFailure { detail, .. }
        | PrIntakeProducerRefusalCause::ContractMismatch { detail } => {
            *detail = sanitize_pr_intake_provider_detail(repo, detail);
        }
        PrIntakeProducerRefusalCause::Authentication { failure } => {
            sanitize_authentication_failure(repo, failure);
        }
        PrIntakeProducerRefusalCause::IntakeRefused { refusal } => {
            sanitize_intake_refusal(repo, refusal);
        }
        PrIntakeProducerRefusalCause::ReplayAmbiguous { .. } => {}
    }
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

fn provider_error_class(error: &MergeAuditorLaneProviderError) -> &'static str {
    match error {
        MergeAuditorLaneProviderError::Unavailable { .. } => "unavailable",
        MergeAuditorLaneProviderError::Refused { .. } => "refused",
        MergeAuditorLaneProviderError::Failed { .. } => "failed",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inbox::{
        DuplicateDetectionResult, GithubPrCandidate, GithubReviewFeedbackSummary,
        InboxSourceSnapshotBinding, PrivacyScanResult,
    };
    use crate::llm::RedactionSummary;
    use crate::supervise::{AgentRole, ModelCapabilityClass, OrchestrationPhase};
    use git2::Repository;
    use std::cell::Cell;
    use tempfile::TempDir;

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
        failure_detail: Option<String>,
    }

    #[derive(Clone)]
    struct FakeObservationProvider {
        result: Result<InboxItem, PrObservationError>,
        calls: usize,
    }

    impl FakeObservationProvider {
        fn returning(item: InboxItem) -> Self {
            Self {
                result: Ok(item),
                calls: 0,
            }
        }

        fn refusing(classification: InboxPrObservationFailureClass, detail: &str) -> Self {
            Self {
                result: Err(PrObservationError {
                    classification,
                    detail: detail.to_string(),
                }),
                calls: 0,
            }
        }
    }

    struct InjectedActorPreflight {
        actor_result: Result<String, InboxApprovedGithubActorError>,
        binding: Option<InboxApprovedGithubActorBinding>,
        change_pin_before_start: bool,
    }

    impl InjectedActorPreflight {
        fn actor(login: &str) -> Self {
            Self {
                actor_result: Ok(login.to_string()),
                binding: None,
                change_pin_before_start: false,
            }
        }

        fn unavailable() -> Self {
            Self {
                actor_result: Err(InboxApprovedGithubActorError {
                    failure: InboxApprovedGithubActorFailure::ActorUnavailable,
                    detail: "injected actor lookup unavailable".to_string(),
                }),
                binding: None,
                change_pin_before_start: false,
            }
        }

        fn changing_pin(login: &str) -> Self {
            Self {
                actor_result: Ok(login.to_string()),
                binding: None,
                change_pin_before_start: true,
            }
        }
    }

    impl ApprovedGithubActorPreflight for InjectedActorPreflight {
        fn verify(&mut self, repo: &Path) -> Result<(), InboxApprovedGithubActorError> {
            if let Some(binding) = &self.binding {
                if self.change_pin_before_start {
                    set_approved_github_login(repo, "changed-publication-owner");
                    self.change_pin_before_start = false;
                }
                return binding.verify_fresh();
            }
            let actor_result = self.actor_result.clone();
            self.binding = Some(crate::inbox::bind_approved_github_actor_with(repo, || {
                actor_result
            })?);
            Ok(())
        }
    }

    impl GithubPrObservationProvider for FakeObservationProvider {
        fn observe_pull_request(&mut self, _number: u64) -> Result<InboxItem, PrObservationError> {
            self.calls += 1;
            self.result.clone()
        }
    }

    impl MergeAuditorLaneProvider for FakeProvider {
        fn launch(
            &mut self,
            request: &MergeAuditorLaneLaunchRequest,
        ) -> Result<MergeAuditorLaneLaunchReceipt, MergeAuditorLaneProviderError> {
            self.requests.push(request.clone());
            if self.fail {
                return Err(MergeAuditorLaneProviderError::Failed {
                    detail: self
                        .failure_detail
                        .clone()
                        .unwrap_or_else(|| "deterministic_failure".to_string()),
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

    fn loaded_sol_catalog() -> Result<CodexRuntimeModelCatalog, String> {
        CodexRuntimeModelCatalog::from_slugs(sol_catalog()).map_err(|error| error.to_string())
    }

    fn repository() -> (TempDir, PathBuf) {
        let temp = TempDir::new().expect("tempdir");
        let path = temp.path().join("repo");
        Repository::init(&path).expect("repository");
        (temp, path)
    }

    fn set_approved_github_login(repo: &Path, login: &str) {
        Repository::open(repo)
            .expect("open repository")
            .config()
            .expect("open repository config")
            .set_str("agentFiles.approvedGitHubLogin", login)
            .expect("set approved GitHub login");
    }

    fn append_approved_github_login(repo: &Path, login: &str) {
        use std::io::Write as _;

        let config_path = Repository::open(repo)
            .expect("open repository")
            .commondir()
            .join("config");
        let mut config = std::fs::OpenOptions::new()
            .append(true)
            .open(config_path)
            .expect("open repository config for append");
        writeln!(config, "\n[agentFiles]\n\tapprovedGitHubLogin = {login}")
            .expect("append approved GitHub login");
    }

    fn assert_pr_intake_wal_phase(repo: &Path, item: &InboxItem, expected: EffectPhase) {
        let prepared = prepare_repository_pr_intake(repo, item).expect("prepare effect identity");
        let authenticator = repository_auth_writer(repo)
            .expect("repository auth writer")
            .into_authenticator()
            .expect("repository authenticator");
        let wal: EffectWal = EffectWal::open_instance(authenticator, &prepared.contract.logical_id)
            .expect("open PR intake WAL");
        assert_eq!(wal.phase(&prepared.contract.effect_id), Some(expected));
    }

    fn produce_with_injected_actor(
        repo: &Path,
        item: InboxItem,
        actor_preflight: &mut InjectedActorPreflight,
        provider: &mut FakeProvider,
    ) -> PrIntakeProducerReport {
        let mut observer = FakeObservationProvider::returning(item);
        produce_repository_pr_intake_with_actor_preflight(
            repo,
            17,
            &mut observer,
            actor_preflight,
            loaded_sol_catalog,
            provider,
        )
    }

    fn provider_pr_item() -> InboxItem {
        provider_pr_item_version(
            "2026-09-03T00:00:00Z",
            &"b".repeat(40),
            &"d".repeat(64),
            &"e".repeat(64),
        )
    }

    fn provider_pr_item_version(
        updated_at: &str,
        head_oid: &str,
        content_digest: &str,
        action_revision_digest: &str,
    ) -> InboxItem {
        let snapshot = InboxSourceSnapshotBinding::for_pull_request(
            InboxSourceProvider::Github,
            "github.com",
            "github.com/acme/repo",
            "f".repeat(64),
            17,
            updated_at,
            "OPEN",
            head_oid.to_string(),
            "c".repeat(40),
            content_digest,
            action_revision_digest,
        )
        .expect("provider snapshot");
        InboxItem {
            item_id: "github-pr-17".to_string(),
            source_key: snapshot.source_key().to_string(),
            source_snapshot: snapshot,
            kind: InboxItemKind::PullRequest,
            title: "Provider observed PR".to_string(),
            url: Some("https://github.com/acme/repo/pull/17".to_string()),
            issue: None,
            pull_request: Some(GithubPrCandidate {
                number: 17,
                title: "Provider observed PR".to_string(),
                url: Some("https://github.com/acme/repo/pull/17".to_string()),
                author: Some("producer".to_string()),
                labels: Vec::new(),
                updated_at: Some(updated_at.to_string()),
                head_ref: Some("feature/provider-intake".to_string()),
                base_ref: Some("main".to_string()),
                is_draft: false,
                source_trust: GithubPrSourceTrust::TrustedTargetRepository,
                head_repository: Some("acme/repo".to_string()),
                changed_files: vec![PathBuf::from("src/lib.rs")],
                checks: vec![green_check()],
                review_feedback: GithubReviewFeedbackSummary::default(),
                body_summary: "Ready for audit".to_string(),
                body_truncated: false,
            }),
            privacy: PrivacyScanResult {
                safe: true,
                reasons: Vec::new(),
                redactions: RedactionSummary::default(),
                body_summary: "Ready for audit".to_string(),
                body_truncated: false,
            },
            duplicate: DuplicateDetectionResult {
                duplicate: false,
                key: "github_pr:17".to_string(),
                matched_run_id: None,
                reason: None,
            },
            selected: true,
            skip_reason: None,
        }
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
    fn provider_observation_produces_authenticated_bound_launch_and_completed_replay() {
        let (_temp, repo) = repository();
        let item = provider_pr_item();
        let prepared = prepare_repository_pr_intake(&repo, &item).expect("prepared intake");
        prepared
            .authenticator
            .authenticate(&prepared.envelope)
            .expect("repository-authenticated envelope");
        let event: IntakeEvent =
            serde_json::from_str(&prepared.envelope.payload_json).expect("authenticated event");
        let IntakeEvent::PullRequest(event) = event else {
            panic!("provider must produce a PR event")
        };
        assert_eq!(event.repository, "github.com/acme/repo");

        let mut observer = FakeObservationProvider::returning(item);
        let mut provider = FakeProvider::default();
        let first = produce_repository_pr_intake_with(
            &repo,
            17,
            &mut observer,
            loaded_sol_catalog,
            &mut provider,
        );

        assert!(first.success, "{first:#?}");
        assert_eq!(first.disposition, PrIntakeProducerDisposition::Launched);
        assert_eq!(first.repository.as_deref(), Some("github.com/acme/repo"));
        assert_eq!(provider.requests.len(), 1);
        let request = &provider.requests[0];
        assert_eq!(
            request.candidate,
            IntakeCandidateIdentity::PullRequest {
                repository: "github.com/acme/repo".to_string(),
                number: 17,
            }
        );
        assert_eq!(request.task.head_repository.as_deref(), Some("acme/repo"));
        assert_eq!(request.selection.model, "gpt-5.6-sol");
        assert_eq!(request.selection.effort, ReasoningEffort::Xhigh);

        let replay = produce_repository_pr_intake_with(
            &repo,
            17,
            &mut observer,
            loaded_sol_catalog,
            &mut provider,
        );
        assert!(replay.success);
        assert_eq!(replay.disposition, PrIntakeProducerDisposition::Replayed);
        assert_eq!(
            provider.requests.len(),
            1,
            "completed replay must not launch"
        );
        assert_eq!(
            observer.calls, 2,
            "each delivery is re-observed at provider"
        );
    }

    #[test]
    fn updated_timestamp_and_head_create_distinct_effects_and_launch_once_each() {
        let (_temp, repo) = repository();
        let deliveries = [
            provider_pr_item_version(
                "2026-09-03T00:00:00Z",
                &"b".repeat(40),
                &"d".repeat(64),
                &"e".repeat(64),
            ),
            provider_pr_item_version(
                "2026-09-03T00:00:01Z",
                &"b".repeat(40),
                &"d".repeat(64),
                &"e".repeat(64),
            ),
            provider_pr_item_version(
                "2026-09-03T00:00:01Z",
                &"a".repeat(40),
                &"d".repeat(64),
                &"e".repeat(64),
            ),
        ];
        let mut provider = FakeProvider::default();
        let mut reports = Vec::new();
        for item in deliveries {
            let mut observer = FakeObservationProvider::returning(item);
            reports.push(produce_repository_pr_intake_with(
                &repo,
                17,
                &mut observer,
                loaded_sol_catalog,
                &mut provider,
            ));
        }

        assert_eq!(
            provider.requests.len(),
            3,
            "each changed delivery launches once"
        );
        assert!(reports.iter().all(|report| {
            report.success && report.disposition == PrIntakeProducerDisposition::Launched
        }));
        assert_eq!(
            reports
                .iter()
                .filter_map(|report| report.delivery_id.as_ref())
                .collect::<BTreeSet<_>>()
                .len(),
            3,
            "updated_at and head changes must create distinct deliveries"
        );
        assert_eq!(
            reports
                .iter()
                .filter_map(|report| report.effect_id.as_ref())
                .collect::<BTreeSet<_>>()
                .len(),
            3,
            "updated_at and head changes must create distinct effects"
        );
    }

    #[test]
    fn contributor_pr_launches_with_matching_injected_publication_actor() {
        let (_temp, repo) = repository();
        set_approved_github_login(&repo, "publication-owner");
        let mut item = provider_pr_item();
        item.pull_request.as_mut().expect("PR evidence").author =
            Some("external-contributor".to_string());
        let mut actor = InjectedActorPreflight::actor("publication-owner");
        let mut provider = FakeProvider::default();

        let report = produce_with_injected_actor(&repo, item, &mut actor, &mut provider);

        assert!(report.success, "{report:#?}");
        assert_eq!(provider.requests.len(), 1);
        assert_eq!(
            provider.requests[0].task.producer_login,
            "external-contributor"
        );
        assert_ne!(
            provider.requests[0].task.producer_login, "publication-owner",
            "PR authors must not be required to match the publication actor"
        );
    }

    #[test]
    fn missing_or_ambiguous_actor_pin_refuses_before_start_or_launch() {
        for ambiguous in [false, true] {
            let (_temp, repo) = repository();
            if ambiguous {
                set_approved_github_login(&repo, "publication-owner");
                append_approved_github_login(&repo, "second-owner");
            }
            let item = provider_pr_item();
            let mut actor = InjectedActorPreflight::actor("publication-owner");
            let mut provider = FakeProvider::default();

            let report =
                produce_with_injected_actor(&repo, item.clone(), &mut actor, &mut provider);

            assert!(matches!(
                report.refusal,
                Some(PrIntakeProducerRefusalCause::ApprovedGithubActor {
                    failure: InboxApprovedGithubActorFailure::MissingOrAmbiguousPin,
                    ..
                })
            ));
            assert!(provider.requests.is_empty());
            assert_pr_intake_wal_phase(&repo, &item, EffectPhase::Planned);
        }
    }

    #[test]
    fn wrong_actor_refuses_before_start_or_launch() {
        let (_temp, repo) = repository();
        set_approved_github_login(&repo, "publication-owner");
        let item = provider_pr_item();
        let mut actor = InjectedActorPreflight::actor("different-owner");
        let mut provider = FakeProvider::default();

        let report = produce_with_injected_actor(&repo, item.clone(), &mut actor, &mut provider);

        assert!(matches!(
            report.refusal,
            Some(PrIntakeProducerRefusalCause::ApprovedGithubActor {
                failure: InboxApprovedGithubActorFailure::PinMismatch,
                ..
            })
        ));
        assert!(provider.requests.is_empty());
        assert_pr_intake_wal_phase(&repo, &item, EffectPhase::Planned);
    }

    #[test]
    fn malformed_or_unavailable_actor_refuses_before_start_or_launch() {
        for mut actor in [
            InjectedActorPreflight::actor("malformed\nactor"),
            InjectedActorPreflight::unavailable(),
        ] {
            let (_temp, repo) = repository();
            set_approved_github_login(&repo, "publication-owner");
            let item = provider_pr_item();
            let mut provider = FakeProvider::default();

            let report =
                produce_with_injected_actor(&repo, item.clone(), &mut actor, &mut provider);

            assert!(matches!(
                report.refusal,
                Some(PrIntakeProducerRefusalCause::ApprovedGithubActor {
                    failure: InboxApprovedGithubActorFailure::MalformedActorResponse
                        | InboxApprovedGithubActorFailure::ActorUnavailable,
                    ..
                })
            ));
            assert!(provider.requests.is_empty());
            assert_pr_intake_wal_phase(&repo, &item, EffectPhase::Planned);
        }
    }

    #[test]
    fn actor_binding_change_at_exact_start_refuses_without_launch_or_wal_start() {
        let (_temp, repo) = repository();
        set_approved_github_login(&repo, "publication-owner");
        let item = provider_pr_item();
        let mut actor = InjectedActorPreflight::changing_pin("publication-owner");
        let mut provider = FakeProvider::default();

        let report = produce_with_injected_actor(&repo, item.clone(), &mut actor, &mut provider);

        assert!(matches!(
            report.refusal,
            Some(PrIntakeProducerRefusalCause::ApprovedGithubActor {
                failure: InboxApprovedGithubActorFailure::BindingChanged,
                ..
            })
        ));
        assert!(provider.requests.is_empty());
        assert_pr_intake_wal_phase(&repo, &item, EffectPhase::Planned);
    }

    #[test]
    fn provider_observation_failures_and_cross_field_mismatch_never_launch() {
        let (_temp, repo) = repository();
        let mut provider = FakeProvider::default();
        for (observed, expected) in [
            (
                InboxPrObservationFailureClass::ProviderUnavailable,
                PrIntakeObservationFailureClass::ProviderUnavailable,
            ),
            (
                InboxPrObservationFailureClass::MalformedProviderResponse,
                PrIntakeObservationFailureClass::MalformedProviderResponse,
            ),
            (
                InboxPrObservationFailureClass::InvalidProviderGroundTruth,
                PrIntakeObservationFailureClass::InvalidProviderGroundTruth,
            ),
        ] {
            let mut observer = FakeObservationProvider::refusing(observed, "typed observation");
            let report = produce_repository_pr_intake_with(
                &repo,
                17,
                &mut observer,
                loaded_sol_catalog,
                &mut provider,
            );
            assert!(matches!(
                report.refusal,
                Some(PrIntakeProducerRefusalCause::ProviderObservation {
                    classification,
                    ..
                }) if classification == expected
            ));
            assert!(provider.requests.is_empty());
        }

        let mut inconsistent_item = provider_pr_item();
        inconsistent_item
            .pull_request
            .as_mut()
            .expect("PR evidence")
            .updated_at = Some("2026-09-03T00:00:01Z".to_string());
        let mut inconsistent = FakeObservationProvider::returning(inconsistent_item);
        let report = produce_repository_pr_intake_with(
            &repo,
            17,
            &mut inconsistent,
            loaded_sol_catalog,
            &mut provider,
        );
        assert!(matches!(
            report.refusal,
            Some(PrIntakeProducerRefusalCause::ProviderObservation {
                classification: PrIntakeObservationFailureClass::InvalidProviderGroundTruth,
                ..
            })
        ));
        assert!(provider.requests.is_empty());

        let mut inconsistent_item = provider_pr_item();
        inconsistent_item
            .pull_request
            .as_mut()
            .expect("PR evidence")
            .head_repository = Some("acme/other".to_string());
        let mut inconsistent = FakeObservationProvider::returning(inconsistent_item);
        let report = produce_repository_pr_intake_with(
            &repo,
            17,
            &mut inconsistent,
            loaded_sol_catalog,
            &mut provider,
        );
        assert!(matches!(
            report.refusal,
            Some(PrIntakeProducerRefusalCause::ProviderObservation {
                classification: PrIntakeObservationFailureClass::InvalidProviderGroundTruth,
                ..
            })
        ));
        assert!(provider.requests.is_empty());
    }

    #[test]
    fn provider_observation_refusal_serialization_redacts_sensitive_public_detail() {
        let (_temp, repo) = repository();
        let mut provider = FakeProvider::default();
        let mut observer = FakeObservationProvider::refusing(
            InboxPrObservationFailureClass::ProviderUnavailable,
            "provider failed at /home/private/token-123456789012345678901234567890 API_TOKEN=secret-value",
        );

        let report = produce_repository_pr_intake_with(
            &repo,
            17,
            &mut observer,
            loaded_sol_catalog,
            &mut provider,
        );
        let detail = match report.refusal.as_ref() {
            Some(PrIntakeProducerRefusalCause::ProviderObservation {
                classification: PrIntakeObservationFailureClass::ProviderUnavailable,
                detail,
            }) => detail,
            other => panic!("unexpected typed provider refusal: {other:?}"),
        };
        assert!(detail.chars().count() <= MAX_DETAIL_CHARS);
        let serialized = serde_json::to_string(&report).expect("serialize producer refusal");
        assert!(!serialized.contains("/home/private"));
        assert!(!serialized.contains("token-123456789012345678901234567890"));
        assert!(!serialized.contains("secret-value"));
        assert!(serialized.contains("redacted"));
        assert!(provider.requests.is_empty());

        let private_key = PrIntakeProducerReport::provider_observation_refusal(
            &repo,
            Some(18),
            PrIntakeObservationFailureClass::MalformedProviderResponse,
            "provider emitted -----BEGIN PRIVATE KEY----- private-material",
        );
        let serialized =
            serde_json::to_string(&private_key).expect("serialize private-key refusal");
        assert!(serialized.contains("redacted:private-key-material"));
        assert!(!serialized.contains("BEGIN PRIVATE KEY"));
        assert!(!serialized.contains("private-material"));
    }

    #[test]
    fn producer_persistence_refusal_serialization_redacts_sensitive_error_chain() {
        let (_temp, repo) = repository();
        let prepared =
            prepare_repository_pr_intake(&repo, &provider_pr_item()).expect("prepared intake");
        let report = PrIntakeProducerReport::for_contract(&prepared.contract).refuse(
            &repo,
            PrIntakeProducerRefusalCause::PersistenceFailure {
                operation: PrIntakePersistenceOperation::OpenOrCreate,
                detail: "WAL failed at /home/private/acceptance with abcdefghijklmnopqrstuvwxyz1234567890"
                    .to_string(),
            },
        );

        assert!(matches!(
            report.refusal.as_ref(),
            Some(PrIntakeProducerRefusalCause::PersistenceFailure {
                operation: PrIntakePersistenceOperation::OpenOrCreate,
                ..
            })
        ));
        let serialized = serde_json::to_string(&report).expect("serialize persistence refusal");
        assert!(!serialized.contains("/home/private/acceptance"));
        assert!(!serialized.contains("abcdefghijklmnopqrstuvwxyz1234567890"));
        assert!(serialized.contains("redacted"));
    }

    #[test]
    fn producer_actor_and_nested_provider_refusals_redact_sensitive_error_chains() {
        let (_actor_temp, actor_repo) = repository();
        set_approved_github_login(&actor_repo, "publication-owner");
        let mut actor = InjectedActorPreflight {
            actor_result: Err(InboxApprovedGithubActorError {
                failure: InboxApprovedGithubActorFailure::ActorUnavailable,
                detail: "actor lookup exposed /home/private/actor-state".to_string(),
            }),
            binding: None,
            change_pin_before_start: false,
        };
        let mut actor_provider = FakeProvider::default();
        let actor_report = produce_with_injected_actor(
            &actor_repo,
            provider_pr_item(),
            &mut actor,
            &mut actor_provider,
        );

        assert!(matches!(
            actor_report.refusal.as_ref(),
            Some(PrIntakeProducerRefusalCause::ApprovedGithubActor {
                failure: InboxApprovedGithubActorFailure::ActorUnavailable,
                ..
            })
        ));
        let serialized =
            serde_json::to_string(&actor_report).expect("serialize approved-actor refusal");
        assert!(!serialized.contains("/home/private/actor-state"));
        assert!(actor_provider.requests.is_empty());

        let (_provider_temp, provider_repo) = repository();
        let mut observer = FakeObservationProvider::returning(provider_pr_item());
        let mut provider = FakeProvider {
            fail: true,
            failure_detail: Some(
                "provider emitted -----BEGIN PRIVATE KEY----- private-material".to_string(),
            ),
            ..FakeProvider::default()
        };
        let provider_report = produce_repository_pr_intake_with(
            &provider_repo,
            17,
            &mut observer,
            loaded_sol_catalog,
            &mut provider,
        );

        assert!(matches!(
            provider_report.refusal.as_ref(),
            Some(PrIntakeProducerRefusalCause::IntakeRefused {
                refusal: PrIntakeRefusalCause::ProviderLaunchFailure {
                    error: MergeAuditorLaneProviderError::Failed { .. }
                }
            })
        ));
        assert!(matches!(
            provider_report
                .intake_report
                .as_ref()
                .and_then(|report| report.refusal.as_ref()),
            Some(PrIntakeRefusalCause::ProviderLaunchFailure {
                error: MergeAuditorLaneProviderError::Failed { .. }
            })
        ));
        let serialized =
            serde_json::to_string(&provider_report).expect("serialize provider-launch refusal");
        assert!(serialized.contains("redacted:private-key-material"));
        assert!(!serialized.contains("BEGIN PRIVATE KEY"));
        assert!(!serialized.contains("private-material"));
        assert_eq!(provider.requests.len(), 1);
    }

    #[test]
    fn tampered_repository_envelope_refuses_before_wal_or_launch() {
        let (_temp, repo) = repository();
        let mut prepared =
            prepare_repository_pr_intake(&repo, &provider_pr_item()).expect("prepared intake");
        prepared.envelope.payload_json.push(' ');
        let mut provider = FakeProvider::default();
        let mut actor_preflight = TestApprovedGithubActorPreflight;

        let report = produce_authenticated_pr_intake_with(
            &repo,
            prepared,
            &mut actor_preflight,
            loaded_sol_catalog,
            &mut provider,
        );

        assert!(matches!(
            report.refusal,
            Some(PrIntakeProducerRefusalCause::Authentication { .. })
        ));
        assert!(provider.requests.is_empty());
    }

    #[test]
    fn failed_launch_after_durable_start_is_not_relaunched() {
        let (_temp, repo) = repository();
        let mut observer = FakeObservationProvider::returning(provider_pr_item());
        let mut provider = FakeProvider {
            fail: true,
            ..FakeProvider::default()
        };

        let first = produce_repository_pr_intake_with(
            &repo,
            17,
            &mut observer,
            loaded_sol_catalog,
            &mut provider,
        );
        assert!(
            matches!(
                first.refusal,
                Some(PrIntakeProducerRefusalCause::IntakeRefused {
                    refusal: PrIntakeRefusalCause::ProviderLaunchFailure { .. }
                })
            ),
            "{first:#?}"
        );
        assert_eq!(provider.requests.len(), 1);

        let replay = produce_repository_pr_intake_with(
            &repo,
            17,
            &mut observer,
            loaded_sol_catalog,
            &mut provider,
        );
        assert_eq!(
            replay.refusal,
            Some(PrIntakeProducerRefusalCause::ReplayAmbiguous {
                phase: PrIntakeReplayPhase::Started,
            })
        );
        assert_eq!(
            provider.requests.len(),
            1,
            "started replay must not relaunch"
        );
    }

    #[test]
    fn persistence_callback_failure_prevents_legacy_provider_launch() {
        let prepared_event = pull_request_event();
        let envelope = envelope(prepared_event);
        let authenticator = FakeAuthenticator::accepting();
        let mut provider = FakeProvider::default();
        let mut persist = |_request: &MergeAuditorLaneLaunchRequest| {
            Err(MergeAuditorLaneProviderError::Unavailable {
                detail: "durable start unavailable".to_string(),
            })
        };

        let report = handle_intake_event_with_catalog_loader(
            &envelope,
            &authenticator,
            &mut provider,
            None,
            Some(&mut persist),
            || CodexRuntimeModelCatalog::from_slugs(sol_catalog()),
        );

        assert!(matches!(
            report.refusal,
            Some(PrIntakeRefusalCause::ProviderLaunchFailure {
                error: MergeAuditorLaneProviderError::Unavailable { .. }
            })
        ));
        assert!(provider.requests.is_empty());
    }

    #[test]
    fn inbox_selection_drift_refuses_before_durable_start_callback() {
        let envelope = envelope(pull_request_event());
        let authenticator = FakeAuthenticator::accepting();
        let mut provider = FakeProvider::default();
        let report = handle_intake_event(&envelope, sol_catalog(), &authenticator, &mut provider);
        assert!(report.success);
        let request = provider.requests.pop().expect("launch request");
        let mut drifted = request.selection.clone();
        drifted.model = "gpt-5.6-codex".to_string();
        let persisted = Cell::new(false);
        let mut persist = |_request: &MergeAuditorLaneLaunchRequest| {
            persisted.set(true);
            Ok(())
        };

        let result = persist_bound_inbox_prelaunch_start(
            &request,
            &request.auditor_session_id,
            &request.selection,
            &request.auditor_session_id,
            &drifted,
            &mut persist,
        );

        assert!(result.is_err());
        assert!(!persisted.get());
    }

    #[test]
    fn provider_neutral_candidate_branch_keeps_v1_launch_semantics() {
        let envelope = envelope(candidate_branch_event());
        let authenticator = FakeAuthenticator::accepting();
        let mut provider = FakeProvider::default();

        let report = handle_intake_event(&envelope, sol_catalog(), &authenticator, &mut provider);

        assert!(report.success);
        assert_eq!(provider.requests.len(), 1);
        assert!(matches!(
            provider.requests[0].candidate,
            IntakeCandidateIdentity::CandidateBranch { .. }
        ));
    }

    #[test]
    fn production_inbox_candidate_branch_is_an_explicit_typed_refusal() {
        let (_temp, repo) = repository();
        let envelope = envelope(candidate_branch_event());
        let authenticator = FakeAuthenticator::accepting();
        let options = InboxRunOptions {
            repo,
            run_id: crate::orchestrator::RunId::new("candidate-production-refusal")
                .expect("run id"),
            github: false,
            permission_mode: None,
            dry_run: false,
            max_items: None,
            codex_bin: None,
            machine_global: None,
        };

        let report = handle_inbox_intake_event(&envelope, sol_catalog(), &authenticator, options);

        assert!(matches!(
            report.refusal,
            Some(PrIntakeRefusalCause::ProviderLaunchFailure {
                error: MergeAuditorLaneProviderError::Refused { .. }
            })
        ));
        assert!(report.launch_receipt.is_none());
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
