pub mod forge_coordination;
pub mod forge_transport;

use self::forge_transport::{
    decide_pull_request_merge, AuthenticatedPullRequestMergeEvidence, ForgeActor, ForgeItem,
    ForgeReviewState, PullRequestAuditorEvidence, PullRequestFreshnessEvidence,
    PullRequestFreshnessStatus, PullRequestMergeAuthorityBlocker,
    PullRequestMergeAuthorityDecision, PullRequestMergeAuthorityInput, PullRequestMergeEffect,
    PullRequestMergeReceipt, PullRequestMergeSimulationEvidence, PullRequestMergeTransport,
};
use crate::{
    artifacts::{repository_auth_writer, state_auth::sha256_hex},
    effect_wal::{EffectPhase, EffectWal},
    llm::{RedactionSummary, Redactor},
    merge::{
        self, ApplyBlocker, ApplyBlockerDetail, ApplyBlockerDisposition, ApplyReadinessStatus,
        BoundValidationEvidenceBundle, ChangeKind, ChangedPath, DiffOutput, MergeApplyPreview,
        MergeCandidate, MergeCollectOptions, MergeForceOptions, MergePreviewOptions, OutputSummary,
        RepoCommonLock, SafetyCheckStatus, ValidationEvidenceBundle, ValidationReport,
        WorktreeMergeMetadata,
    },
    optimizer::ids::TimestampMillis,
    process_runner::{StdinMode, TrustedFixedNetworkProfile},
    safe_state::SafeRoot,
    sync::normalize_repo_relative_path,
    worktree::{ManagedWorktreeWriteLease, WorktreeManager},
};
use anyhow::{bail, Context, Result};
use git2::{
    BranchType, Delta, DiffFormat, DiffOptions, ObjectType, Oid, Repository, Signature, Time, Tree,
};
use serde::{Deserialize, Serialize, Serializer};
use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    ffi::OsString,
    fs::{self, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

const SUMMARY_LIMIT: usize = 12 * 1024;
const PUBLICATION_JOURNAL_VERSION: u32 = 3;
#[cfg(test)]
const REMOTE_BINDING_SECRET_FILE: &str = "publication-remote-binding.key";
#[cfg(test)]
const REMOTE_BINDING_SECRET_BYTES: usize = 32;
const GH_CAPTURE_LIMIT_BYTES: usize = 1024 * 1024;
const GH_STDIN_LIMIT_BYTES: usize = 1024 * 1024;
const APPROVED_GITHUB_LOGIN_CONFIG_KEY: &str = "agentFiles.approvedGitHubLogin";
const PUBLICATION_JOURNAL_MAX_DIRECTORY_ENTRIES: usize = 96;
const PUBLICATION_JOURNAL_MAX_RECORDS: usize = 64;
const PUBLICATION_JOURNAL_MAX_RECORD_BYTES: u64 = 2 * 1024 * 1024;
const MAX_NETWORK_TOKEN_BYTES: usize = 64 * 1024;
const MAX_PUBLICATION_REMOTE_URL_BYTES: usize = 8 * 1024;
const MAX_PUBLICATION_HOST_BYTES: usize = 253;
const MAX_PUBLICATION_PATH_BYTES: usize = 2 * 1024;
const MAX_PUBLICATION_PATH_COMPONENTS: usize = 32;
const MAX_GITHUB_SLUG_BYTES: usize = 100;
const MAX_PUBLICATION_REF_BYTES: usize = 1024;
const MAX_PUBLICATION_REF_COMPONENTS: usize = 64;
const MAX_GITHUB_RECEIPT_URL_BYTES: usize = 8 * 1024;
const MAX_GITHUB_RECEIPT_STRING_BYTES: usize = 1024;
const MAX_GITHUB_PR_LIST_RECEIPTS: usize = 32;
const GITHUB_PR_EFFECT_LOOKUP_LIMIT: &str = "33";
#[cfg(test)]
const PUBLICATION_PR_MARKER_BYTES: usize = 32;
const MAX_GITHUB_RECEIPT_BODY_BYTES: usize = 512 * 1024;
const MAX_PUBLICATION_SOURCE_CONFIG_BYTES: u64 = 1024 * 1024;
const MAX_PUBLICATION_OBJECT_ENTRIES: usize = 262_144;
const MAX_PUBLICATION_OBJECT_DEPTH: usize = 8;
const MAX_PUBLICATION_CLOSURE_OBJECTS: usize = 262_144;
const MAX_PUBLICATION_CLOSURE_BYTES: u64 = 4 * 1024 * 1024 * 1024;
const MAX_PUBLICATION_TREE_DEPTH: usize = 256;
const MAX_PUBLICATION_COMMIT_DEPTH: usize = 262_144;
const MAX_EXCLUSION_REFERENCE_FILE_BYTES: usize = 1024 * 1024;
const GITHUB_PR_RECEIPT_FIELDS: &str = "url,headRefOid,baseRefOid,number,baseRefName,state,isDraft,title,body,headRefName,headRepository,headRepositoryOwner,isCrossRepository,author";
const GITHUB_ISSUE_SOURCE_FIELDS: &str = "number,title,body,labels,author,url,updatedAt,state";
const GITHUB_PR_SOURCE_FIELDS: &str = "number,title,body,labels,author,url,updatedAt,state,headRefName,baseRefName,headRefOid,baseRefOid,isDraft,files,reviewDecision,latestReviews,statusCheckRollup";
const GITHUB_ISSUE_EFFECT_FIELDS: &str = "number,url,title,body,labels,author,state";
const EXTERNAL_EFFECT_VERSION: u32 = 2;
const EXTERNAL_SOURCE_GUARD_VERSION: u32 = 2;
const EXTERNAL_EFFECT_MARKER_PREFIX: &str = "maco-external-effect";
const MAX_EXTERNAL_SOURCE_SERIALIZED_BYTES: usize = 512 * 1024;
const MAX_EXTERNAL_SOURCE_LABELS: usize = 100;
const MAX_EXTERNAL_SOURCE_FILES: usize = 512;
const MAX_EXTERNAL_SOURCE_CHECKS: usize = 512;
const MAX_EXTERNAL_SOURCE_REVIEWS: usize = 512;
const MAX_GITHUB_EFFECT_CANDIDATES: usize = 100;
const GITHUB_ISSUE_EFFECT_LOOKUP_LIMIT: &str = "101";
const MAX_GITHUB_COMMENT_PAGES: usize = 100;
const MAX_GITHUB_COMMENT_CANDIDATES: usize = 10_000;
const MAX_GITHUB_SOURCE_LIST_ITEMS: usize = 100;
const MAX_GITHUB_SOURCE_LIST_LABELS: usize = 32;

#[cfg(all(test, target_os = "linux"))]
std::thread_local! {
    static FAKE_PR_URL_CALLS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum PublicationRemoteTransport {
    Https {
        host: String,
        path: String,
        command_url: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ForgeKind {
    Fake,
    Git,
    Github,
}

impl ForgeKind {
    pub fn parse(value: &str) -> std::result::Result<Self, String> {
        match value {
            "fake" => Ok(Self::Fake),
            "git" => Ok(Self::Git),
            "github" => Ok(Self::Github),
            _ => Err("expected one of: fake, git, github".to_string()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExternalSourceObjectKind {
    Issue,
    PullRequest,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalSourceGuard {
    pub version: u32,
    pub provider: String,
    pub repository_host: String,
    pub repository_selector: String,
    pub repository_identity: String,
    pub object_kind: ExternalSourceObjectKind,
    pub number: u64,
    pub updated_at: String,
    pub state: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub head_oid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_oid: Option<String>,
    pub content_digest: String,
    pub action_revision_digest: String,
    pub provenance_digest: String,
}

impl ExternalSourceGuard {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        provider: impl Into<String>,
        repository_host: impl Into<String>,
        repository_selector: impl Into<String>,
        repository_identity: impl Into<String>,
        object_kind: ExternalSourceObjectKind,
        number: u64,
        updated_at: impl Into<String>,
        state: impl Into<String>,
        head_oid: Option<String>,
        base_oid: Option<String>,
        content_digest: impl Into<String>,
        action_revision_digest: impl Into<String>,
    ) -> Result<Self> {
        let mut guard = Self {
            version: EXTERNAL_SOURCE_GUARD_VERSION,
            provider: provider.into(),
            repository_host: repository_host.into(),
            repository_selector: repository_selector.into(),
            repository_identity: repository_identity.into(),
            object_kind,
            number,
            updated_at: updated_at.into(),
            state: state.into(),
            head_oid,
            base_oid,
            content_digest: content_digest.into(),
            action_revision_digest: action_revision_digest.into(),
            provenance_digest: String::new(),
        };
        guard.provenance_digest = guard.expected_provenance_digest()?;
        guard.validate()?;
        Ok(guard)
    }

    pub fn validate(&self) -> Result<()> {
        if self.version != EXTERNAL_SOURCE_GUARD_VERSION
            || self.provider != "github"
            || self.repository_host.is_empty()
            || self.number == 0
            || self.repository_selector.is_empty()
            || self.repository_identity.is_empty()
            || self.updated_at.is_empty()
            || self.state.is_empty()
        {
            bail!("external source guard is malformed or unsupported");
        }
        validate_external_digest(
            &self.repository_identity,
            "external source repository identity",
        )?;
        validate_external_source_field(
            &self.repository_selector,
            "external source repository selector",
            MAX_PUBLICATION_PATH_BYTES,
        )?;
        let repository = github_repository_identity_from_selector(&self.repository_selector)?;
        if repository.host != self.repository_host {
            bail!("external source repository host did not match its canonical selector");
        }
        validate_external_source_field(
            &self.updated_at,
            "external source updatedAt",
            MAX_GITHUB_RECEIPT_STRING_BYTES,
        )?;
        validate_external_source_field(
            &self.state,
            "external source state",
            MAX_GITHUB_RECEIPT_STRING_BYTES,
        )?;
        let valid_state = match self.object_kind {
            ExternalSourceObjectKind::Issue => matches!(self.state.as_str(), "OPEN" | "CLOSED"),
            ExternalSourceObjectKind::PullRequest => {
                matches!(self.state.as_str(), "OPEN" | "CLOSED" | "MERGED")
            }
        };
        if !valid_state {
            bail!("external source state was not canonical for its object kind");
        }
        for digest in [
            &self.content_digest,
            &self.action_revision_digest,
            &self.provenance_digest,
        ] {
            validate_external_digest(digest, "external source guard digest")?;
        }
        match self.object_kind {
            ExternalSourceObjectKind::Issue => {
                if self.head_oid.is_some() || self.base_oid.is_some() {
                    bail!("external issue source guard contains pull-request revisions");
                }
            }
            ExternalSourceObjectKind::PullRequest => {
                validate_external_git_oid(
                    self.head_oid
                        .as_deref()
                        .context("external pull-request guard omitted head OID")?,
                    "external source head OID",
                )?;
                validate_external_git_oid(
                    self.base_oid
                        .as_deref()
                        .context("external pull-request guard omitted base OID")?,
                    "external source base OID",
                )?;
            }
        }
        if self.provenance_digest != self.expected_provenance_digest()? {
            bail!("external source guard provenance digest does not match its canonical fields");
        }
        Ok(())
    }

    fn expected_provenance_digest(&self) -> Result<String> {
        stable_json_digest(&(
            "maco_external_source_guard_v2",
            self.version,
            &self.provider,
            &self.repository_host,
            &self.repository_selector,
            &self.repository_identity,
            self.object_kind,
            self.number,
            &self.updated_at,
            &self.state,
            &self.head_oid,
            &self.base_oid,
            &self.content_digest,
            &self.action_revision_digest,
        ))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum ExternalEffectOperation {
    GitPush,
    GithubPullRequest,
    GithubIssue,
    GithubIssueComment,
    GithubPullRequestComment,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ExternalEffectRequest {
    version: u32,
    transport_provider: String,
    repository_selector: String,
    repository_identity: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    source: Option<ExternalSourceGuard>,
    operation: ExternalEffectOperation,
    target: serde_json::Value,
    payload: serde_json::Value,
    target_digest: String,
    payload_digest: String,
    effect_id: String,
    logical_id: String,
    marker: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ExternalEffectReceipt {
    version: u32,
    transport_provider: String,
    repository_identity: String,
    repository_selector: String,
    effect_id: String,
    operation: ExternalEffectOperation,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    source_provenance_digest: Option<String>,
    provider_id: String,
    url: String,
    repository: String,
    marker: String,
    target: serde_json::Value,
    payload: serde_json::Value,
    target_digest: String,
    payload_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ExternalEffectRecord {
    version: u32,
    request: ExternalEffectRequest,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    receipt: Option<ExternalEffectReceipt>,
}

impl ExternalEffectRequest {
    fn new(
        transport_provider: &str,
        repository_selector: &str,
        repository_identity: &str,
        source: Option<ExternalSourceGuard>,
        operation: ExternalEffectOperation,
        target: serde_json::Value,
        payload: serde_json::Value,
    ) -> Result<Self> {
        if let Some(source) = &source {
            source.validate()?;
        }
        let target_digest = stable_json_digest(&target)?;
        let payload_digest = stable_json_digest(&payload)?;
        let logical_binding = match &source {
            Some(source) => stable_json_digest(&(
                "maco_external_effect_logical_v2",
                transport_provider,
                repository_selector,
                repository_identity,
                &source.provider,
                &source.repository_host,
                &source.repository_selector,
                &source.repository_identity,
                source.object_kind,
                source.number,
                &source.action_revision_digest,
            ))?,
            None => stable_json_digest(&(
                "maco_external_effect_logical_v2",
                transport_provider,
                repository_selector,
                repository_identity,
                operation,
                &target_digest,
                &payload_digest,
            ))?,
        };
        let effect_binding = match &source {
            Some(_) => {
                stable_json_digest(&("maco_external_effect_id_v2", &logical_binding, operation))?
            }
            None => stable_json_digest(&(
                "maco_external_effect_id_v2",
                &logical_binding,
                operation,
                &target_digest,
                &payload_digest,
            ))?,
        };
        let marker = format!("<!-- {EXTERNAL_EFFECT_MARKER_PREFIX}:v2:{effect_binding} -->");
        let request = Self {
            version: EXTERNAL_EFFECT_VERSION,
            transport_provider: transport_provider.to_string(),
            repository_selector: repository_selector.to_string(),
            repository_identity: repository_identity.to_string(),
            source,
            operation,
            target,
            payload,
            target_digest,
            payload_digest,
            effect_id: effect_binding,
            logical_id: format!("external-{logical_binding}"),
            marker,
        };
        request.validate()?;
        Ok(request)
    }

    fn validate(&self) -> Result<()> {
        if self.version != EXTERNAL_EFFECT_VERSION
            || self.repository_selector.is_empty()
            || self.repository_identity.is_empty()
        {
            bail!("external effect request is malformed or unsupported");
        }
        let expected_transport_provider = match self.operation {
            ExternalEffectOperation::GitPush => "git",
            ExternalEffectOperation::GithubPullRequest
            | ExternalEffectOperation::GithubIssue
            | ExternalEffectOperation::GithubIssueComment
            | ExternalEffectOperation::GithubPullRequestComment => "github",
        };
        if self.transport_provider != expected_transport_provider {
            bail!("external effect operation used the wrong transport provider");
        }
        validate_external_digest(&self.effect_id, "external effect id")?;
        let logical_digest = self
            .logical_id
            .strip_prefix("external-")
            .context("external effect logical id is malformed")?;
        validate_external_digest(logical_digest, "external effect logical id")?;
        if self.marker
            != format!(
                "<!-- {EXTERNAL_EFFECT_MARKER_PREFIX}:v2:{} -->",
                self.effect_id
            )
        {
            bail!("external effect marker is not derived from its stable identity");
        }
        if let Some(source) = &self.source {
            source.validate()?;
            if source.repository_selector != self.repository_selector {
                bail!("external effect source does not match its repository binding");
            }
        }
        if self.target_digest != stable_json_digest(&self.target)?
            || self.payload_digest != stable_json_digest(&self.payload)?
        {
            bail!(
                "external effect target or payload digest does not match its exact planned value"
            );
        }
        validate_external_digest(&self.target_digest, "external effect target digest")?;
        validate_external_digest(&self.payload_digest, "external effect payload digest")
    }
}

trait ExternalEffectProvider {
    fn preflight_before_start(&mut self, request: &ExternalEffectRequest) -> Result<()>;
    fn lookup(&mut self, request: &ExternalEffectRequest) -> Result<Vec<ExternalEffectReceipt>>;
    fn invoke(&mut self, request: &ExternalEffectRequest) -> Result<ExternalEffectReceipt>;
    fn verify(
        &mut self,
        request: &ExternalEffectRequest,
        receipt: &ExternalEffectReceipt,
    ) -> Result<ExternalEffectReceipt>;
}

fn execute_external_effect_exactly_once(
    repo: &Path,
    request: ExternalEffectRequest,
    provider: &mut impl ExternalEffectProvider,
) -> Result<ExternalEffectReceipt> {
    request.validate()?;
    let planned = ExternalEffectRecord {
        version: EXTERNAL_EFFECT_VERSION,
        request: request.clone(),
        receipt: None,
    };
    let mut wal = EffectWal::open_or_create_planned(
        || {
            repository_auth_writer(repo)?
                .into_authenticator()
                .context("failed to bind authenticated external-effect ledger")
        },
        &request.logical_id,
        &request.effect_id,
        &planned,
    )?;
    execute_external_effect_with_wal(&mut wal, request, provider)
}

fn execute_external_effect_with_wal(
    wal: &mut EffectWal,
    request: ExternalEffectRequest,
    provider: &mut impl ExternalEffectProvider,
) -> Result<ExternalEffectReceipt> {
    request.validate()?;
    if wal.logical_id() != request.logical_id {
        bail!("external effect was presented to a different authenticated logical ledger");
    }
    if wal.phase(&request.effect_id).is_none() {
        let planned = ExternalEffectRecord {
            version: EXTERNAL_EFFECT_VERSION,
            request: request.clone(),
            receipt: None,
        };
        wal.planned(&request.effect_id, &planned)?;
    }
    let (phase, current) = latest_external_effect_record(wal, &request.effect_id)?;
    if !same_external_effect_contract(&current.request, &request) {
        bail!("existing external effect planned payload does not exactly match this request");
    }
    let durable_request = current.request;
    match phase {
        EffectPhase::Completed => {
            let receipt = current
                .receipt
                .context("completed external effect omitted its durable receipt")?;
            provider.verify(&durable_request, &receipt).context(
                "completed external effect remote receipt changed or disappeared; provider call must not be retried and manual reconciliation is required",
            )
        }
        EffectPhase::Observed => {
            let receipt = current
                .receipt
                .context("observed external effect omitted its durable receipt")?;
            let verified = provider.verify(&durable_request, &receipt).context(
                "observed external effect could not be reverified; manual reconciliation required",
            )?;
            let completed = ExternalEffectRecord {
                version: EXTERNAL_EFFECT_VERSION,
                request: durable_request.clone(),
                receipt: Some(verified.clone()),
            };
            wal.completed(&request.effect_id, &completed)?;
            Ok(verified)
        }
        EffectPhase::Started => {
            let receipt = reconcile_started_external_effect(provider, &durable_request)?;
            let observed = ExternalEffectRecord {
                version: EXTERNAL_EFFECT_VERSION,
                request: durable_request.clone(),
                receipt: Some(receipt.clone()),
            };
            wal.observed(&request.effect_id, &observed)?;
            let verified = provider.verify(&durable_request, &receipt).context(
                "reconciled external effect could not be reverified; manual reconciliation required",
            )?;
            let completed = ExternalEffectRecord {
                version: EXTERNAL_EFFECT_VERSION,
                request: durable_request.clone(),
                receipt: Some(verified.clone()),
            };
            wal.completed(&request.effect_id, &completed)?;
            Ok(verified)
        }
        EffectPhase::Planned => {
            provider
                .preflight_before_start(&durable_request)
                .context("external effect source changed before start")?;
            match provider.lookup(&durable_request) {
                Ok(matches) if matches.is_empty() => {}
                Ok(_) => bail!(
                    "planned external effect already has a remote marker match; refusing possible front-run and requiring manual reconciliation"
                ),
                Err(error) => bail!(
                    "planned external effect lookup failed before start; refusing provider call: {error:#}"
                ),
            }
            provider
                .preflight_before_start(&durable_request)
                .context("external effect source changed immediately before durable start")?;
            let started = ExternalEffectRecord {
                version: EXTERNAL_EFFECT_VERSION,
                request: durable_request.clone(),
                receipt: None,
            };
            wal.started(&request.effect_id, &started)?;
            let receipt = match provider.invoke(&durable_request) {
                Ok(receipt) => provider.verify(&durable_request, &receipt).context(
                    "provider returned a receipt that could not be verified; manual reconciliation required",
                )?,
                Err(invoke_error) => reconcile_started_external_effect(provider, &durable_request)
                    .with_context(|| {
                        format!(
                            "provider call failed or lost its response ({invoke_error:#}); blind retry is forbidden"
                        )
                    })?,
            };
            let observed = ExternalEffectRecord {
                version: EXTERNAL_EFFECT_VERSION,
                request: durable_request.clone(),
                receipt: Some(receipt.clone()),
            };
            wal.observed(&request.effect_id, &observed)?;
            let verified = provider.verify(&durable_request, &receipt).context(
                "observed external effect could not be reverified; manual reconciliation required",
            )?;
            let completed = ExternalEffectRecord {
                version: EXTERNAL_EFFECT_VERSION,
                request: durable_request,
                receipt: Some(verified.clone()),
            };
            wal.completed(&completed.request.effect_id, &completed)?;
            Ok(verified)
        }
    }
}

fn same_external_effect_contract(
    stored: &ExternalEffectRequest,
    current: &ExternalEffectRequest,
) -> bool {
    let same_source_action = match (&stored.source, &current.source) {
        (None, None) => true,
        (Some(stored), Some(current)) => {
            stored.provider == current.provider
                && stored.repository_host == current.repository_host
                && stored.repository_selector == current.repository_selector
                && stored.repository_identity == current.repository_identity
                && stored.object_kind == current.object_kind
                && stored.number == current.number
                && stored.action_revision_digest == current.action_revision_digest
        }
        _ => false,
    };
    same_source_action
        && stored.version == current.version
        && stored.transport_provider == current.transport_provider
        && stored.repository_selector == current.repository_selector
        && stored.repository_identity == current.repository_identity
        && stored.operation == current.operation
        && stored.target == current.target
        && stored.payload == current.payload
        && stored.target_digest == current.target_digest
        && stored.payload_digest == current.payload_digest
        && stored.effect_id == current.effect_id
        && stored.logical_id == current.logical_id
        && stored.marker == current.marker
}

fn reconcile_started_external_effect(
    provider: &mut impl ExternalEffectProvider,
    request: &ExternalEffectRequest,
) -> Result<ExternalEffectReceipt> {
    let matches = provider.lookup(request).context(
        "started external effect lookup failed; provider call must not be retried and manual reconciliation is required",
    )?;
    if matches.len() != 1 {
        bail!(
            "started external effect lookup found {} exact matches; provider call must not be retried and manual reconciliation is required",
            matches.len()
        );
    }
    provider.verify(request, &matches[0])
}

fn latest_external_effect_record(
    wal: &EffectWal,
    effect_id: &str,
) -> Result<(EffectPhase, ExternalEffectRecord)> {
    let phase = wal
        .phase(effect_id)
        .context("authenticated external-effect ledger omitted its claimed effect")?;
    let event = wal
        .events()
        .iter()
        .rev()
        .find(|event| event.effect_id == effect_id)
        .context("authenticated external-effect ledger omitted its latest event")?;
    let record: ExternalEffectRecord = serde_json::from_value(event.data.clone())
        .context("authenticated external-effect payload is malformed")?;
    if record.version != EXTERNAL_EFFECT_VERSION || event.phase != phase {
        bail!("authenticated external-effect phase or payload version is inconsistent");
    }
    record.request.validate()?;
    if let Some(receipt) = &record.receipt {
        validate_external_effect_receipt(&record.request, receipt)?;
    }
    Ok((phase, record))
}

fn validate_external_effect_receipt(
    request: &ExternalEffectRequest,
    receipt: &ExternalEffectReceipt,
) -> Result<()> {
    if receipt.version != EXTERNAL_EFFECT_VERSION
        || receipt.transport_provider != request.transport_provider
        || receipt.repository_identity != request.repository_identity
        || receipt.repository_selector != request.repository_selector
        || receipt.repository != request.repository_selector
        || receipt.effect_id != request.effect_id
        || receipt.operation != request.operation
        || receipt.source_provenance_digest.as_deref()
            != request
                .source
                .as_ref()
                .map(|source| source.provenance_digest.as_str())
        || receipt.provider_id.is_empty()
        || receipt.url.is_empty()
        || receipt.repository.is_empty()
        || receipt.marker != request.marker
        || receipt.target != request.target
        || receipt.payload != request.payload
        || receipt.target_digest != request.target_digest
        || receipt.payload_digest != request.payload_digest
    {
        bail!("external effect receipt does not match its exact request binding");
    }
    validate_external_digest(&receipt.effect_id, "external effect receipt id")?;
    if let Some(digest) = &receipt.source_provenance_digest {
        validate_external_digest(digest, "external effect receipt source provenance")?;
    }
    if receipt.url.len() > MAX_GITHUB_RECEIPT_URL_BYTES
        || receipt.url.as_bytes().contains(&0)
        || receipt.provider_id.len() > MAX_GITHUB_RECEIPT_STRING_BYTES
        || receipt.repository_selector.len() > MAX_PUBLICATION_PATH_BYTES
    {
        bail!("external effect receipt object identity is malformed or oversized");
    }
    Ok(())
}

fn validate_external_digest(value: &str, label: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        bail!("{label} is not canonical lowercase SHA-256 hexadecimal");
    }
    Ok(())
}

fn validate_external_git_oid(value: &str, label: &str) -> Result<()> {
    if !matches!(value.len(), 40 | 64)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        bail!("{label} is not a canonical lowercase 40- or 64-hex Git OID");
    }
    Ok(())
}

fn stable_json_digest(value: &impl Serialize) -> Result<String> {
    Ok(sha256_hex(&serde_json::to_vec(value).context(
        "failed to encode stable external-effect binding",
    )?))
}

const AUTHENTICATED_PR_MERGE_VERSION: u32 = 1;

/// Typed reasons why the authenticated merge executor performed no effect.
/// Provider failures after the durable `Started` transition are intentionally
/// returned as errors instead: at that point claiming "not merged" would be
/// unsafe without successful reconciliation.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(tag = "blocker", content = "details", rename_all = "snake_case")]
pub(crate) enum AuthenticatedPullRequestMergeBlocker {
    MissingAuthenticatedAuditorEvidence,
    CurrentGroundTruthUnavailable {
        message: String,
    },
    AuthenticatedEvidenceCandidateMismatch,
    CurrentPullRequestIdentityMismatch,
    StaleCandidateHead {
        candidate_head_oid: String,
        current_head_oid: String,
    },
    MissingApprovedAuditorReview,
    AuditorReviewNotApproved {
        state: ForgeReviewState,
    },
    ApprovedActorMismatch {
        expected_actor_id: String,
        observed_actor_id: String,
    },
    Authority(PullRequestMergeAuthorityBlocker),
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub(crate) enum AuthenticatedPullRequestMergeOutcome {
    NotMerged {
        blockers: Vec<AuthenticatedPullRequestMergeBlocker>,
        authority: Option<PullRequestMergeAuthorityDecision>,
    },
    Merged {
        authority: PullRequestMergeAuthorityDecision,
        receipt: PullRequestMergeReceipt,
    },
}

impl AuthenticatedPullRequestMergeOutcome {
    pub(crate) fn is_merged(&self) -> bool {
        matches!(self, Self::Merged { .. })
    }

    pub(crate) fn blockers(&self) -> &[AuthenticatedPullRequestMergeBlocker] {
        match self {
            Self::NotMerged { blockers, .. } => blockers,
            Self::Merged { .. } => &[],
        }
    }

    pub(crate) fn receipt(&self) -> Option<&PullRequestMergeReceipt> {
        match self {
            Self::NotMerged { .. } => None,
            Self::Merged { receipt, .. } => Some(receipt),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AuthenticatedPullRequestMergeRecord {
    version: u32,
    plan_digest: String,
    candidate: ForgeItem,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    effect: Option<PullRequestMergeEffect>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    authority: Option<PullRequestMergeAuthorityDecision>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    receipt: Option<PullRequestMergeReceipt>,
}

struct AuthorizedPullRequestMerge {
    snapshot: forge_transport::PullRequestReviewSnapshot,
    approved_actor: ForgeActor,
    authority: PullRequestMergeAuthorityDecision,
}

enum PullRequestMergePreflight {
    Allowed(AuthorizedPullRequestMerge),
    Blocked(AuthenticatedPullRequestMergeOutcome),
}

/// Execute one authenticated, head-bound pull-request merge exactly once.
///
/// The evidence capability cannot be deserialized or publicly constructed.
/// On the first attempt this function opens an authenticated effect WAL,
/// observes and authorizes current forge state, proves no pre-existing remote
/// effect, then repeats the complete observation immediately before the
/// durable start and provider compare-and-swap merge. Retries reconcile the
/// exact stored effect and receipt without issuing a blind second merge.
pub(crate) fn execute_authenticated_pull_request_merge(
    repo: &Path,
    candidate: &ForgeItem,
    evidence: Option<&AuthenticatedPullRequestMergeEvidence>,
    transport: &impl PullRequestMergeTransport,
) -> Result<AuthenticatedPullRequestMergeOutcome> {
    let Some(evidence) = evidence else {
        return Ok(AuthenticatedPullRequestMergeOutcome::NotMerged {
            blockers: vec![
                AuthenticatedPullRequestMergeBlocker::MissingAuthenticatedAuditorEvidence,
            ],
            authority: None,
        });
    };

    let plan_digest = stable_json_digest(&(
        "maco_authenticated_pull_request_merge_plan_v1",
        candidate,
        evidence,
    ))?;
    validate_external_digest(&plan_digest, "authenticated PR merge plan digest")?;
    let effect_id = format!("merge:{plan_digest}");
    let logical_id = format!("pr-merge-{plan_digest}");
    let planned = AuthenticatedPullRequestMergeRecord {
        version: AUTHENTICATED_PR_MERGE_VERSION,
        plan_digest: plan_digest.clone(),
        candidate: candidate.clone(),
        effect: None,
        authority: None,
        receipt: None,
    };
    let mut wal = EffectWal::open_or_create_planned(
        || {
            repository_auth_writer(repo)?
                .into_authenticator()
                .context("failed to bind authenticated pull-request merge ledger")
        },
        &logical_id,
        &effect_id,
        &planned,
    )?;
    execute_authenticated_pull_request_merge_with_wal(
        &mut wal,
        candidate,
        evidence,
        &plan_digest,
        &effect_id,
        transport,
    )
}

fn execute_authenticated_pull_request_merge_with_wal(
    wal: &mut EffectWal,
    candidate: &ForgeItem,
    evidence: &AuthenticatedPullRequestMergeEvidence,
    plan_digest: &str,
    effect_id: &str,
    transport: &impl PullRequestMergeTransport,
) -> Result<AuthenticatedPullRequestMergeOutcome> {
    let (phase, current) = latest_authenticated_pull_request_merge_record(wal, effect_id)?;
    if current.plan_digest != plan_digest || current.candidate != *candidate {
        bail!("authenticated pull-request merge ledger belongs to a different exact plan");
    }

    match phase {
        EffectPhase::Completed => {
            let effect = current
                .effect
                .context("completed pull-request merge omitted its durable effect")?;
            let authority = current
                .authority
                .context("completed pull-request merge omitted its authority decision")?;
            let receipt = current
                .receipt
                .context("completed pull-request merge omitted its durable receipt")?;
            let verified = transport
                .verify_pull_request_merge(&effect, &receipt)
                .context("completed pull-request merge receipt changed or disappeared")?;
            Ok(AuthenticatedPullRequestMergeOutcome::Merged {
                authority,
                receipt: verified,
            })
        }
        EffectPhase::Observed => {
            let effect = current
                .effect
                .context("observed pull-request merge omitted its durable effect")?;
            let authority = current
                .authority
                .context("observed pull-request merge omitted its authority decision")?;
            let receipt = current
                .receipt
                .context("observed pull-request merge omitted its durable receipt")?;
            let verified = transport
                .verify_pull_request_merge(&effect, &receipt)
                .context("observed pull-request merge receipt could not be reverified")?;
            complete_authenticated_pull_request_merge(
                wal,
                plan_digest,
                candidate,
                effect_id,
                effect,
                authority,
                verified,
                transport,
                false,
            )
        }
        EffectPhase::Started => {
            let effect = current
                .effect
                .context("started pull-request merge omitted its durable effect")?;
            let authority = current
                .authority
                .context("started pull-request merge omitted its authority decision")?;
            let receipt = reconcile_authenticated_pull_request_merge(transport, &effect)?;
            complete_authenticated_pull_request_merge(
                wal,
                plan_digest,
                candidate,
                effect_id,
                effect,
                authority,
                receipt,
                transport,
                true,
            )
        }
        EffectPhase::Planned => {
            let first = match authorize_current_pull_request_merge(candidate, evidence, transport)?
            {
                PullRequestMergePreflight::Allowed(authorized) => authorized,
                PullRequestMergePreflight::Blocked(outcome) => return Ok(outcome),
            };
            let probe = pull_request_merge_effect(effect_id, plan_digest, evidence, &first)?;
            match transport.lookup_pull_request_merge(&probe) {
                Ok(matches) if matches.is_empty() => {}
                Ok(_) => bail!(
                    "planned pull-request merge already has a remote effect; refusing a possible front-run"
                ),
                Err(error) => bail!(
                    "planned pull-request merge lookup failed before durable start: {error:#}"
                ),
            }

            let authorized =
                match authorize_current_pull_request_merge(candidate, evidence, transport)? {
                    PullRequestMergePreflight::Allowed(authorized) => authorized,
                    PullRequestMergePreflight::Blocked(outcome) => return Ok(outcome),
                };
            let effect = pull_request_merge_effect(effect_id, plan_digest, evidence, &authorized)?;
            let started = AuthenticatedPullRequestMergeRecord {
                version: AUTHENTICATED_PR_MERGE_VERSION,
                plan_digest: plan_digest.to_string(),
                candidate: candidate.clone(),
                effect: Some(effect.clone()),
                authority: Some(authorized.authority.clone()),
                receipt: None,
            };
            wal.started(effect_id, &started)?;

            let receipt = match transport.execute_pull_request_merge(&effect) {
                Ok(receipt) => transport
                    .verify_pull_request_merge(&effect, &receipt)
                    .context("forge returned an unverifiable pull-request merge receipt")?,
                Err(invoke_error) => {
                    reconcile_authenticated_pull_request_merge(transport, &effect).with_context(
                        || {
                            format!(
                                "forge merge failed or lost its response ({invoke_error:#}); blind retry is forbidden"
                            )
                        },
                    )?
                }
            };
            complete_authenticated_pull_request_merge(
                wal,
                plan_digest,
                candidate,
                effect_id,
                effect,
                authorized.authority,
                receipt,
                transport,
                true,
            )
        }
    }
}

fn authorize_current_pull_request_merge(
    candidate: &ForgeItem,
    evidence: &AuthenticatedPullRequestMergeEvidence,
    transport: &impl PullRequestMergeTransport,
) -> Result<PullRequestMergePreflight> {
    let snapshot = match transport.observe_pull_request_for_merge(candidate) {
        Ok(snapshot) => snapshot,
        Err(error) => {
            return Ok(PullRequestMergePreflight::Blocked(
                AuthenticatedPullRequestMergeOutcome::NotMerged {
                    blockers: vec![
                        AuthenticatedPullRequestMergeBlocker::CurrentGroundTruthUnavailable {
                            message: format!("{error:#}"),
                        },
                    ],
                    authority: None,
                },
            ));
        }
    };
    let current = snapshot.item();
    let mut blockers = Vec::new();
    if evidence.candidate != *candidate {
        blockers.push(AuthenticatedPullRequestMergeBlocker::AuthenticatedEvidenceCandidateMismatch);
    }
    if candidate.kind() != current.kind()
        || candidate.repository() != current.repository()
        || candidate.number() != current.number()
        || candidate.provider_item_id() != current.provider_item_id()
    {
        blockers.push(AuthenticatedPullRequestMergeBlocker::CurrentPullRequestIdentityMismatch);
    }
    let candidate_head = candidate.head_oid().unwrap_or_default();
    let current_head = current.head_oid().unwrap_or_default();
    if candidate_head != current_head {
        blockers.push(AuthenticatedPullRequestMergeBlocker::StaleCandidateHead {
            candidate_head_oid: candidate_head.to_string(),
            current_head_oid: current_head.to_string(),
        });
    }

    let approved_review = snapshot
        .reviews()
        .iter()
        .find(|review| review.provider_review_id() == &evidence.approved_review_id);
    let approved_actor = match approved_review {
        None => {
            blockers.push(AuthenticatedPullRequestMergeBlocker::MissingApprovedAuditorReview);
            None
        }
        Some(review) if review.state() != ForgeReviewState::Approved => {
            blockers.push(
                AuthenticatedPullRequestMergeBlocker::AuditorReviewNotApproved {
                    state: review.state(),
                },
            );
            None
        }
        Some(review) => {
            let expected = &evidence.auditor.auditor.agent.stable_id;
            let observed = review.author().provider_actor_id().stable_id();
            if expected != observed {
                blockers.push(
                    AuthenticatedPullRequestMergeBlocker::ApprovedActorMismatch {
                        expected_actor_id: expected.clone(),
                        observed_actor_id: observed.to_string(),
                    },
                );
                None
            } else {
                Some(review.author().clone())
            }
        }
    };

    if !blockers.is_empty() {
        return Ok(PullRequestMergePreflight::Blocked(
            AuthenticatedPullRequestMergeOutcome::NotMerged {
                blockers,
                authority: None,
            },
        ));
    }

    let decided_at = current_timestamp_millis()?;
    let input = PullRequestMergeAuthorityInput {
        freshness: Some(PullRequestFreshnessEvidence {
            current_item: current.clone(),
            snapshot_observed_at: snapshot.observed_at().clone(),
            status: PullRequestFreshnessStatus::Fresh,
            decided_at,
        }),
        required_checks: Some(evidence.required_checks.clone()),
        producer: Some(evidence.producer.clone()),
        auditor: Some(PullRequestAuditorEvidence {
            head_oid: evidence.auditor.head_oid.clone(),
            snapshot_observed_at: snapshot.observed_at().clone(),
            auditor: evidence.auditor.auditor.clone(),
            lenses: evidence.auditor.lenses.clone(),
        }),
        merge_simulation: Some(PullRequestMergeSimulationEvidence {
            head_oid: evidence.merge_simulation.head_oid.clone(),
            base_oid: evidence.merge_simulation.base_oid.clone(),
            snapshot_observed_at: snapshot.observed_at().clone(),
            merges_cleanly: evidence.merge_simulation.merges_cleanly,
        }),
        completion_mode: Some(evidence.completion_mode),
        changed_paths: Some(evidence.changed_paths.clone()),
    };
    let authority = decide_pull_request_merge(&snapshot, &input);
    if !authority.is_allowed() {
        let blockers = authority
            .blockers()
            .iter()
            .cloned()
            .map(AuthenticatedPullRequestMergeBlocker::Authority)
            .collect();
        return Ok(PullRequestMergePreflight::Blocked(
            AuthenticatedPullRequestMergeOutcome::NotMerged {
                blockers,
                authority: Some(authority),
            },
        ));
    }

    Ok(PullRequestMergePreflight::Allowed(
        AuthorizedPullRequestMerge {
            snapshot,
            approved_actor: approved_actor.expect("unblocked approval contains an actor"),
            authority,
        },
    ))
}

fn pull_request_merge_effect(
    effect_id: &str,
    plan_digest: &str,
    evidence: &AuthenticatedPullRequestMergeEvidence,
    authorized: &AuthorizedPullRequestMerge,
) -> Result<PullRequestMergeEffect> {
    let ground_truth_digest = stable_json_digest(&(
        "maco_authenticated_pull_request_merge_ground_truth_v1",
        &authorized.snapshot,
        &authorized.approved_actor,
        &authorized.authority,
        plan_digest,
    ))?;
    PullRequestMergeEffect::new(
        effect_id,
        authorized.snapshot.item().clone(),
        authorized.approved_actor.clone(),
        format!("sha256:{plan_digest}"),
        format!("sha256:{ground_truth_digest}"),
        evidence.completion_mode,
    )
}

#[allow(clippy::too_many_arguments)]
fn complete_authenticated_pull_request_merge(
    wal: &mut EffectWal,
    plan_digest: &str,
    candidate: &ForgeItem,
    effect_id: &str,
    effect: PullRequestMergeEffect,
    authority: PullRequestMergeAuthorityDecision,
    receipt: PullRequestMergeReceipt,
    transport: &impl PullRequestMergeTransport,
    write_observed: bool,
) -> Result<AuthenticatedPullRequestMergeOutcome> {
    let verified = transport.verify_pull_request_merge(&effect, &receipt)?;
    let record = AuthenticatedPullRequestMergeRecord {
        version: AUTHENTICATED_PR_MERGE_VERSION,
        plan_digest: plan_digest.to_string(),
        candidate: candidate.clone(),
        effect: Some(effect.clone()),
        authority: Some(authority.clone()),
        receipt: Some(verified.clone()),
    };
    if write_observed {
        wal.observed(effect_id, &record)?;
    }
    let completed_receipt = transport
        .verify_pull_request_merge(&effect, &verified)
        .context("authenticated merge receipt changed before completion")?;
    let completed = AuthenticatedPullRequestMergeRecord {
        receipt: Some(completed_receipt.clone()),
        ..record
    };
    wal.completed(effect_id, &completed)?;
    Ok(AuthenticatedPullRequestMergeOutcome::Merged {
        authority,
        receipt: completed_receipt,
    })
}

fn reconcile_authenticated_pull_request_merge(
    transport: &impl PullRequestMergeTransport,
    effect: &PullRequestMergeEffect,
) -> Result<PullRequestMergeReceipt> {
    let matches = transport
        .lookup_pull_request_merge(effect)
        .context("started pull-request merge lookup failed; blind provider retry is forbidden")?;
    if matches.len() != 1 {
        bail!(
            "started pull-request merge lookup found {} exact receipts; blind provider retry is forbidden",
            matches.len()
        );
    }
    transport.verify_pull_request_merge(effect, &matches[0])
}

fn latest_authenticated_pull_request_merge_record(
    wal: &EffectWal,
    effect_id: &str,
) -> Result<(EffectPhase, AuthenticatedPullRequestMergeRecord)> {
    let phase = wal
        .phase(effect_id)
        .context("authenticated pull-request merge ledger omitted its effect")?;
    let event = wal
        .events()
        .iter()
        .rev()
        .find(|event| event.effect_id == effect_id)
        .context("authenticated pull-request merge ledger omitted its latest event")?;
    let record: AuthenticatedPullRequestMergeRecord = serde_json::from_value(event.data.clone())
        .context("authenticated pull-request merge record is malformed")?;
    if event.phase != phase || record.version != AUTHENTICATED_PR_MERGE_VERSION {
        bail!("authenticated pull-request merge phase or version is inconsistent");
    }
    validate_external_digest(&record.plan_digest, "authenticated PR merge record digest")?;
    match phase {
        EffectPhase::Planned
            if record.effect.is_none()
                && record.authority.is_none()
                && record.receipt.is_none() => {}
        EffectPhase::Started
            if record.effect.is_some()
                && record
                    .authority
                    .as_ref()
                    .is_some_and(|value| value.is_allowed())
                && record.receipt.is_none() => {}
        EffectPhase::Observed | EffectPhase::Completed
            if record.effect.is_some()
                && record
                    .authority
                    .as_ref()
                    .is_some_and(|value| value.is_allowed())
                && record.receipt.is_some() =>
        {
            record
                .receipt
                .as_ref()
                .expect("checked receipt")
                .validate_for_effect(record.effect.as_ref().expect("checked effect"))?;
        }
        _ => bail!("authenticated pull-request merge record does not match its durable phase"),
    }
    Ok((phase, record))
}

fn current_timestamp_millis() -> Result<TimestampMillis> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before the Unix epoch")?
        .as_millis();
    Ok(TimestampMillis::from_millis(
        u64::try_from(millis).context("system clock milliseconds exceed u64")?,
    ))
}

pub(crate) fn external_source_repository_identity(device: u64, file: u64) -> String {
    let mut payload = b"MACO\0external-source-repository\0v2\0".to_vec();
    payload.extend_from_slice(&device.to_be_bytes());
    payload.extend_from_slice(&file.to_be_bytes());
    sha256_hex(&payload)
}

pub(crate) fn stable_external_digest(bytes: &[u8]) -> String {
    sha256_hex(bytes)
}

pub(crate) fn github_source_guard_from_value(
    repository_host: &str,
    repository_selector: &str,
    repository_identity: &str,
    kind: ExternalSourceObjectKind,
    value: &serde_json::Value,
) -> Result<ExternalSourceGuard> {
    let serialized =
        serde_json::to_vec(value).context("failed to bound GitHub source observation")?;
    if serialized.len() > MAX_EXTERNAL_SOURCE_SERIALIZED_BYTES {
        bail!("GitHub source observation exceeded its serialized byte limit");
    }
    let object = value
        .as_object()
        .context("GitHub source observation was not an object")?;
    let number = object
        .get("number")
        .and_then(serde_json::Value::as_u64)
        .filter(|number| *number > 0)
        .context("GitHub source observation omitted its positive number")?;
    let updated_at = external_source_string(object, "updatedAt")?;
    let state = external_source_string(object, "state")?.to_ascii_uppercase();
    let title = external_source_string(object, "title")?;
    let body = required_external_source_string_allow_empty(object, "body")?;
    let url = external_source_string(object, "url")?;
    let author = nullable_external_source_author(object, "author")?;
    let label_values = required_bounded_external_source_array(
        object.get("labels"),
        "GitHub source labels",
        MAX_EXTERNAL_SOURCE_LABELS,
    )?;
    let mut labels = Vec::with_capacity(label_values.len());
    for label in label_values {
        let name = label
            .as_object()
            .and_then(|label| label.get("name"))
            .and_then(serde_json::Value::as_str)
            .context("GitHub source label omitted name")?;
        validate_external_source_field(name, "GitHub source label", MAX_GITHUB_SLUG_BYTES)?;
        labels.push(name.to_string());
    }
    labels.sort();
    labels.dedup();
    let (head_oid, base_oid, content_digest, action_revision_digest) = match kind {
        ExternalSourceObjectKind::Issue => {
            let action = stable_json_digest(&(
                "maco_github_issue_action_revision_v1",
                repository_selector,
                kind,
                number,
                title,
                body,
                url,
                author,
                &labels,
                &state,
            ))?;
            let full = stable_json_digest(&(
                "maco_github_issue_content_v1",
                number,
                title,
                body,
                url,
                author,
                &labels,
                &state,
                &updated_at,
            ))?;
            (None, None, full, action)
        }
        ExternalSourceObjectKind::PullRequest => {
            let head_oid = external_source_string(object, "headRefOid")?.to_string();
            let base_oid = external_source_string(object, "baseRefOid")?.to_string();
            validate_external_git_oid(&head_oid, "GitHub source head OID")?;
            validate_external_git_oid(&base_oid, "GitHub source base OID")?;
            let head_ref = external_source_string(object, "headRefName")?;
            let base_ref = external_source_string(object, "baseRefName")?;
            let is_draft = object
                .get("isDraft")
                .and_then(serde_json::Value::as_bool)
                .context("GitHub source observation omitted boolean isDraft")?;
            let file_values = required_bounded_external_source_array(
                object.get("files"),
                "GitHub source files",
                MAX_EXTERNAL_SOURCE_FILES,
            )?;
            let mut files = Vec::with_capacity(file_values.len());
            for file in file_values {
                let path = file
                    .as_object()
                    .and_then(|file| file.get("path"))
                    .and_then(serde_json::Value::as_str)
                    .context("GitHub source file omitted path")?;
                validate_external_source_field(
                    path,
                    "GitHub source file path",
                    MAX_PUBLICATION_PATH_BYTES,
                )?;
                files.push(path.to_string());
            }
            files.sort();
            files.dedup();
            let checks = canonical_required_external_source_items(
                object.get("statusCheckRollup"),
                "GitHub source checks",
                MAX_EXTERNAL_SOURCE_CHECKS,
            )?;
            let reviews = canonical_required_external_source_items(
                object.get("latestReviews"),
                "GitHub source reviews",
                MAX_EXTERNAL_SOURCE_REVIEWS,
            )?;
            let review_decision = nullable_external_source_string(object, "reviewDecision")?;
            let action = stable_json_digest(&(
                "maco_github_pull_request_action_revision_v1",
                repository_selector,
                kind,
                number,
                title,
                body,
                url,
                author,
                &labels,
                &state,
                head_ref,
                base_ref,
                &head_oid,
                &base_oid,
                is_draft,
                &files,
            ))?;
            let full = stable_json_digest(&(
                "maco_github_pull_request_content_v1",
                (
                    number,
                    title,
                    body,
                    url,
                    author,
                    &labels,
                    &state,
                    &updated_at,
                ),
                (head_ref, base_ref, &head_oid, &base_oid, is_draft, &files),
                (&checks, &reviews, review_decision),
            ))?;
            (Some(head_oid), Some(base_oid), full, action)
        }
    };
    ExternalSourceGuard::new(
        "github",
        repository_host,
        repository_selector,
        repository_identity,
        kind,
        number,
        updated_at,
        state,
        head_oid,
        base_oid,
        content_digest,
        action_revision_digest,
    )
}

fn required_bounded_external_source_array<'a>(
    value: Option<&'a serde_json::Value>,
    label: &str,
    max: usize,
) -> Result<&'a [serde_json::Value]> {
    let values = value
        .context(format!("{label} was missing"))?
        .as_array()
        .with_context(|| format!("{label} was not an array"))?;
    if values.len() > max {
        bail!("{label} exceeded its entry limit");
    }
    Ok(values)
}

fn canonical_required_external_source_items(
    value: Option<&serde_json::Value>,
    label: &str,
    max: usize,
) -> Result<Vec<String>> {
    let values = required_bounded_external_source_array(value, label, max)?;
    let mut canonical = Vec::with_capacity(values.len());
    for item in values {
        if !item.is_object() {
            bail!("{label} entry was not an object");
        }
        let bytes =
            serde_json::to_vec(item).with_context(|| format!("failed to encode {label}"))?;
        if bytes.len() > MAX_GITHUB_RECEIPT_BODY_BYTES {
            bail!("{label} entry exceeded its byte limit");
        }
        canonical.push(String::from_utf8(bytes).context("canonical JSON was not UTF-8")?);
    }
    canonical.sort();
    canonical.dedup();
    Ok(canonical)
}

fn required_external_source_string_allow_empty<'a>(
    object: &'a serde_json::Map<String, serde_json::Value>,
    field: &str,
) -> Result<&'a str> {
    let value = object
        .get(field)
        .with_context(|| format!("GitHub source observation omitted {field}"))?
        .as_str()
        .with_context(|| format!("GitHub source observation {field} was not a string"))?;
    if value.len() > MAX_GITHUB_RECEIPT_BODY_BYTES || value.contains('\0') {
        bail!("GitHub source observation {field} was malformed or oversized");
    }
    Ok(value)
}

fn nullable_external_source_author<'a>(
    object: &'a serde_json::Map<String, serde_json::Value>,
    field: &str,
) -> Result<&'a str> {
    match object
        .get(field)
        .with_context(|| format!("GitHub source observation omitted {field}"))?
    {
        serde_json::Value::Null => Ok("<unknown>"),
        serde_json::Value::Object(author) => {
            let login = author
                .get("login")
                .and_then(serde_json::Value::as_str)
                .with_context(|| format!("GitHub source observation {field}.login was missing"))?;
            validate_external_source_field(
                login,
                "GitHub source author login",
                MAX_GITHUB_SLUG_BYTES,
            )?;
            Ok(login)
        }
        _ => bail!("GitHub source observation {field} was neither null nor an object"),
    }
}

fn nullable_external_source_string<'a>(
    object: &'a serde_json::Map<String, serde_json::Value>,
    field: &str,
) -> Result<&'a str> {
    match object
        .get(field)
        .with_context(|| format!("GitHub source observation omitted {field}"))?
    {
        serde_json::Value::Null => Ok(""),
        serde_json::Value::String(value) => {
            if value.len() > MAX_GITHUB_RECEIPT_STRING_BYTES || value.contains('\0') {
                bail!("GitHub source observation {field} was malformed or oversized");
            }
            Ok(value)
        }
        _ => bail!("GitHub source observation {field} was neither null nor a string"),
    }
}

fn validate_external_source_field(value: &str, label: &str, max: usize) -> Result<()> {
    if value.is_empty()
        || value.len() > max
        || value.as_bytes().iter().any(|byte| byte.is_ascii_control())
    {
        bail!("{label} was empty, malformed, or oversized");
    }
    Ok(())
}

fn external_source_string<'a>(
    object: &'a serde_json::Map<String, serde_json::Value>,
    field: &str,
) -> Result<&'a str> {
    let value = object
        .get(field)
        .and_then(serde_json::Value::as_str)
        .with_context(|| format!("GitHub source observation omitted {field}"))?;
    if value.is_empty() || value.len() > MAX_GITHUB_RECEIPT_BODY_BYTES || value.contains('\0') {
        bail!("GitHub source observation {field} was empty, malformed, or oversized");
    }
    Ok(value)
}

pub(crate) fn revalidate_external_source(
    repo: &Path,
    expected: &ExternalSourceGuard,
) -> Result<()> {
    revalidate_external_source_with(repo, expected, true)
}

fn revalidate_external_source_action_revision(
    repo: &Path,
    expected: &ExternalSourceGuard,
) -> Result<()> {
    revalidate_external_source_with(repo, expected, false)
}

fn revalidate_external_source_with(
    repo: &Path,
    expected: &ExternalSourceGuard,
    require_full_freshness: bool,
) -> Result<()> {
    expected.validate()?;
    let repository =
        crate::git_repository::discover(repo).context("failed to discover guarded source repo")?;
    let remote_url = remote_url(&repository, "origin")
        .context("external source revalidation requires canonical origin")?;
    let github_repository = github_repository_identity(&remote_url)?;
    let selector = github_repository.selector();
    if github_repository.host != expected.repository_host
        || selector != expected.repository_selector
    {
        bail!("external source guard repository selector changed");
    }
    let common = SafeRoot::open_existing(repository.commondir())
        .context("failed to bind external source repository common directory")?;
    if external_source_repository_identity(common.identity().device, common.identity().file)
        != expected.repository_identity
    {
        bail!("external source guard belongs to a different local repository identity");
    }
    let value = cli_github_source_view(
        repo,
        expected.number,
        expected.object_kind,
        &github_repository,
    )?;
    let observed = github_source_guard_from_value(
        &github_repository.host,
        &expected.repository_selector,
        &expected.repository_identity,
        expected.object_kind,
        &value,
    )?;
    if require_full_freshness {
        if &observed != expected {
            bail!("external source changed from its exact freshness snapshot");
        }
    } else if observed.provider != expected.provider
        || observed.repository_host != expected.repository_host
        || observed.repository_selector != expected.repository_selector
        || observed.repository_identity != expected.repository_identity
        || observed.object_kind != expected.object_kind
        || observed.number != expected.number
        || observed.action_revision_digest != expected.action_revision_digest
    {
        bail!("external source action revision changed during effect reconciliation");
    }
    common.verify()
}

#[cfg(test)]
pub(crate) fn revalidate_external_source_value(
    expected: &ExternalSourceGuard,
    value: &serde_json::Value,
) -> Result<()> {
    expected.validate()?;
    let observed = github_source_guard_from_value(
        &expected.repository_host,
        &expected.repository_selector,
        &expected.repository_identity,
        expected.object_kind,
        value,
    )?;
    if &observed != expected {
        bail!("external source changed from its exact freshness snapshot");
    }
    Ok(())
}

#[derive(Debug, Clone)]
pub struct PrPublicationOptions {
    pub repo: PathBuf,
    pub agent_id: String,
    pub claimed_paths: Vec<PathBuf>,
    pub validations: Vec<ValidationReport>,
    pub forge: ForgeKind,
    pub draft: bool,
    pub from_branch: Option<String>,
    pub squash_onto: Option<String>,
    pub exclude_paths: Vec<PathBuf>,
}

#[derive(Debug, Clone)]
pub struct IssuePublicationOptions {
    pub repo: PathBuf,
    pub title: String,
    pub body: String,
    pub labels: Vec<String>,
    pub forge: ForgeKind,
}

fn validate_publication_branch_name(branch: &str, label: &str) -> Result<()> {
    if branch.is_empty() {
        bail!("{label} cannot be empty");
    }
    validate_publication_ref(&format!("refs/heads/{branch}"))
        .with_context(|| format!("{label} is not a safe local branch name"))
}

pub fn branch_publication_agent_id(branch: &str) -> Result<String> {
    validate_publication_branch_name(branch, "from-branch")?;
    let mut segment = sanitize_url_segment(branch);
    if segment.len() > 38 {
        segment.truncate(38);
        segment = segment.trim_matches('-').to_string();
    }
    if segment.is_empty() {
        segment = "branch".to_string();
    }
    let id = format!("branch-{segment}-{:016x}", stable_hash(branch.as_bytes()));
    crate::worktree::normalize_agent_id(&id)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PrPublicationStatus {
    Preview,
    Blocked,
    Published,
}

#[derive(Debug, Serialize)]
pub struct PrPublicationReport {
    pub status: PrPublicationStatus,
    pub agent_id: String,
    pub branch: String,
    pub base: String,
    pub base_head: Option<String>,
    pub remote: Option<String>,
    pub forge: ForgeKind,
    pub draft: bool,
    pub title: String,
    pub body_summary: OutputSummary,
    #[serde(serialize_with = "serialize_paths")]
    pub changed_paths: Vec<PathBuf>,
    pub validation_status: SafetyCheckStatus,
    pub validation_required: bool,
    pub readiness: ApplyReadinessStatus,
    pub blockers: Vec<ApplyBlocker>,
    pub commit_id: Option<String>,
    pub head_id: Option<String>,
    pub pr_url: Option<String>,
    pub pushed: bool,
    pub created: bool,
    pub publication_receipt: Option<PrPublicationReceipt>,
    pub next_action: String,
    pub preview: MergeApplyPreview,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PrPublicationReceipt {
    pub version: u32,
    pub transaction_id: String,
    pub sequence: u64,
    pub phase: PublicationTransactionPhase,
    pub expected_oid: String,
    pub expected_base_oid: Option<String>,
    pub remote_ref: String,
    pub github_repository: Option<String>,
    pub push_observed_oid: Option<String>,
    pub pr_url: Option<String>,
    pub pr_head_oid: Option<String>,
    pub pr_base: Option<String>,
    pub pr_state: Option<String>,
    pub pr_is_draft: Option<bool>,
    pub create_attempted: bool,
    pub created_by_transaction: bool,
    pub observed_existing_pr: bool,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicationTransactionPhase {
    Prepared,
    PushObserved,
    PrObserved,
    Completed,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PublicationTransactionJournal {
    version: u32,
    transaction_id: String,
    sequence: u64,
    agent_id: String,
    forge: ForgeKind,
    expected_oid: String,
    expected_base_oid: Option<String>,
    remote_name: String,
    remote_binding_digest: String,
    remote_display: String,
    remote_ref: String,
    remote_branch: String,
    github_repository: Option<GithubRepositoryIdentity>,
    pr_marker_nonce: Option<String>,
    expected_pr_title: Option<String>,
    expected_pr_body: Option<String>,
    expected_pr_author: Option<String>,
    base: String,
    draft: bool,
    phase: PublicationTransactionPhase,
    push_observed_oid: Option<String>,
    pr_url: Option<String>,
    pr_head_oid: Option<String>,
    pr_base: Option<String>,
    pr_state: Option<String>,
    pr_is_draft: Option<bool>,
    pr_number: Option<u64>,
    pr_title: Option<String>,
    pr_body: Option<String>,
    pr_head_ref_name: Option<String>,
    pr_head_repository_owner: Option<String>,
    pr_head_repository_name: Option<String>,
    pr_is_cross_repository: Option<bool>,
    pr_author: Option<String>,
    create_attempted: bool,
    created_by_transaction: bool,
    observed_existing_pr: bool,
    last_error: Option<String>,
    updated_unix_seconds: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct GithubRepositoryIdentity {
    host: String,
    owner: String,
    name: String,
}

impl GithubRepositoryIdentity {
    fn selector(&self) -> String {
        format!("{}/{}/{}", self.host, self.owner, self.name)
    }
}

fn github_repository_identity_from_selector(selector: &str) -> Result<GithubRepositoryIdentity> {
    if selector.len() > MAX_PUBLICATION_PATH_BYTES || selector.contains(['\\', '@', '?', '#']) {
        bail!("GitHub repository selector was malformed or oversized");
    }
    let components = selector.split('/').collect::<Vec<_>>();
    if components.len() != 3 {
        bail!("GitHub repository selector must be canonical host/owner/name");
    }
    let host = normalize_github_host(components[0])?;
    if host != components[0] {
        bail!("GitHub repository selector host was not canonical");
    }
    validate_github_slug(components[1], "GitHub repository owner")?;
    validate_github_slug(components[2], "GitHub repository name")?;
    Ok(GithubRepositoryIdentity {
        host,
        owner: components[1].to_ascii_lowercase(),
        name: components[2].to_ascii_lowercase(),
    })
}

pub(crate) fn canonical_github_source_repository(remote_url: &str) -> Result<(String, String)> {
    let repository = github_repository_identity(remote_url)?;
    Ok((repository.host.clone(), repository.selector()))
}

pub(crate) fn validate_github_source_repository_binding(host: &str, selector: &str) -> Result<()> {
    let repository = github_repository_identity_from_selector(selector)?;
    if repository.host != host {
        bail!("GitHub source repository host did not match its canonical selector");
    }
    Ok(())
}

struct PublicationTransaction {
    directory: PathBuf,
    journal: PublicationTransactionJournal,
    remote_url: String,
    push_effect_request: Option<ExternalEffectRequest>,
    pr_effect_request: Option<ExternalEffectRequest>,
}

struct PublicationGitContext {
    directory: PathBuf,
    runtime_directory: merge::PrivateRuntimeDirectory,
    environment: BTreeMap<String, String>,
    boundary: PublicationGitBoundary,
    config_files: Vec<PrivateConfigFileIdentity>,
    token: Option<PrivateNetworkToken>,
    operation: PublicationGitOperation,
    object_seal: Option<PrivateObjectClosureSeal>,
}

struct GhCommandContext {
    runtime_directory: merge::PrivateRuntimeDirectory,
    environment: BTreeMap<String, String>,
    profile: TrustedFixedNetworkProfile,
    config_files: Vec<PrivateConfigFileIdentity>,
    repository: GithubRepositoryIdentity,
    token: PrivateNetworkToken,
    source_config_path: PathBuf,
}

type PublicationGitContextSetup = (
    BTreeMap<String, String>,
    PublicationGitBoundary,
    Vec<PrivateConfigFileIdentity>,
    Option<PrivateNetworkToken>,
    Option<PrivateObjectClosureSeal>,
);

type GhCommandContextSetup = (
    BTreeMap<String, String>,
    TrustedFixedNetworkProfile,
    Vec<PrivateConfigFileIdentity>,
    PrivateNetworkToken,
    PathBuf,
);

struct ApprovedGithubActorBinding {
    login: String,
    source_config: PrivateConfigFileIdentity,
}

#[derive(Clone)]
enum PublicationGitBoundary {
    Https(TrustedFixedNetworkProfile),
}

#[derive(Clone)]
enum PublicationGitOperation {
    ObserveRemoteRef {
        remote_ref: String,
    },
    PushCreateOnly {
        expected_oid: String,
        remote_ref: String,
    },
}

impl PublicationGitOperation {
    fn observe(remote_ref: &str) -> Result<Self> {
        validate_publication_ref(remote_ref)?;
        Ok(Self::ObserveRemoteRef {
            remote_ref: remote_ref.to_string(),
        })
    }

    fn push_create_only(expected_oid: &str, remote_ref: &str) -> Result<Self> {
        validate_publication_ref(remote_ref)?;
        let oid = Oid::from_str(expected_oid).context("publication push OID was invalid")?;
        if oid.to_string() != expected_oid {
            bail!("publication push OID was not canonical lowercase hexadecimal");
        }
        Ok(Self::PushCreateOnly {
            expected_oid: expected_oid.to_string(),
            remote_ref: remote_ref.to_string(),
        })
    }

    fn requires_object_closure(&self) -> Option<&str> {
        match self {
            Self::ObserveRemoteRef { .. } => None,
            Self::PushCreateOnly { expected_oid, .. } => Some(expected_oid),
        }
    }

    fn label(&self) -> &'static str {
        match self {
            Self::ObserveRemoteRef { .. } => "observe publication remote ref",
            Self::PushCreateOnly { .. } => "create publication remote ref",
        }
    }

    fn arguments(&self) -> Vec<OsString> {
        match self {
            Self::ObserveRemoteRef { remote_ref } => vec![
                OsString::from("ls-remote"),
                OsString::from("--refs"),
                OsString::from("maco-publication"),
                OsString::from(remote_ref),
            ],
            Self::PushCreateOnly {
                expected_oid,
                remote_ref,
            } => vec![
                OsString::from("push"),
                OsString::from("--no-verify"),
                OsString::from(format!("--force-with-lease={remote_ref}:")),
                OsString::from("maco-publication"),
                OsString::from(format!("{expected_oid}:{remote_ref}")),
            ],
        }
    }
}

struct PrivateObjectClosureSeal {
    expected_oid: Oid,
    object_ids: BTreeSet<Oid>,
    total_bytes: u64,
}

enum ClosureObject {
    Commit(Oid),
    Tree { oid: Oid, depth: usize },
    Blob(Oid),
}

struct PrivateNetworkToken {
    bytes: Vec<u8>,
    basic: Vec<u8>,
}

struct ZeroizingString(String);

#[derive(PartialEq, Eq)]
#[cfg(test)]
struct ZeroizingBytes(Vec<u8>);

#[cfg(test)]
impl ZeroizingBytes {
    fn as_slice(&self) -> &[u8] {
        &self.0
    }

    fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.0
    }

    fn len(&self) -> usize {
        self.0.len()
    }
}

#[cfg(test)]
impl std::fmt::Debug for ZeroizingBytes {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("<redacted:zeroizing-bytes>")
    }
}

#[cfg(test)]
impl Drop for ZeroizingBytes {
    fn drop(&mut self) {
        zeroize_bytes(&mut self.0);
        self.0.clear();
    }
}

impl ZeroizingString {
    fn as_str(&self) -> &str {
        &self.0
    }

    fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    fn zeroize(&mut self) {
        // SAFETY: replacing every UTF-8 byte with NUL preserves UTF-8 validity; the string is
        // cleared immediately after the overwrite and is not observed during mutation.
        zeroize_bytes(unsafe { self.0.as_bytes_mut() });
        self.0.clear();
    }
}

impl std::fmt::Debug for ZeroizingString {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("<redacted:zeroizing-string>")
    }
}

impl Drop for ZeroizingString {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl std::fmt::Debug for PrivateNetworkToken {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("<redacted:network-token>")
    }
}

impl Drop for PrivateNetworkToken {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl PrivateNetworkToken {
    fn zeroize(&mut self) {
        zeroize_bytes(&mut self.bytes);
        self.bytes.clear();
        zeroize_bytes(&mut self.basic);
        self.basic.clear();
    }
}

struct PrivateConfigFileIdentity {
    path: PathBuf,
    private_owner_only: bool,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    bytes: Vec<u8>,
}

impl std::fmt::Debug for PrivateConfigFileIdentity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PrivateConfigFileIdentity")
            .field("path", &self.path)
            .field("private_owner_only", &self.private_owner_only)
            .field(
                "bytes",
                &format_args!("<redacted:{} bytes>", self.bytes.len()),
            )
            .finish_non_exhaustive()
    }
}

impl Drop for PrivateConfigFileIdentity {
    fn drop(&mut self) {
        zeroize_bytes(&mut self.bytes);
        self.bytes.clear();
    }
}

fn zeroize_bytes(bytes: &mut [u8]) {
    bytes.fill(0);
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}

#[derive(Debug, Serialize)]
pub struct IssuePublicationReport {
    pub title: String,
    pub redacted_body: String,
    pub redactions: RedactionSummary,
    pub labels: Vec<String>,
    pub forge: ForgeKind,
    pub url: Option<String>,
    pub created: bool,
    pub next_action: String,
}

#[derive(Debug, Clone)]
struct GithubPrResult {
    url: String,
    head_oid: String,
    base_oid: String,
    number: u64,
    base_ref_name: String,
    state: String,
    is_draft: bool,
    title: String,
    body: String,
    head_ref_name: String,
    head_repository_owner: String,
    head_repository_name: String,
    is_cross_repository: bool,
    author: String,
    created: bool,
}

struct GithubCreateOutput {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

trait GithubApi {
    fn list(
        &mut self,
        worktree_path: &Path,
        branch: &str,
        repository: &GithubRepositoryIdentity,
    ) -> Result<Vec<GithubPrResult>>;

    fn view(
        &mut self,
        worktree_path: &Path,
        selector: &str,
        repository: &GithubRepositoryIdentity,
    ) -> Result<GithubPrResult>;

    #[allow(clippy::too_many_arguments)]
    fn create(
        &mut self,
        worktree_path: &Path,
        branch: &str,
        base: &str,
        title: &str,
        body: &str,
        draft: bool,
        repository: &GithubRepositoryIdentity,
    ) -> Result<GithubCreateOutput>;
}

struct CliGithubApi;

impl GithubApi for CliGithubApi {
    fn list(
        &mut self,
        worktree_path: &Path,
        branch: &str,
        repository: &GithubRepositoryIdentity,
    ) -> Result<Vec<GithubPrResult>> {
        cli_github_pr_list(worktree_path, branch, repository)
    }

    fn view(
        &mut self,
        worktree_path: &Path,
        selector: &str,
        repository: &GithubRepositoryIdentity,
    ) -> Result<GithubPrResult> {
        cli_github_pr_view(worktree_path, selector, repository)
    }

    fn create(
        &mut self,
        worktree_path: &Path,
        branch: &str,
        base: &str,
        title: &str,
        body: &str,
        draft: bool,
        repository: &GithubRepositoryIdentity,
    ) -> Result<GithubCreateOutput> {
        cli_github_pr_create(worktree_path, branch, base, title, body, draft, repository)
    }
}

pub fn preview_pr(options: PrPublicationOptions) -> Result<PrPublicationReport> {
    preview_pr_with_validation_requirement(options, false)
}

pub fn preview_pr_with_validation_requirement(
    options: PrPublicationOptions,
    require_validation: bool,
) -> Result<PrPublicationReport> {
    let evidence = ValidationEvidenceBundle::legacy(options.validations.clone());
    preview_pr_with_validation_evidence(options, require_validation, evidence)
}

pub fn preview_pr_with_validation_evidence(
    options: PrPublicationOptions,
    require_validation: bool,
    validation_evidence: ValidationEvidenceBundle,
) -> Result<PrPublicationReport> {
    if options.from_branch.is_some() {
        return preview_branch_pr_with_validation_evidence(
            options,
            require_validation,
            validation_evidence,
        );
    }
    ensure_worktree_publication_options(&options)?;
    let preview = build_merge_preview(&options, require_validation, validation_evidence)?;
    publication_report_from_preview(options, preview)
}

/// Previews publication under an already-held managed-worktree write lease.
///
/// Autopilot uses this entrypoint while retaining its mutation authority. The
/// merge collector validates the lease's durable repository and agent binding
/// and snapshots directly under it, so no nested shared lease is acquired.
pub(crate) fn preview_pr_with_validation_evidence_and_write_lease(
    options: PrPublicationOptions,
    require_validation: bool,
    validation_evidence: ValidationEvidenceBundle,
    write_lease: &ManagedWorktreeWriteLease,
) -> Result<PrPublicationReport> {
    ensure_worktree_publication_options(&options)?;
    let preview = build_merge_preview_with_write_lease(
        &options,
        require_validation,
        validation_evidence,
        write_lease,
    )?;
    publication_report_from_preview(options, preview)
}

/// Stabilizes an agent candidate for validation without any push, forge, or PR
/// side effect.
///
/// A dirty candidate is committed locally under the caller's existing write
/// lease and one repository mutation lock. The pre-commit, commit-tree, and
/// post-commit snapshots must describe identical candidate content; only the
/// expected agent HEAD transition may differ.
pub(crate) fn prepare_pr_candidate_with_write_lease(
    options: PrPublicationOptions,
    write_lease: &ManagedWorktreeWriteLease,
) -> Result<PrPublicationReport> {
    prepare_pr_candidate_with_write_lease_after_preview(options, write_lease, |_| {})
}

fn prepare_pr_candidate_with_write_lease_after_preview<F>(
    options: PrPublicationOptions,
    write_lease: &ManagedWorktreeWriteLease,
    after_preview: F,
) -> Result<PrPublicationReport>
where
    F: FnOnce(&PrPublicationReport),
{
    let repo_root = discover_primary_repo_root(&options.repo)?;
    let manager = WorktreeManager::new(&repo_root);
    manager.verify_write_execution_lease(&options.agent_id, write_lease)?;
    let _lock = RepoCommonLock::acquire(&repo_root, "pr-publish")?;
    let initial = preview_pr_with_validation_evidence_and_write_lease(
        options.clone(),
        false,
        ValidationEvidenceBundle::default(),
        write_lease,
    )?;
    after_preview(&initial);
    prepare_pr_candidate_with_verified_authority(options, write_lease, initial)
}

fn prepare_pr_candidate_with_verified_authority(
    options: PrPublicationOptions,
    write_lease: &ManagedWorktreeWriteLease,
    initial: PrPublicationReport,
) -> Result<PrPublicationReport> {
    if initial.readiness == ApplyReadinessStatus::Blocked {
        return Ok(initial);
    }
    let worktree_path = initial.preview.candidate.metadata.worktree_path.clone();
    let initially_dirty = has_uncommitted_changes(&worktree_path)?;
    let stable = preview_pr_with_validation_evidence_and_write_lease(
        options.clone(),
        false,
        ValidationEvidenceBundle::default(),
        write_lease,
    )?;
    if stable.readiness == ApplyReadinessStatus::Blocked {
        return Ok(stable);
    }
    ensure_same_candidate_snapshot(
        &initial.preview.candidate,
        &stable.preview.candidate,
        "before candidate preparation",
    )?;
    if has_uncommitted_changes(&worktree_path)? != initially_dirty {
        bail!("agent worktree dirty state changed before candidate preparation");
    }

    let prepared_commit = if initially_dirty {
        let previous_head = stable
            .preview
            .candidate
            .metadata
            .agent_head
            .as_deref()
            .context("dirty publication candidate has no agent HEAD")?;
        let commit_id = commit_agent_changes(
            &worktree_path,
            &stable.agent_id,
            &stable.changed_paths,
            &stable.preview,
        )?;
        if commit_id.to_string() == previous_head {
            bail!("dirty publication candidate produced an empty local commit capture");
        }
        verify_prepared_commit(
            &worktree_path,
            previous_head,
            commit_id,
            stable.preview.candidate.snapshot_tree,
        )?;
        commit_id
    } else {
        stable
            .preview
            .candidate
            .metadata
            .agent_head
            .as_deref()
            .context("clean publication candidate has no agent HEAD")?
            .parse::<Oid>()
            .context("clean publication candidate agent HEAD is malformed")?
    };

    if has_uncommitted_changes(&worktree_path)? {
        bail!("agent worktree remained dirty after candidate preparation");
    }
    let mut prepared = preview_pr_with_validation_evidence_and_write_lease(
        options,
        false,
        ValidationEvidenceBundle::default(),
        write_lease,
    )?;
    if prepared.readiness == ApplyReadinessStatus::Blocked {
        prepared.commit_id = Some(prepared_commit.to_string());
        prepared.head_id = prepared.preview.candidate.metadata.agent_head.clone();
        return Ok(prepared);
    }
    if initially_dirty {
        ensure_candidate_commit_transition(
            &stable.preview.candidate,
            &prepared.preview.candidate,
            prepared_commit,
        )?;
    } else {
        ensure_same_candidate_snapshot(
            &stable.preview.candidate,
            &prepared.preview.candidate,
            "while confirming an already-clean candidate",
        )?;
    }
    let prepared_commit = prepared_commit.to_string();
    if prepared.preview.candidate.metadata.agent_head.as_deref() != Some(&prepared_commit)
        || prepared
            .preview
            .candidate
            .validation_binding
            .agent_head
            .as_deref()
            != Some(&prepared_commit)
    {
        bail!("prepared candidate HEAD did not match its exact validation binding");
    }
    prepared.status = PrPublicationStatus::Preview;
    prepared.commit_id = Some(prepared_commit.clone());
    prepared.head_id = Some(prepared_commit);
    prepared.pushed = false;
    prepared.created = false;
    prepared.pr_url = None;
    prepared.publication_receipt = None;
    prepared.next_action =
        "validate and review this exact candidate.validation_binding, then call strict prepared publication"
            .to_string();
    Ok(prepared)
}

fn ensure_same_candidate_snapshot(
    before: &MergeCandidate,
    after: &MergeCandidate,
    phase: &str,
) -> Result<()> {
    if before.raw_diff != after.raw_diff
        || before.snapshot_tree != after.snapshot_tree
        || before.claimed_paths != after.claimed_paths
        || before.changed_paths != after.changed_paths
        || before.changes != after.changes
        || before.unclaimed_changed_paths != after.unclaimed_changed_paths
        || before.diff != after.diff
        || before.validations != after.validations
        || before.validation_evidence != after.validation_evidence
        || before.metadata != after.metadata
        || before.validation_binding != after.validation_binding
    {
        bail!("publication candidate changed {phase}; refusing preparation");
    }
    Ok(())
}

fn ensure_candidate_commit_transition(
    before: &MergeCandidate,
    after: &MergeCandidate,
    expected_commit: Oid,
) -> Result<()> {
    if before.raw_diff != after.raw_diff
        || before.snapshot_tree != after.snapshot_tree
        || before.claimed_paths != after.claimed_paths
        || before.changed_paths != after.changed_paths
        || !prepared_change_kinds_match(&before.changes, &after.changes)
        || before.unclaimed_changed_paths != after.unclaimed_changed_paths
        || before.diff != after.diff
        || before.validations != after.validations
        || before.validation_evidence != after.validation_evidence
        || before.metadata.agent_id != after.metadata.agent_id
        || before.metadata.worktree_path != after.metadata.worktree_path
        || before.metadata.branch != after.metadata.branch
        || before.metadata.primary_repo_root != after.metadata.primary_repo_root
        || before.metadata.primary_head != after.metadata.primary_head
        || before.metadata.merge_base != after.metadata.merge_base
        || before.metadata.base_matches_primary != after.metadata.base_matches_primary
        || before.validation_binding.version != after.validation_binding.version
        || before.validation_binding.agent_id != after.validation_binding.agent_id
        || before.validation_binding.primary_head != after.validation_binding.primary_head
        || before.validation_binding.merge_base != after.validation_binding.merge_base
        || before.validation_binding.diff_oid != after.validation_binding.diff_oid
    {
        bail!("publication candidate content or base changed across its local preparation commit");
    }
    let expected_commit = expected_commit.to_string();
    if after.metadata.agent_head.as_deref() != Some(&expected_commit)
        || after.validation_binding.agent_head.as_deref() != Some(&expected_commit)
    {
        bail!("publication candidate did not make the expected preparation HEAD transition");
    }
    Ok(())
}

fn prepared_change_kinds_match(
    before: &[merge::ChangedPath],
    after: &[merge::ChangedPath],
) -> bool {
    before.len() == after.len()
        && before.iter().zip(after).all(|(before, after)| {
            before.path == after.path
                && (before.kind == after.kind
                    || (before.kind == merge::ChangeKind::Untracked
                        && after.kind == merge::ChangeKind::Added))
        })
}

fn verify_prepared_commit(
    worktree_path: &Path,
    expected_parent: &str,
    commit_id: Oid,
    expected_tree: Oid,
) -> Result<()> {
    let repo = crate::git_repository::open(worktree_path).with_context(|| {
        format!(
            "failed to verify prepared worktree {}",
            worktree_path.display()
        )
    })?;
    let commit = repo
        .find_commit(commit_id)
        .context("failed to find prepared publication commit")?;
    let expected_parent =
        Oid::from_str(expected_parent).context("reviewed publication parent HEAD is malformed")?;
    if commit.parent_count() != 1
        || commit.parent_id(0).ok() != Some(expected_parent)
        || commit.tree_id() != expected_tree
        || repo.head().ok().and_then(|head| head.target()) != Some(commit_id)
    {
        bail!("prepared publication commit did not match the reviewed parent, tree, and HEAD");
    }
    Ok(())
}

fn publication_report_from_preview(
    options: PrPublicationOptions,
    preview: MergeApplyPreview,
) -> Result<PrPublicationReport> {
    let primary_repo = crate::git_repository::open(&preview.candidate.metadata.primary_repo_root)
        .context("failed to open primary repository")?;
    let base = options.squash_onto.clone().map(Ok).unwrap_or_else(|| {
        current_branch_name(&primary_repo).map(|name| name.unwrap_or_else(|| "HEAD".to_string()))
    })?;
    let body = pr_body(&preview);
    let status = if preview.safety.readiness.status == ApplyReadinessStatus::Blocked {
        PrPublicationStatus::Blocked
    } else {
        PrPublicationStatus::Preview
    };
    let next_action = match status {
        PrPublicationStatus::Blocked => "resolve merge-preview blockers before publishing",
        PrPublicationStatus::Preview => "run pr publish with an explicit forge when ready",
        PrPublicationStatus::Published => "review the created pull request",
    }
    .to_string();

    Ok(PrPublicationReport {
        status,
        agent_id: options.agent_id,
        branch: preview.candidate.metadata.branch.clone(),
        base,
        base_head: preview.candidate.metadata.primary_head.clone(),
        remote: remote_url(&primary_repo, "origin")
            .ok()
            .map(|url| redact_remote_url(&url)),
        forge: options.forge,
        draft: options.draft,
        title: pr_title(&preview),
        body_summary: summarize_text(&body, SUMMARY_LIMIT),
        changed_paths: preview.candidate.changed_paths.clone(),
        validation_status: preview.safety.validation.status,
        validation_required: preview.safety.validation_required,
        readiness: preview.safety.readiness.status,
        blockers: preview.safety.readiness.blockers.clone(),
        commit_id: None,
        head_id: preview.candidate.metadata.agent_head.clone(),
        pr_url: None,
        pushed: false,
        created: false,
        publication_receipt: None,
        next_action,
        preview,
    })
}

pub fn publish_pr(options: PrPublicationOptions) -> Result<PrPublicationReport> {
    ensure_worktree_publication_options(&options)?;
    let repo_root = discover_primary_repo_root(&options.repo)?;
    let manager = WorktreeManager::new(&repo_root);
    let write_lease = manager
        .acquire_write_execution_lease(&options.agent_id)
        .with_context(|| {
            format!(
                "failed to acquire publication write authority for agent '{}'",
                options.agent_id
            )
        })?;
    publish_pr_with_write_lease(options, &write_lease)
}

fn ensure_worktree_publication_options(options: &PrPublicationOptions) -> Result<()> {
    if options.from_branch.is_some() {
        bail!("worktree publication entrypoint cannot be used with --from-branch");
    }
    if options.squash_onto.is_some() {
        bail!("--squash-onto requires --from-branch");
    }
    if !options.exclude_paths.is_empty() {
        bail!("--exclude requires --from-branch");
    }
    Ok(())
}

pub fn publish_pr_with_validation_requirement(
    options: PrPublicationOptions,
    require_validation: bool,
) -> Result<PrPublicationReport> {
    let evidence = ValidationEvidenceBundle::legacy(options.validations.clone());
    publish_pr_with_validation_evidence(options, require_validation, evidence)
}

pub fn publish_pr_with_validation_evidence(
    options: PrPublicationOptions,
    require_validation: bool,
    validation_evidence: ValidationEvidenceBundle,
) -> Result<PrPublicationReport> {
    if options.from_branch.is_some() {
        return publish_branch_pr_with_validation_evidence(
            options,
            require_validation,
            validation_evidence,
        );
    }
    ensure_worktree_publication_options(&options)?;
    let repo_root = discover_primary_repo_root(&options.repo)?;
    let manager = WorktreeManager::new(&repo_root);
    let write_lease = manager
        .acquire_write_execution_lease(&options.agent_id)
        .with_context(|| {
            format!(
                "failed to acquire publication write authority for agent '{}'",
                options.agent_id
            )
        })?;
    publish_pr_with_validation_evidence_and_write_lease(
        options,
        require_validation,
        validation_evidence,
        &write_lease,
    )
}

#[cfg(all(test, target_os = "linux"))]
fn publish_pr_with_validation_evidence_after_lock<F>(
    options: PrPublicationOptions,
    require_validation: bool,
    validation_evidence: ValidationEvidenceBundle,
    after_lock: F,
) -> Result<PrPublicationReport>
where
    F: FnOnce(),
{
    ensure_worktree_publication_options(&options)?;
    let repo_root = discover_primary_repo_root(&options.repo)?;
    let manager = WorktreeManager::new(&repo_root);
    let write_lease = manager
        .acquire_write_execution_lease(&options.agent_id)
        .with_context(|| {
            format!(
                "failed to acquire publication write authority for agent '{}'",
                options.agent_id
            )
        })?;
    publish_pr_with_validation_evidence_and_write_lease_after_lock(
        options,
        require_validation,
        validation_evidence,
        &write_lease,
        after_lock,
        None,
    )
}

/// Publishes under a borrowed managed-worktree write lease.
///
/// Callers such as Autopilot retain the lease across validation, publication,
/// and subsequent review. This function verifies the lease binding, then
/// acquires the repository mutation lock without reacquiring either lock. Both
/// locks use nonblocking acquisition, and standalone publication takes them in
/// write-lease then repository-lock order to match this borrowed path.
pub(crate) fn publish_pr_with_validation_evidence_and_write_lease(
    options: PrPublicationOptions,
    require_validation: bool,
    validation_evidence: ValidationEvidenceBundle,
    write_lease: &ManagedWorktreeWriteLease,
) -> Result<PrPublicationReport> {
    publish_pr_with_validation_evidence_and_write_lease_after_lock(
        options,
        require_validation,
        validation_evidence,
        write_lease,
        || {},
        None,
    )
}

pub(crate) fn publish_pr_with_write_lease(
    options: PrPublicationOptions,
    write_lease: &ManagedWorktreeWriteLease,
) -> Result<PrPublicationReport> {
    let evidence = ValidationEvidenceBundle::legacy(options.validations.clone());
    publish_pr_with_validation_evidence_and_write_lease(options, false, evidence, write_lease)
}

/// Publishes a previously prepared candidate with mandatory exact validation
/// evidence. There is intentionally no `require_validation` argument: callers
/// cannot downgrade this strict bridge to legacy or unbound validation.
#[cfg(test)]
pub(crate) fn publish_prepared_pr_with_write_lease(
    options: PrPublicationOptions,
    bound_evidence: &BoundValidationEvidenceBundle,
    write_lease: &ManagedWorktreeWriteLease,
) -> Result<PrPublicationReport> {
    if bound_evidence.binding().agent_id != options.agent_id {
        bail!("strict publication evidence belongs to a different agent");
    }
    publish_pr_with_validation_evidence_and_write_lease(
        options,
        true,
        bound_evidence.evidence().clone(),
        write_lease,
    )
}

pub(crate) fn publish_prepared_pr_with_source_guard(
    options: PrPublicationOptions,
    bound_evidence: &BoundValidationEvidenceBundle,
    write_lease: &ManagedWorktreeWriteLease,
    source_guard: Option<ExternalSourceGuard>,
) -> Result<PrPublicationReport> {
    if bound_evidence.binding().agent_id != options.agent_id {
        bail!("strict publication evidence belongs to a different agent");
    }
    publish_pr_with_validation_evidence_and_write_lease_after_lock(
        options,
        true,
        bound_evidence.evidence().clone(),
        write_lease,
        || {},
        source_guard,
    )
}

fn publish_pr_with_validation_evidence_and_write_lease_after_lock<F>(
    options: PrPublicationOptions,
    require_validation: bool,
    validation_evidence: ValidationEvidenceBundle,
    write_lease: &ManagedWorktreeWriteLease,
    after_lock: F,
    source_guard: Option<ExternalSourceGuard>,
) -> Result<PrPublicationReport>
where
    F: FnOnce(),
{
    let repo_root = discover_primary_repo_root(&options.repo)?;
    let manager = WorktreeManager::new(&repo_root);
    manager.verify_write_execution_lease(&options.agent_id, write_lease)?;
    let _lock = RepoCommonLock::acquire(&repo_root, "pr-publish")?;
    after_lock();
    publish_pr_with_verified_authority(
        options,
        require_validation,
        validation_evidence,
        write_lease,
        repo_root,
        source_guard,
    )
}

fn publish_pr_with_verified_authority(
    options: PrPublicationOptions,
    require_validation: bool,
    validation_evidence: ValidationEvidenceBundle,
    write_lease: &ManagedWorktreeWriteLease,
    repo_root: PathBuf,
    source_guard: Option<ExternalSourceGuard>,
) -> Result<PrPublicationReport> {
    let mut report = preview_pr_with_validation_evidence_and_write_lease(
        options.clone(),
        require_validation,
        validation_evidence.clone(),
        write_lease,
    )?;
    if report.readiness == ApplyReadinessStatus::Blocked {
        return Ok(report);
    }

    let worktree_path = report.preview.candidate.metadata.worktree_path.clone();
    let needs_commit = has_uncommitted_changes(&worktree_path)?;
    if require_validation && needs_commit {
        return Ok(block_publication(
            report,
            ApplyBlocker::ValidationMissing,
            "candidate-bound publication requires a clean, committed agent candidate",
            "commit the candidate, rerun pr preview, validate that exact binding, create a bound envelope, then rerun pr publish",
        ));
    }

    let originally_reviewed = report.preview.candidate.validation_binding.clone();
    let mut local_commit = None;
    if needs_commit {
        report = preview_pr_with_validation_evidence_and_write_lease(
            options.clone(),
            false,
            validation_evidence.clone(),
            write_lease,
        )?;
        if report.readiness == ApplyReadinessStatus::Blocked {
            return Ok(report);
        }
        if has_uncommitted_changes(&worktree_path)? {
            let commit_id = commit_agent_changes(
                &worktree_path,
                &report.agent_id,
                &report.changed_paths,
                &report.preview,
            )?;
            local_commit = Some(commit_id.to_string());
            if has_uncommitted_changes(&worktree_path)? {
                let mut changed_during_commit =
                    preview_pr_with_validation_evidence_and_write_lease(
                        options.clone(),
                        false,
                        validation_evidence.clone(),
                        write_lease,
                    )?;
                changed_during_commit.commit_id = local_commit.clone();
                changed_during_commit.head_id = changed_during_commit
                    .preview
                    .candidate
                    .metadata
                    .agent_head
                    .clone();
                return Ok(block_publication(
                    changed_during_commit,
                    ApplyBlocker::StaleBase,
                    "agent worktree changed while the local publication commit was being created",
                    "review and commit the remaining worktree changes, then rerun pr preview before publishing",
                ));
            }
        }
    }

    let mut after_local = preview_pr_with_validation_evidence_and_write_lease(
        options.clone(),
        require_validation,
        validation_evidence.clone(),
        write_lease,
    )?;
    if after_local.readiness == ApplyReadinessStatus::Blocked {
        after_local.commit_id = local_commit.clone();
        after_local.head_id = after_local.preview.candidate.metadata.agent_head.clone();
        return Ok(after_local);
    }
    if !needs_commit && after_local.preview.candidate.validation_binding != originally_reviewed {
        return Ok(block_publication(
            after_local,
            ApplyBlocker::StaleBase,
            "agent or primary candidate changed after the publication preview",
            "rerun pr preview and validation for the current committed candidate before publishing",
        ));
    }
    let reviewed_binding = after_local.preview.candidate.validation_binding.clone();
    let published_commit = if require_validation {
        reviewed_binding.agent_head.clone()
    } else {
        local_commit.clone()
    };
    after_local.commit_id = published_commit.clone();
    after_local.head_id = after_local.preview.candidate.metadata.agent_head.clone();

    let primary_repo =
        crate::git_repository::open(&repo_root).context("failed to open primary repository")?;
    let raw_remote_url = match after_local.forge {
        ForgeKind::Fake => None,
        ForgeKind::Git => Some(
            remote_url(&primary_repo, "origin")
                .context("Git publication requires an 'origin' remote")?,
        ),
        ForgeKind::Github => Some(
            remote_url(&primary_repo, "origin")
                .context("GitHub PR publication requires an 'origin' remote")?,
        ),
    };

    let mut final_report = preview_pr_with_validation_evidence_and_write_lease(
        options,
        require_validation,
        validation_evidence,
        write_lease,
    )?;
    final_report.commit_id = published_commit;
    final_report.head_id = final_report.preview.candidate.metadata.agent_head.clone();
    final_report.remote = raw_remote_url.as_deref().map(redact_remote_url);
    if final_report.readiness == ApplyReadinessStatus::Blocked {
        return Ok(final_report);
    }
    if final_report.preview.candidate.validation_binding != reviewed_binding {
        return Ok(block_publication(
            final_report,
            ApplyBlocker::StaleBase,
            "agent or primary candidate changed before external publication",
            "rerun pr preview and validation for the current committed candidate before publishing",
        ));
    }
    complete_pr_publication_effects(
        final_report,
        &repo_root,
        &worktree_path,
        raw_remote_url,
        source_guard,
    )
}

fn preview_branch_pr_with_validation_evidence(
    options: PrPublicationOptions,
    require_validation: bool,
    validation_evidence: ValidationEvidenceBundle,
) -> Result<PrPublicationReport> {
    ensure_branch_publication_options(&options)?;
    let (preview, excluded_reference) =
        build_branch_publication_preview(&options, require_validation, validation_evidence)?;
    let report = publication_report_from_preview(options, preview)?;
    Ok(block_excluded_reference_if_needed(
        report,
        excluded_reference,
    ))
}

fn publish_branch_pr_with_validation_evidence(
    options: PrPublicationOptions,
    require_validation: bool,
    validation_evidence: ValidationEvidenceBundle,
) -> Result<PrPublicationReport> {
    ensure_branch_publication_options(&options)?;
    let repo_root = discover_primary_repo_root(&options.repo)?;
    let _lock = RepoCommonLock::acquire(&repo_root, "pr-publish")?;
    let mut report = preview_branch_pr_with_validation_evidence(
        options.clone(),
        require_validation,
        validation_evidence.clone(),
    )?;
    if report.readiness == ApplyReadinessStatus::Blocked {
        return Ok(report);
    }
    let reviewed_binding = report.preview.candidate.validation_binding.clone();
    let published_commit = reviewed_binding.agent_head.clone();
    report.commit_id = published_commit.clone();
    report.head_id = report.preview.candidate.metadata.agent_head.clone();

    let primary_repo =
        crate::git_repository::open(&repo_root).context("failed to open primary repository")?;
    let raw_remote_url = publication_remote_url_for_forge(report.forge, &primary_repo)?;
    if options.squash_onto.is_some() || !options.exclude_paths.is_empty() {
        let materialized = materialize_branch_publication_import_commit(&options)?;
        if Some(materialized.to_string()) != reviewed_binding.agent_head {
            return Ok(block_publication(
                report,
                ApplyBlocker::StaleBase,
                "branch publication import commit changed before external publication",
                "rerun pr preview and validation for the current branch candidate before publishing",
            ));
        }
    }

    let mut final_report = preview_branch_pr_with_validation_evidence(
        options,
        require_validation,
        validation_evidence,
    )?;
    final_report.commit_id = published_commit;
    final_report.head_id = final_report.preview.candidate.metadata.agent_head.clone();
    final_report.remote = raw_remote_url.as_deref().map(redact_remote_url);
    if final_report.readiness == ApplyReadinessStatus::Blocked {
        return Ok(final_report);
    }
    if final_report.preview.candidate.validation_binding != reviewed_binding {
        return Ok(block_publication(
            final_report,
            ApplyBlocker::StaleBase,
            "branch publication candidate changed before external publication",
            "rerun pr preview and validation for the current branch candidate before publishing",
        ));
    }
    complete_pr_publication_effects(final_report, &repo_root, &repo_root, raw_remote_url, None)
}

fn ensure_branch_publication_options(options: &PrPublicationOptions) -> Result<()> {
    let branch = options
        .from_branch
        .as_deref()
        .context("--from-branch is required for branch publication")?;
    validate_publication_branch_name(branch, "from-branch")?;
    if let Some(base) = options.squash_onto.as_deref() {
        validate_publication_branch_name(base, "squash-onto")?;
    }
    Ok(())
}

fn publication_remote_url_for_forge(forge: ForgeKind, repo: &Repository) -> Result<Option<String>> {
    match forge {
        ForgeKind::Fake => Ok(None),
        ForgeKind::Git => Ok(Some(
            remote_url(repo, "origin").context("Git publication requires an 'origin' remote")?,
        )),
        ForgeKind::Github => Ok(Some(
            remote_url(repo, "origin")
                .context("GitHub PR publication requires an 'origin' remote")?,
        )),
    }
}

fn build_branch_publication_preview(
    options: &PrPublicationOptions,
    require_validation: bool,
    validation_evidence: ValidationEvidenceBundle,
) -> Result<(MergeApplyPreview, Option<ExcludedReference>)> {
    let repo_root = discover_primary_repo_root(&options.repo)?;
    let repo = crate::git_repository::open(&repo_root)
        .with_context(|| format!("failed to open primary repository {}", repo_root.display()))?;
    let source_branch = options
        .from_branch
        .as_deref()
        .context("--from-branch is required for branch publication")?;
    let base_branch = branch_publication_base(&repo, options.squash_onto.as_deref())?;
    if source_branch == base_branch {
        bail!("--from-branch must differ from the publication base branch");
    }

    let excluded_paths = normalize_exclude_paths(&options.exclude_paths)?;
    let source_oid = branch_head_oid(&repo, source_branch, "from-branch")?;
    let base_oid = branch_head_oid(&repo, &base_branch, "publication base")?;
    let current_head = repo.head().ok().and_then(|head| head.target());
    let source_commit = repo
        .find_commit(source_oid)
        .with_context(|| format!("failed to read from-branch commit {source_oid}"))?;
    let base_commit = repo
        .find_commit(base_oid)
        .with_context(|| format!("failed to read publication base commit {base_oid}"))?;
    let source_tree = source_commit
        .tree()
        .context("failed to read from-branch tree")?;
    let publish_tree_id = filtered_tree_id(&repo, &source_tree, &excluded_paths)?;
    let needs_import = options.squash_onto.is_some() || !excluded_paths.is_empty();
    let (publish_head, merge_base) = if needs_import {
        (
            planned_squashed_import_commit_oid(
                &repo,
                &base_commit,
                publish_tree_id,
                source_branch,
                source_oid,
                &base_branch,
                &excluded_paths,
            )?,
            Some(base_oid),
        )
    } else {
        (source_oid, merge_base_or_none(&repo, base_oid, source_oid)?)
    };

    let base_tree = base_commit
        .tree()
        .context("failed to read publication base tree")?;
    let publish_tree = repo
        .find_tree(publish_tree_id)
        .context("failed to read branch publication tree")?;
    let (changes, raw_diff) = diff_trees(&repo, &base_tree, &publish_tree)?;
    let changed_paths = changes
        .iter()
        .map(|change| change.path.clone())
        .collect::<Vec<_>>();
    let claimed_paths = if options.claimed_paths.is_empty() {
        changed_paths.clone()
    } else {
        merge::normalize_claim_paths(options.claimed_paths.clone())?
    };
    let unclaimed_changed_paths = merge::unclaimed_paths(&changed_paths, &claimed_paths);
    let presented_diff = merge::patch_text_for_json(&raw_diff);
    let metadata = WorktreeMergeMetadata {
        agent_id: options.agent_id.clone(),
        worktree_path: repo_root.clone(),
        branch: branch_publication_report_branch(source_branch, needs_import),
        primary_repo_root: repo_root,
        primary_head: Some(base_oid.to_string()),
        agent_head: Some(publish_head.to_string()),
        merge_base: merge_base.map(|oid| oid.to_string()),
        base_matches_primary: Some(current_head == Some(base_oid) && merge_base == Some(base_oid)),
    };
    let validation_binding = merge::candidate_validation_binding(&metadata, &raw_diff)?;
    let validations = validation_evidence.reports();
    let diff = DiffOutput {
        summary: summarize_text(&presented_diff, options_diff_summary_limit()),
        full: Some(presented_diff),
    };
    let candidate = MergeCandidate {
        metadata,
        claimed_paths,
        changed_paths: changed_paths.clone(),
        changes,
        unclaimed_changed_paths,
        diff,
        validations,
        validation_binding,
        validation_evidence,
        raw_diff,
        snapshot_tree: publish_tree_id,
    };
    let excluded_reference = find_excluded_reference(&repo, &publish_tree, &excluded_paths)?;
    let preview = merge::build_merge_apply_preview(
        candidate,
        MergeForceOptions::default(),
        require_validation,
    )?;
    Ok((preview, excluded_reference))
}

fn options_diff_summary_limit() -> usize {
    merge::DEFAULT_DIFF_SUMMARY_CHAR_LIMIT
}

fn branch_publication_base(repo: &Repository, squash_onto: Option<&str>) -> Result<String> {
    if let Some(base) = squash_onto {
        validate_publication_branch_name(base, "squash-onto")?;
        return Ok(base.to_string());
    }
    current_branch_name(repo)?
        .filter(|branch| branch != "HEAD")
        .context("branch publication requires a checked-out base branch or --squash-onto")
}

fn branch_head_oid(repo: &Repository, branch: &str, label: &str) -> Result<Oid> {
    validate_publication_branch_name(branch, label)?;
    let branch = repo
        .find_branch(branch, BranchType::Local)
        .with_context(|| format!("{label} branch '{branch}' was not found locally"))?;
    branch
        .get()
        .target()
        .with_context(|| format!("{label} branch did not point at a commit"))
}

fn normalize_exclude_paths(paths: &[PathBuf]) -> Result<Vec<PathBuf>> {
    paths
        .iter()
        .map(|path| normalize_repo_relative_path(path).map_err(anyhow::Error::from))
        .collect::<Result<BTreeSet<_>>>()
        .map(|paths| paths.into_iter().collect())
}

fn merge_base_or_none(repo: &Repository, base: Oid, head: Oid) -> Result<Option<Oid>> {
    match repo.merge_base(base, head) {
        Ok(oid) => Ok(Some(oid)),
        Err(error) if error.code() == git2::ErrorCode::NotFound => Ok(None),
        Err(error) => Err(error).context("failed to compute branch publication merge base"),
    }
}

fn branch_publication_report_branch(source_branch: &str, import_commit: bool) -> String {
    if import_commit {
        format!(
            "maco/branch-publish/{}-{:016x}",
            sanitize_url_segment(source_branch),
            stable_hash(source_branch.as_bytes())
        )
    } else {
        source_branch.to_string()
    }
}

fn planned_squashed_import_commit_oid(
    repo: &Repository,
    base_commit: &git2::Commit<'_>,
    tree_id: Oid,
    source_branch: &str,
    source_oid: Oid,
    base_branch: &str,
    excluded_paths: &[PathBuf],
) -> Result<Oid> {
    let bytes = squashed_import_commit_bytes(
        repo,
        base_commit,
        tree_id,
        source_branch,
        source_oid,
        base_branch,
        excluded_paths,
    )?;
    Oid::hash_object(ObjectType::Commit, &bytes)
        .context("failed to hash deterministic branch publication import commit")
}

fn materialize_branch_publication_import_commit(options: &PrPublicationOptions) -> Result<Oid> {
    let repo_root = discover_primary_repo_root(&options.repo)?;
    let repo = crate::git_repository::open(&repo_root)
        .with_context(|| format!("failed to open primary repository {}", repo_root.display()))?;
    let source_branch = options
        .from_branch
        .as_deref()
        .context("--from-branch is required for branch publication")?;
    let base_branch = branch_publication_base(&repo, options.squash_onto.as_deref())?;
    let excluded_paths = normalize_exclude_paths(&options.exclude_paths)?;
    let source_oid = branch_head_oid(&repo, source_branch, "from-branch")?;
    let base_oid = branch_head_oid(&repo, &base_branch, "publication base")?;
    let source_commit = repo
        .find_commit(source_oid)
        .with_context(|| format!("failed to read from-branch commit {source_oid}"))?;
    let base_commit = repo
        .find_commit(base_oid)
        .with_context(|| format!("failed to read publication base commit {base_oid}"))?;
    let source_tree = source_commit
        .tree()
        .context("failed to read from-branch tree")?;
    let publish_tree_id = filtered_tree_id(&repo, &source_tree, &excluded_paths)?;
    let bytes = squashed_import_commit_bytes(
        &repo,
        &base_commit,
        publish_tree_id,
        source_branch,
        source_oid,
        &base_branch,
        &excluded_paths,
    )?;
    let oid = Oid::hash_object(ObjectType::Commit, &bytes)
        .context("failed to hash deterministic branch publication import commit")?;
    let written = repo
        .odb()
        .context("failed to open publication object database")?
        .write(ObjectType::Commit, &bytes)
        .context("failed to write deterministic branch publication import commit")?;
    if written != oid {
        bail!("written branch publication import commit did not match its planned OID");
    }
    Ok(written)
}

fn squashed_import_commit_bytes(
    repo: &Repository,
    base_commit: &git2::Commit<'_>,
    tree_id: Oid,
    source_branch: &str,
    source_oid: Oid,
    base_branch: &str,
    excluded_paths: &[PathBuf],
) -> Result<Vec<u8>> {
    let tree = repo
        .find_tree(tree_id)
        .context("failed to read filtered branch tree for squash import")?;
    let signature = deterministic_publication_signature()?;
    let message =
        squashed_import_commit_message(source_branch, source_oid, base_branch, excluded_paths);
    let buffer = repo
        .commit_create_buffer(&signature, &signature, &message, &tree, &[base_commit])
        .context("failed to build deterministic branch publication import commit")?;
    Ok(buffer.as_ref().to_vec())
}

fn deterministic_publication_signature() -> Result<Signature<'static>> {
    Signature::new(
        "maco publication",
        "maco-publication@example.invalid",
        &Time::new(0, 0),
    )
    .context("failed to build deterministic publication signature")
}

fn squashed_import_commit_message(
    source_branch: &str,
    source_oid: Oid,
    base_branch: &str,
    excluded_paths: &[PathBuf],
) -> String {
    let mut message = format!(
        "maco: import {source_branch} snapshot\n\nSource branch: {source_branch}\nSource commit: {source_oid}\nBase branch: {base_branch}\n"
    );
    if !excluded_paths.is_empty() {
        message.push_str("\nExcluded paths:\n");
        for path in excluded_paths {
            message.push_str("- ");
            message.push_str(&merge::path_json_text(path));
            message.push('\n');
        }
    }
    message
}

fn filtered_tree_id(
    repo: &Repository,
    source_tree: &Tree<'_>,
    excluded_paths: &[PathBuf],
) -> Result<Oid> {
    if excluded_paths.is_empty() {
        return Ok(source_tree.id());
    }
    let mut tree_id = source_tree.id();
    for path in excluded_paths {
        let tree = repo
            .find_tree(tree_id)
            .context("failed to read tree while applying publication exclusions")?;
        tree_id = remove_path_from_tree(repo, &tree, path)?;
    }
    Ok(tree_id)
}

fn remove_path_from_tree(repo: &Repository, tree: &Tree<'_>, path: &Path) -> Result<Oid> {
    let components = repo_path_components(path)?;
    remove_components_from_tree(repo, tree, &components)
}

fn remove_components_from_tree(
    repo: &Repository,
    tree: &Tree<'_>,
    components: &[String],
) -> Result<Oid> {
    let name = components
        .first()
        .context("publication exclusion path was empty")?;
    let mut builder = repo
        .treebuilder(Some(tree))
        .context("failed to create tree filter builder")?;
    if components.len() == 1 {
        match builder.remove(name.as_str()) {
            Ok(()) => {}
            Err(error) if error.code() == git2::ErrorCode::NotFound => {}
            Err(error) => return Err(error).context("failed to remove excluded path from tree"),
        }
        return builder.write().context("failed to write filtered tree");
    }
    if let Some(entry) = tree.get_name(name) {
        if entry.kind() == Some(ObjectType::Tree) {
            let child = entry
                .to_object(repo)
                .context("failed to read tree entry for exclusion")?
                .peel_to_tree()
                .context("failed to peel exclusion entry to tree")?;
            let child_id = remove_components_from_tree(repo, &child, &components[1..])?;
            builder
                .insert(name.as_str(), child_id, 0o040000)
                .context("failed to insert filtered subtree")?;
        }
    }
    builder.write().context("failed to write filtered tree")
}

fn repo_path_components(path: &Path) -> Result<Vec<String>> {
    path.components()
        .map(|component| match component {
            std::path::Component::Normal(segment) => segment
                .to_str()
                .map(|segment| segment.to_string())
                .context("publication path component was not UTF-8"),
            _ => bail!("publication path was not normalized"),
        })
        .collect()
}

fn diff_trees(
    repo: &Repository,
    base_tree: &Tree<'_>,
    publish_tree: &Tree<'_>,
) -> Result<(Vec<ChangedPath>, Vec<u8>)> {
    let mut options = DiffOptions::new();
    let diff = repo
        .diff_tree_to_tree(Some(base_tree), Some(publish_tree), Some(&mut options))
        .context("failed to diff branch publication trees")?;
    let changes = diff
        .deltas()
        .map(|delta| {
            let path = delta
                .new_file()
                .path()
                .or_else(|| delta.old_file().path())
                .context("branch publication diff omitted path")?
                .to_path_buf();
            Ok(ChangedPath {
                path,
                kind: change_kind_from_delta(delta.status()),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let mut raw_diff = Vec::new();
    diff.print(DiffFormat::Patch, |_delta, _hunk, line| {
        if matches!(line.origin(), ' ' | '+' | '-') {
            raw_diff.push(line.origin() as u8);
        }
        raw_diff.extend_from_slice(line.content());
        true
    })
    .context("failed to render branch publication diff")?;
    Ok((changes, raw_diff))
}

fn change_kind_from_delta(delta: Delta) -> ChangeKind {
    match delta {
        Delta::Added => ChangeKind::Added,
        Delta::Deleted => ChangeKind::Deleted,
        Delta::Modified => ChangeKind::Modified,
        Delta::Renamed => ChangeKind::Renamed,
        Delta::Typechange => ChangeKind::Typechange,
        Delta::Untracked => ChangeKind::Untracked,
        Delta::Conflicted => ChangeKind::Conflicted,
        _ => ChangeKind::Unknown,
    }
}

#[derive(Debug)]
struct ExcludedReference {
    excluded_path: PathBuf,
    referencing_path: PathBuf,
    pattern: String,
}

fn find_excluded_reference(
    repo: &Repository,
    tree: &Tree<'_>,
    excluded_paths: &[PathBuf],
) -> Result<Option<ExcludedReference>> {
    if excluded_paths.is_empty() {
        return Ok(None);
    }
    let patterns = excluded_paths
        .iter()
        .map(|path| (path.clone(), excluded_reference_patterns(path)))
        .collect::<Vec<_>>();
    find_excluded_reference_in_tree(repo, tree, PathBuf::new(), &patterns)
}

fn find_excluded_reference_in_tree(
    repo: &Repository,
    tree: &Tree<'_>,
    prefix: PathBuf,
    patterns: &[(PathBuf, Vec<String>)],
) -> Result<Option<ExcludedReference>> {
    for entry in tree {
        let name = entry
            .name()
            .context("publication tree entry name was not UTF-8")?;
        let path = prefix.join(name);
        match entry.kind() {
            Some(ObjectType::Tree) => {
                let child = entry
                    .to_object(repo)
                    .context("failed to read publication subtree")?
                    .peel_to_tree()
                    .context("failed to peel publication subtree")?;
                if let Some(reference) =
                    find_excluded_reference_in_tree(repo, &child, path, patterns)?
                {
                    return Ok(Some(reference));
                }
            }
            Some(ObjectType::Blob) => {
                let blob = entry
                    .to_object(repo)
                    .context("failed to read publication blob")?
                    .peel_to_blob()
                    .context("failed to peel publication blob")?;
                if blob.size() > MAX_EXCLUSION_REFERENCE_FILE_BYTES {
                    continue;
                }
                let Ok(text) = std::str::from_utf8(blob.content()) else {
                    continue;
                };
                for (excluded_path, excluded_patterns) in patterns {
                    if let Some(pattern) = excluded_patterns
                        .iter()
                        .find(|pattern| text.contains(pattern.as_str()))
                    {
                        return Ok(Some(ExcludedReference {
                            excluded_path: excluded_path.clone(),
                            referencing_path: path,
                            pattern: pattern.clone(),
                        }));
                    }
                }
            }
            _ => {}
        }
    }
    Ok(None)
}

fn excluded_reference_patterns(path: &Path) -> Vec<String> {
    let mut patterns = vec![merge::path_json_text(path)];
    if let Some(file_name) = path.file_name().and_then(|name| name.to_str()) {
        patterns.push(format!("\"{file_name}\""));
        patterns.push(format!("r#\"{file_name}\"#"));
    }
    if let Some(module) = rust_module_name(path) {
        patterns.push(format!("mod {module};"));
        patterns.push(format!("pub mod {module};"));
        patterns.push(format!("mod {module} {{"));
    }
    patterns.sort();
    patterns.dedup();
    patterns
}

fn rust_module_name(path: &Path) -> Option<String> {
    if path.extension().and_then(|extension| extension.to_str()) != Some("rs") {
        return None;
    }
    let stem = path.file_stem()?.to_str()?;
    if stem == "mod" {
        path.parent()?
            .file_name()?
            .to_str()
            .map(ToString::to_string)
    } else {
        Some(stem.to_string())
    }
}

fn block_excluded_reference_if_needed(
    report: PrPublicationReport,
    reference: Option<ExcludedReference>,
) -> PrPublicationReport {
    let Some(reference) = reference else {
        return report;
    };
    let message = format!(
        "published tree still references excluded path {} from {} using '{}'",
        merge::path_json_text(&reference.excluded_path),
        merge::path_json_text(&reference.referencing_path),
        reference.pattern
    );
    block_publication(
        report,
        ApplyBlocker::ExcludedReference,
        &message,
        "remove the reference to the excluded path or publish without that exclusion",
    )
}

fn complete_pr_publication_effects(
    mut report: PrPublicationReport,
    repo_root: &Path,
    worktree_path: &Path,
    raw_remote_url: Option<String>,
    source_guard: Option<ExternalSourceGuard>,
) -> Result<PrPublicationReport> {
    match report.forge {
        ForgeKind::Fake => {
            report.pr_url = Some(fake_pr_url(
                &report.agent_id,
                &report.branch,
                &report.changed_paths,
            ));
            report.created = true;
            report.next_action = "review the fake pull request report locally".to_string();
        }
        ForgeKind::Git => {
            let expected_head = report
                .head_id
                .as_deref()
                .context("validated publication candidate has no HEAD commit")?
                .to_string();
            let remote_url = raw_remote_url
                .as_deref()
                .context("Git publication report has no origin URL")?;
            let mut transaction = PublicationTransaction::open(
                repo_root,
                &report,
                "origin",
                remote_url,
                &expected_head,
                source_guard.clone(),
            )?;
            report.publication_receipt = Some(transaction.receipt());
            if let Err(error) = ensure_remote_expected_commit(worktree_path, &mut transaction) {
                return Ok(publication_transaction_failure(
                    report,
                    &mut transaction,
                    error,
                ));
            }
            report.pushed = true;
            report.created = false;
            report.pr_url = None;
            report.next_action = "open a pull request on your Git host manually".to_string();
            let previous = transaction.journal.clone();
            transaction.advance_phase(PublicationTransactionPhase::Completed);
            transaction.journal.last_error = None;
            if let Err(error) = transaction.persist_if_changed(&previous) {
                return Ok(publication_transaction_failure(
                    report,
                    &mut transaction,
                    error,
                ));
            }
            report.publication_receipt = Some(transaction.receipt());
        }
        ForgeKind::Github => {
            merge::resolve_trusted_executable("gh")
                .context("GitHub publication requires a trusted gh executable")?;
            let expected_head = report
                .head_id
                .as_deref()
                .context("validated publication candidate has no HEAD commit")?
                .to_string();
            let remote_url = raw_remote_url
                .as_deref()
                .context("GitHub publication report has no origin URL")?;
            let mut transaction = PublicationTransaction::open(
                repo_root,
                &report,
                "origin",
                remote_url,
                &expected_head,
                source_guard.clone(),
            )?;
            report.publication_receipt = Some(transaction.receipt());
            if let Err(error) =
                ensure_github_remote_expected_commit(worktree_path, &mut transaction)
            {
                return Ok(publication_transaction_failure(
                    report,
                    &mut transaction,
                    error,
                ));
            }
            report.pushed = true;
            report.publication_receipt = Some(transaction.receipt());
            let github = match reconcile_github_pr(worktree_path, &mut transaction) {
                Ok(github) => github,
                Err(error) => {
                    return Ok(publication_transaction_failure(
                        report,
                        &mut transaction,
                        error,
                    ))
                }
            };
            report.pr_url = Some(github.url);
            report.pushed = true;
            report.created = github.created;
            report.next_action = "review the draft pull request on GitHub".to_string();
            let previous = transaction.journal.clone();
            transaction.advance_phase(PublicationTransactionPhase::Completed);
            transaction.journal.last_error = None;
            if let Err(error) = transaction.persist_if_changed(&previous) {
                return Ok(publication_transaction_failure(
                    report,
                    &mut transaction,
                    error,
                ));
            }
            report.publication_receipt = Some(transaction.receipt());
        }
    }

    report.status = PrPublicationStatus::Published;
    Ok(report)
}

fn block_publication(
    mut report: PrPublicationReport,
    blocker: ApplyBlocker,
    message: &str,
    next_action: &str,
) -> PrPublicationReport {
    let paths = report.preview.candidate.changed_paths.clone();
    report.preview.safety.readiness.blockers.push(blocker);
    report.preview.safety.readiness.blockers.sort();
    report.preview.safety.readiness.blockers.dedup();
    report
        .preview
        .safety
        .readiness
        .details
        .push(ApplyBlockerDetail {
            kind: blocker,
            disposition: ApplyBlockerDisposition::Blocked,
            check_status: SafetyCheckStatus::Failed,
            paths,
            message: Some(message.to_string()),
            validation_reports: report.preview.candidate.validations.clone(),
            validation_commands: report.preview.safety.candidate_validation_commands.clone(),
            next_safe_operation: Some(next_action.to_string()),
        });
    report.preview.safety.readiness.status = ApplyReadinessStatus::Blocked;
    report.status = PrPublicationStatus::Blocked;
    report.readiness = ApplyReadinessStatus::Blocked;
    report.blockers = report.preview.safety.readiness.blockers.clone();
    report.pushed = false;
    report.created = false;
    report.pr_url = None;
    report.next_action = next_action.to_string();
    report
}

fn publication_transaction_failure(
    mut report: PrPublicationReport,
    transaction: &mut PublicationTransaction,
    error: anyhow::Error,
) -> PrPublicationReport {
    let mut message = format!("{error:#}");
    transaction.journal.last_error = Some(message.clone());
    if let Err(journal_error) = transaction.persist() {
        message.push_str(&format!(
            "; additionally failed to persist the latest transaction error: {journal_error:#}"
        ));
        transaction.journal.last_error = Some(message.clone());
    }
    report.status = PrPublicationStatus::Blocked;
    // A failing attempt has no current end-to-end observation. The durable receipt retains the
    // last verified push OID, but the report must not present that historical observation as the
    // current attempt's success.
    report.pushed = false;
    report.pr_url = transaction.journal.pr_url.clone();
    report.created = transaction.journal.created_by_transaction;
    report.publication_receipt = Some(transaction.receipt());
    report.next_action = format!(
        "publication transaction is incomplete: {message}; rerun the same pr publish command to reconcile the durable receipt"
    );
    report
}

fn discover_primary_repo_root(repo_path: &Path) -> Result<PathBuf> {
    let repo = crate::git_repository::discover(repo_path)
        .with_context(|| format!("failed to discover repository from {}", repo_path.display()))?;
    repo.workdir()
        .map(Path::to_path_buf)
        .context("PR publication requires a non-bare primary repository")
}

pub fn preview_issue(options: IssuePublicationOptions) -> Result<IssuePublicationReport> {
    let (redacted_body, redactions) = redacted_body(&options.body);
    Ok(IssuePublicationReport {
        title: normalize_title(&options.title)?,
        redacted_body,
        redactions,
        labels: normalized_labels(options.labels),
        forge: options.forge,
        url: None,
        created: false,
        next_action: "run issue create with an explicit forge when ready".to_string(),
    })
}

pub fn create_issue(options: IssuePublicationOptions) -> Result<IssuePublicationReport> {
    let repo = options.repo.clone();
    let mut report = preview_issue(options)?;
    let url = match report.forge {
        ForgeKind::Fake => fake_issue_url(&report.title, &report.redacted_body, &report.labels),
        ForgeKind::Git => bail!("git forge does not create issues; use fake or github"),
        ForgeKind::Github => {
            create_github_issue(&repo, &report.title, &report.redacted_body, &report.labels)?
        }
    };
    report.url = Some(url);
    report.created = true;
    report.next_action = match report.forge {
        ForgeKind::Fake => "review the fake issue report locally",
        ForgeKind::Git => "use fake or github issue publication",
        ForgeKind::Github => "review the created GitHub issue",
    }
    .to_string();
    Ok(report)
}

fn build_merge_preview(
    options: &PrPublicationOptions,
    require_validation: bool,
    validation_evidence: ValidationEvidenceBundle,
) -> Result<MergeApplyPreview> {
    merge::preview_merge_apply_with_evidence(
        MergePreviewOptions {
            collect: MergeCollectOptions {
                repo: options.repo.clone(),
                agent_id: options.agent_id.clone(),
                claimed_paths: options.claimed_paths.clone(),
                include_full_diff: true,
                diff_summary_char_limit: merge::DEFAULT_DIFF_SUMMARY_CHAR_LIMIT,
                validations: Vec::new(),
            },
            forces: MergeForceOptions::default(),
            require_validation,
        },
        validation_evidence,
    )
}

fn build_merge_preview_with_write_lease(
    options: &PrPublicationOptions,
    require_validation: bool,
    validation_evidence: ValidationEvidenceBundle,
    write_lease: &ManagedWorktreeWriteLease,
) -> Result<MergeApplyPreview> {
    merge::preview_merge_apply_with_evidence_and_write_lease(
        MergePreviewOptions {
            collect: MergeCollectOptions {
                repo: options.repo.clone(),
                agent_id: options.agent_id.clone(),
                claimed_paths: options.claimed_paths.clone(),
                include_full_diff: true,
                diff_summary_char_limit: merge::DEFAULT_DIFF_SUMMARY_CHAR_LIMIT,
                validations: Vec::new(),
            },
            forces: MergeForceOptions::default(),
            require_validation,
        },
        validation_evidence,
        write_lease,
    )
}

fn pr_title(preview: &MergeApplyPreview) -> String {
    format!("Agent {} changes", preview.candidate.metadata.agent_id)
}

fn pr_body(preview: &MergeApplyPreview) -> String {
    let changed = preview
        .candidate
        .changed_paths
        .iter()
        .map(|path| format!("- {}", merge::path_json_text(path)))
        .collect::<Vec<_>>()
        .join("\n");
    let changed = if changed.is_empty() {
        "- no changed paths".to_string()
    } else {
        changed
    };
    format!(
        "Agent: {}\nBranch: {}\nBase: {}\nReadiness: {:?}\n\nChanged paths:\n{}\n",
        preview.candidate.metadata.agent_id,
        preview.candidate.metadata.branch,
        preview
            .candidate
            .metadata
            .primary_head
            .as_deref()
            .unwrap_or("unknown"),
        preview.safety.readiness.status,
        changed
    )
}

#[cfg(test)]
fn generate_publication_pr_marker_nonce() -> Result<String> {
    let mut bytes = ZeroizingBytes(vec![0_u8; PUBLICATION_PR_MARKER_BYTES]);
    fill_os_random(bytes.as_mut_slice())?;
    Ok(bytes
        .as_slice()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

#[cfg(test)]
fn validate_publication_pr_marker_nonce(value: &str) -> Result<()> {
    if value.len() != PUBLICATION_PR_MARKER_BYTES * 2
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        bail!("GitHub publication marker nonce was not canonical");
    }
    Ok(())
}

#[cfg(test)]
fn pr_body_with_publication_marker(body: &str, nonce: &str) -> Result<String> {
    validate_publication_pr_marker_nonce(nonce)?;
    if body.len() > MAX_GITHUB_RECEIPT_BODY_BYTES.saturating_sub(128) {
        bail!("GitHub publication body exceeds its marker-bound safety limit");
    }
    Ok(format!(
        "{body}\n<!-- maco-publication-marker:{nonce} -->\n"
    ))
}

fn has_uncommitted_changes(worktree_path: &Path) -> Result<bool> {
    let repo = crate::git_repository::open(worktree_path)
        .with_context(|| format!("failed to open agent worktree {}", worktree_path.display()))?;
    let mut options = git2::StatusOptions::new();
    options.include_untracked(true).recurse_untracked_dirs(true);
    let statuses = repo
        .statuses(Some(&mut options))
        .context("failed to inspect agent worktree status")?;
    Ok(!statuses.is_empty())
}

fn commit_agent_changes(
    worktree_path: &Path,
    agent_id: &str,
    changed_paths: &[PathBuf],
    preview: &MergeApplyPreview,
) -> Result<Oid> {
    if changed_paths.is_empty() {
        bail!("agent worktree has local changes but merge preview found no changed paths");
    }

    let repo = crate::git_repository::open(worktree_path)
        .with_context(|| format!("failed to open agent worktree {}", worktree_path.display()))?;
    let signature = repo.signature().context(
        "git identity missing; configure user.name and user.email before publishing uncommitted agent changes",
    )?;
    let parent = repo
        .head()
        .context("agent worktree has no HEAD commit")?
        .peel_to_commit()
        .context("failed to read agent HEAD commit")?;
    let (captured_paths, raw_diff) =
        merge::capture_worktree_diff_from_commit(&repo, worktree_path, parent.id())?;
    let allowed = changed_paths.iter().collect::<BTreeSet<_>>();
    let unexpected = captured_paths
        .iter()
        .filter(|path| !allowed.contains(path))
        .cloned()
        .collect::<Vec<_>>();
    if !unexpected.is_empty() {
        bail!(
            "agent worktree changed outside the reviewed publication paths during commit capture: {:?}",
            unexpected
        );
    }
    let diff = git2::Diff::from_buffer(&raw_diff)
        .context("failed to parse isolated publication commit diff")?;
    let parent_tree = parent.tree().context("failed to read agent parent tree")?;
    let mut index = repo
        .apply_to_tree(&parent_tree, &diff, None)
        .context("failed to apply isolated publication diff to parent tree")?;
    let tree_id = index
        .write_tree_to(&repo)
        .context("failed to write publication commit tree")?;
    let tree = repo
        .find_tree(tree_id)
        .context("failed to read publication commit tree")?;
    if tree_id != preview.candidate.snapshot_tree {
        bail!("agent worktree changed before the exact reviewed publication tree was committed");
    }
    if parent.tree_id() == tree_id {
        return Ok(parent.id());
    }
    let parents = [&parent];
    let message = commit_message(agent_id, preview);
    let commit_id = repo
        .commit(
            Some("HEAD"),
            &signature,
            &signature,
            &message,
            &tree,
            &parents,
        )
        .context("failed to commit agent worktree changes")?;
    let mut worktree_index = repo
        .index()
        .context("failed to reopen publication worktree index")?;
    worktree_index
        .read_tree(&tree)
        .context("failed to align publication worktree index with committed tree")?;
    worktree_index
        .write()
        .context("failed to persist publication worktree index")?;
    Ok(commit_id)
}

fn commit_message(agent_id: &str, preview: &MergeApplyPreview) -> String {
    let paths = preview
        .candidate
        .changed_paths
        .iter()
        .map(|path| format!("- {}", merge::path_json_text(path)))
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        "maco: publish {agent_id} changes\n\nGenerated by maco pr publish after merge-preview gates passed.\n\nChanged paths:\n{paths}\n"
    )
}

fn current_branch_name(repo: &Repository) -> Result<Option<String>> {
    repo.find_reference("HEAD")
        .context("failed to inspect current HEAD backlink")?
        .symbolic_target()
        .context("current HEAD symbolic target is not valid UTF-8")?;
    match repo.head() {
        Ok(head) => head
            .shorthand()
            .map(|name| Some(name.to_owned()))
            .context("current branch shorthand is not valid UTF-8"),
        Err(error) if error.code() == git2::ErrorCode::UnbornBranch => Ok(None),
        Err(error) => Err(error).context("failed to inspect current branch"),
    }
}

fn remote_url(repo: &Repository, name: &str) -> Result<String> {
    let remote = repo
        .find_remote(name)
        .with_context(|| format!("remote '{name}' is not configured"))?;
    remote
        .url()
        .map(ToOwned::to_owned)
        .with_context(|| format!("remote '{name}' URL is not valid UTF-8"))
}

fn redact_remote_url(url: &str) -> String {
    let query = url.find('?');
    let fragment = url.find('#');
    let identity_end = query.into_iter().chain(fragment).min().unwrap_or(url.len());
    let identity = &url[..identity_end];
    let mut redacted = if let Some(scheme_end) = identity.find("://") {
        let authority_start = scheme_end + 3;
        let authority_end = identity[authority_start..]
            .find('/')
            .map(|offset| authority_start + offset)
            .unwrap_or(identity.len());
        let authority = &identity[authority_start..authority_end];
        if let Some(at) = authority.rfind('@') {
            let host = &authority[at + 1..];
            format!(
                "{}<redacted>@{}{}",
                &identity[..authority_start],
                host,
                &identity[authority_end..]
            )
        } else {
            identity.to_string()
        }
    } else if let Some(at) = identity.find('@') {
        if identity[at + 1..].contains(':') {
            format!("<redacted>@{}", &identity[at + 1..])
        } else {
            identity.to_string()
        }
    } else {
        identity.to_string()
    };
    if query.is_some_and(|index| fragment.is_none_or(|fragment| index < fragment)) {
        redacted.push_str("?<redacted>");
    }
    if fragment.is_some() {
        redacted.push_str("#<redacted>");
    }
    redacted
}

include!("publication/part2.rs");
include!("publication/part3.rs");

#[cfg(test)]
mod tests;
