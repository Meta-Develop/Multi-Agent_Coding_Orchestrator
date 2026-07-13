use crate::{
    artifacts::{repository_auth_writer, state_auth::sha256_hex},
    effect_wal::{EffectPhase, EffectWal},
    llm::{RedactionSummary, Redactor},
    merge::{
        self, ApplyBlocker, ApplyBlockerDetail, ApplyBlockerDisposition, ApplyReadinessStatus,
        BoundValidationEvidenceBundle, MergeApplyPreview, MergeCandidate, MergeCollectOptions,
        MergeForceOptions, MergePreviewOptions, OutputSummary, RepoCommonLock, SafetyCheckStatus,
        ValidationEvidenceBundle, ValidationReport,
    },
    process_runner::{StdinMode, TrustedFixedNetworkProfile},
    safe_state::SafeRoot,
    worktree::{ManagedWorktreeWriteLease, WorktreeManager},
};
use anyhow::{bail, Context, Result};
use git2::{ObjectType, Oid, Repository};
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
        Repository::discover(repo).context("failed to discover guarded source repo")?;
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
}

#[derive(Debug, Clone)]
pub struct IssuePublicationOptions {
    pub repo: PathBuf,
    pub title: String,
    pub body: String,
    pub labels: Vec<String>,
    pub forge: ForgeKind,
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
);

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
    let repo = Repository::open(worktree_path).with_context(|| {
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
    let primary_repo = Repository::open(&preview.candidate.metadata.primary_repo_root)
        .context("failed to open primary repository")?;
    let base = current_branch_name(&primary_repo).unwrap_or_else(|| "HEAD".to_string());
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
    after_local.commit_id = local_commit.clone();
    after_local.head_id = after_local.preview.candidate.metadata.agent_head.clone();
    let reviewed_binding = after_local.preview.candidate.validation_binding.clone();

    let primary_repo = Repository::open(&repo_root).context("failed to open primary repository")?;
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
    final_report.commit_id = local_commit;
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
    report = final_report;

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
                &repo_root,
                &report,
                "origin",
                remote_url,
                &expected_head,
                source_guard.clone(),
            )?;
            report.publication_receipt = Some(transaction.receipt());
            if let Err(error) = ensure_remote_expected_commit(&worktree_path, &mut transaction) {
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
                &repo_root,
                &report,
                "origin",
                remote_url,
                &expected_head,
                source_guard.clone(),
            )?;
            report.publication_receipt = Some(transaction.receipt());
            if let Err(error) =
                ensure_github_remote_expected_commit(&worktree_path, &mut transaction)
            {
                return Ok(publication_transaction_failure(
                    report,
                    &mut transaction,
                    error,
                ));
            }
            report.pushed = true;
            report.publication_receipt = Some(transaction.receipt());
            let github = match reconcile_github_pr(&worktree_path, &mut transaction) {
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
    let repo = Repository::discover(repo_path)
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
    let repo = Repository::open(worktree_path)
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

    let repo = Repository::open(worktree_path)
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

fn current_branch_name(repo: &Repository) -> Option<String> {
    repo.head()
        .ok()
        .and_then(|head| head.shorthand().map(ToOwned::to_owned))
}

fn remote_url(repo: &Repository, name: &str) -> Result<String> {
    let remote = repo
        .find_remote(name)
        .with_context(|| format!("remote '{name}' is not configured"))?;
    remote
        .url()
        .map(ToOwned::to_owned)
        .with_context(|| format!("remote '{name}' has no URL"))
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

fn github_repository_identity(remote_url: &str) -> Result<GithubRepositoryIdentity> {
    let PublicationRemoteTransport::Https { host, path, .. } =
        publication_remote_transport(remote_url)?;
    let mut components = path.split('/');
    let owner = components
        .next()
        .filter(|component| !component.is_empty())
        .context("GitHub origin URL omitted owner")?;
    let raw_name = components
        .next()
        .filter(|component| !component.is_empty())
        .context("GitHub origin URL omitted repository")?;
    if components.next().is_some() {
        bail!("GitHub origin URL must contain exactly owner/repository");
    }
    let name = raw_name.strip_suffix(".git").unwrap_or(raw_name);
    validate_github_slug(owner, "owner")?;
    validate_github_slug(name, "repository")?;
    Ok(GithubRepositoryIdentity {
        host,
        owner: owner.to_ascii_lowercase(),
        name: name.to_ascii_lowercase(),
    })
}

fn normalize_github_host(host: &str) -> Result<String> {
    let (hostname, port) = host
        .rsplit_once(':')
        .map_or((host, None), |(hostname, port)| (hostname, Some(port)));
    if hostname.is_empty()
        || hostname.len() > MAX_PUBLICATION_HOST_BYTES
        || hostname.contains(':')
        || host.starts_with('.')
        || host.ends_with('.')
        || host.contains("..")
        || !host
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b':'))
    {
        bail!("GitHub origin URL host is invalid");
    }
    if hostname.split('.').any(|label| {
        label.is_empty() || label.len() > 63 || label.starts_with('-') || label.ends_with('-')
    }) {
        bail!("GitHub origin URL DNS label is invalid");
    }
    let port = port
        .map(|port| {
            let parsed = port
                .parse::<u16>()
                .ok()
                .filter(|parsed| *parsed != 0)
                .context("GitHub origin URL port is invalid")?;
            if port != parsed.to_string() {
                bail!("GitHub origin URL port was not canonical");
            }
            Ok(parsed)
        })
        .transpose()?;
    let hostname = hostname.to_ascii_lowercase();
    if hostname == "github.com" {
        if port.is_some_and(|port| port != 443) {
            bail!("github.com publication permits only the canonical HTTPS port");
        }
        return Ok(hostname);
    }
    if let Some(port) = port {
        return Ok(format!("{hostname}:{port}"));
    }
    Ok(hostname)
}

fn validate_github_slug(value: &str, label: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > MAX_GITHUB_SLUG_BYTES
        || matches!(value, "." | "..")
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        bail!("GitHub {label} component is invalid");
    }
    Ok(())
}

fn canonical_github_author_login(value: &str) -> Result<String> {
    if value.is_empty()
        || value.len() > MAX_GITHUB_SLUG_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'[' | b']'))
    {
        bail!("GitHub expected author is empty, malformed, or oversized");
    }
    Ok(value.to_ascii_lowercase())
}

fn validate_github_receipt_url(
    url: &str,
    expected: &GithubRepositoryIdentity,
    expected_number: u64,
) -> Result<()> {
    if expected_number == 0 {
        bail!("GitHub PR receipt number was zero");
    }
    validate_github_receipt_url_text(url)?;
    let (scheme, remainder) = url
        .split_once("://")
        .context("GitHub PR receipt URL was not absolute")?;
    if scheme != "https" {
        bail!("GitHub PR receipt URL was not HTTPS");
    }
    let slash = remainder
        .find('/')
        .context("GitHub PR receipt URL omitted repository path")?;
    let authority = &remainder[..slash];
    let host = normalize_github_host(authority)?;
    if host != authority {
        bail!("GitHub PR receipt URL host was not canonical");
    }
    let components = remainder[slash + 1..].split('/').collect::<Vec<_>>();
    if components.len() != 4
        || components[2] != "pull"
        || components[3] != expected_number.to_string()
    {
        bail!("GitHub PR receipt URL did not identify the expected pull request");
    }
    if host != expected.host
        || !components[0].eq_ignore_ascii_case(&expected.owner)
        || !components[1].eq_ignore_ascii_case(&expected.name)
    {
        bail!("GitHub PR receipt URL did not match the bound forge repository");
    }
    Ok(())
}

fn validate_github_issue_receipt_url(
    url: &str,
    expected: &GithubRepositoryIdentity,
    expected_number: u64,
) -> Result<String> {
    if expected_number == 0 {
        bail!("GitHub issue receipt number was zero");
    }
    validate_github_receipt_url_text(url)?;
    let (scheme, remainder) = url
        .split_once("://")
        .context("GitHub issue receipt URL was not absolute")?;
    if scheme != "https" {
        bail!("GitHub issue receipt URL was not HTTPS");
    }
    let slash = remainder
        .find('/')
        .context("GitHub issue receipt URL omitted repository path")?;
    let authority = &remainder[..slash];
    let host = normalize_github_host(authority)?;
    let components = remainder[slash + 1..].split('/').collect::<Vec<_>>();
    let issue_number = components
        .get(3)
        .and_then(|component| component.parse::<u64>().ok())
        .filter(|number| *number > 0);
    if host != authority
        || components.len() != 4
        || components[2] != "issues"
        || issue_number != Some(expected_number)
        || components[3] != expected_number.to_string()
        || host != expected.host
        || !components[0].eq_ignore_ascii_case(&expected.owner)
        || !components[1].eq_ignore_ascii_case(&expected.name)
    {
        bail!("GitHub issue receipt URL did not match the bound repository and issue");
    }
    Ok(url.to_string())
}

fn validate_github_receipt_url_text(url: &str) -> Result<()> {
    if url.is_empty()
        || url.len() > MAX_GITHUB_RECEIPT_URL_BYTES
        || url
            .as_bytes()
            .iter()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
        || url.contains(['?', '#', '%', '\\', '@'])
    {
        bail!("GitHub receipt URL was empty, noncanonical, or oversized");
    }
    Ok(())
}

#[cfg(test)]
fn publication_remote_binding_digest(
    secret: &[u8],
    remote_name: &str,
    remote_url: &str,
) -> Result<String> {
    if secret.len() != REMOTE_BINDING_SECRET_BYTES {
        bail!("publication remote binding secret has an invalid length");
    }
    let mut input = ZeroizingBytes(b"maco-publication-remote-binding-v1\0".to_vec());
    input.0.extend_from_slice(secret);
    input.0.push(0);
    input.0.extend_from_slice(remote_name.as_bytes());
    input.0.push(0);
    input.0.extend_from_slice(remote_url.as_bytes());
    Ok(Oid::hash_object(ObjectType::Blob, input.as_slice())
        .context("failed to digest publication remote binding")?
        .to_string())
}

#[cfg(test)]
fn load_or_create_remote_binding_secret(state_directory: &Path) -> Result<ZeroizingBytes> {
    let path = state_directory.join(REMOTE_BINDING_SECRET_FILE);
    match fs::symlink_metadata(&path) {
        Ok(_) => return read_remote_binding_secret(&path),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "failed to inspect publication remote binding key {}",
                    path.display()
                )
            })
        }
    }
    refuse_missing_binding_key_with_existing_transactions(state_directory)?;

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system time before UNIX epoch")?;
    let temporary_path = state_directory.join(format!(
        ".{REMOTE_BINDING_SECRET_FILE}-{}-{}.tmp",
        std::process::id(),
        timestamp.as_nanos()
    ));
    let mut secret = ZeroizingBytes(vec![0_u8; REMOTE_BINDING_SECRET_BYTES]);
    fill_os_random(secret.as_mut_slice())?;
    let result = (|| -> Result<ZeroizingBytes> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        }
        let mut file = options.open(&temporary_path).with_context(|| {
            format!(
                "failed to create publication binding key temp file {}",
                temporary_path.display()
            )
        })?;
        file.write_all(secret.as_slice())
            .context("failed to write publication remote binding key")?;
        file.sync_all()
            .context("failed to persist publication remote binding key")?;
        match publish_remote_binding_secret_temp(&temporary_path, &path)? {
            RemoteBindingSecretPublish::Published { temp_is_link } => {
                sync_journal_directory(state_directory)?;
                if temp_is_link {
                    match fs::remove_file(&temporary_path) {
                        Ok(()) => {}
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                        Err(error) => {
                            return Err(error).with_context(|| {
                                format!(
                                    "failed to remove publication binding key temp file {}",
                                    temporary_path.display()
                                )
                            })
                        }
                    }
                    sync_journal_directory(state_directory)?;
                }
                read_remote_binding_secret(&path)
            }
            RemoteBindingSecretPublish::Existing => {
                fs::remove_file(&temporary_path).with_context(|| {
                    format!(
                        "failed to remove losing publication binding key temp file {}",
                        temporary_path.display()
                    )
                })?;
                read_remote_binding_secret(&path)
            }
        }
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary_path);
    }
    result
}

#[cfg(test)]
enum RemoteBindingSecretPublish {
    Published { temp_is_link: bool },
    Existing,
}

#[cfg(all(test, unix))]
fn publish_remote_binding_secret_temp(
    temporary_path: &Path,
    final_path: &Path,
) -> Result<RemoteBindingSecretPublish> {
    match fs::hard_link(temporary_path, final_path) {
        Ok(()) => Ok(RemoteBindingSecretPublish::Published { temp_is_link: true }),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            Ok(RemoteBindingSecretPublish::Existing)
        }
        Err(error) => Err(error).with_context(|| {
            format!(
                "failed to publish publication remote binding key {}",
                final_path.display()
            )
        }),
    }
}

#[cfg(all(test, target_os = "windows"))]
fn publish_remote_binding_secret_temp(
    temporary_path: &Path,
    final_path: &Path,
) -> Result<RemoteBindingSecretPublish> {
    use std::os::windows::ffi::OsStrExt;

    const MOVEFILE_WRITE_THROUGH: u32 = 0x0000_0008;
    const ERROR_FILE_EXISTS: i32 = 80;
    const ERROR_ALREADY_EXISTS: i32 = 183;
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn MoveFileExW(existing: *const u16, new: *const u16, flags: u32) -> i32;
    }
    let existing = temporary_path
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let new = final_path
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    // SAFETY: Both paths are NUL-terminated UTF-16 buffers that remain alive
    // for the call. MOVEFILE_REPLACE_EXISTING is deliberately not supplied.
    let moved = unsafe { MoveFileExW(existing.as_ptr(), new.as_ptr(), MOVEFILE_WRITE_THROUGH) };
    if moved != 0 {
        return Ok(RemoteBindingSecretPublish::Published {
            temp_is_link: false,
        });
    }
    let error = std::io::Error::last_os_error();
    if matches!(
        error.raw_os_error(),
        Some(ERROR_FILE_EXISTS) | Some(ERROR_ALREADY_EXISTS)
    ) {
        Ok(RemoteBindingSecretPublish::Existing)
    } else {
        Err(error).with_context(|| {
            format!(
                "failed to publish publication remote binding key {}",
                final_path.display()
            )
        })
    }
}

#[cfg(all(test, not(any(unix, target_os = "windows"))))]
fn publish_remote_binding_secret_temp(
    _temporary_path: &Path,
    _final_path: &Path,
) -> Result<RemoteBindingSecretPublish> {
    bail!("atomic publication remote binding key creation is unsupported on this platform")
}

#[cfg(test)]
fn refuse_missing_binding_key_with_existing_transactions(state_directory: &Path) -> Result<()> {
    let transactions = state_directory.join("publication-transactions");
    match fs::symlink_metadata(&transactions) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink()
                || publication_metadata_is_windows_reparse_point(&metadata)
                || !metadata.file_type().is_dir()
            {
                bail!(
                    "publication transaction root {} is unsafe while the remote binding key is missing",
                    transactions.display()
                );
            }
            let mut entries = fs::read_dir(&transactions).with_context(|| {
                format!(
                    "failed to inspect existing publication transactions {}",
                    transactions.display()
                )
            })?;
            if entries.next().transpose()?.is_some() {
                bail!(
                    "publication remote binding key is missing while prior transaction entries exist; refusing to generate a replacement key"
                );
            }
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| {
            format!(
                "failed to inspect publication transaction root {}",
                transactions.display()
            )
        }),
    }
}

fn refuse_legacy_publication_journals(repository: &Repository) -> Result<()> {
    let legacy_root = repository
        .commondir()
        .join("maco")
        .join("state")
        .join("publication-transactions");
    let metadata = match fs::symlink_metadata(&legacy_root) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(error).context("failed to inspect legacy publication journal root")
        }
    };
    if metadata.file_type().is_symlink()
        || publication_metadata_is_windows_reparse_point(&metadata)
        || !metadata.is_dir()
    {
        bail!("legacy publication journal root is unsafe; signed migration is required");
    }
    let mut entries = fs::read_dir(&legacy_root)
        .context("failed to enumerate legacy publication journal root")?;
    if entries.next().transpose()?.is_some() {
        bail!(
            "legacy publication journals require explicit signed migration before authenticated external effects can run"
        );
    }
    Ok(())
}

#[cfg(test)]
fn read_remote_binding_secret(path: &Path) -> Result<ZeroizingBytes> {
    #[cfg(unix)]
    recover_remote_binding_secret_temp_link(path)?;
    let path_metadata = fs::symlink_metadata(path).with_context(|| {
        format!(
            "failed to inspect publication remote binding key {}",
            path.display()
        )
    })?;
    validate_remote_binding_secret_metadata(path, &path_metadata)?;
    let mut file = open_remote_binding_secret_file(path)
        .with_context(|| format!("failed to open publication binding key {}", path.display()))?;
    let file_metadata = file
        .metadata()
        .with_context(|| format!("failed to inspect open binding key {}", path.display()))?;
    validate_remote_binding_secret_metadata(path, &file_metadata)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if path_metadata.dev() != file_metadata.dev() || path_metadata.ino() != file_metadata.ino()
        {
            bail!(
                "publication remote binding key {} changed while being opened",
                path.display()
            );
        }
    }
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::fs::MetadataExt;

        let path_volume = path_metadata
            .volume_serial_number()
            .context("publication binding key path omitted volume identity")?;
        let file_volume = file_metadata
            .volume_serial_number()
            .context("open publication binding key omitted volume identity")?;
        let path_index = path_metadata
            .file_index()
            .context("publication binding key path omitted file identity")?;
        let file_index = file_metadata
            .file_index()
            .context("open publication binding key omitted file identity")?;
        if path_volume != file_volume || path_index != file_index {
            bail!(
                "publication remote binding key {} changed while being opened",
                path.display()
            );
        }
    }
    let mut secret = ZeroizingBytes(Vec::new());
    Read::by_ref(&mut file)
        .take((REMOTE_BINDING_SECRET_BYTES + 1) as u64)
        .read_to_end(&mut secret.0)
        .with_context(|| format!("failed to read publication binding key {}", path.display()))?;
    if secret.len() != REMOTE_BINDING_SECRET_BYTES {
        bail!(
            "publication remote binding key {} has invalid length {}; expected {}",
            path.display(),
            secret.len(),
            REMOTE_BINDING_SECRET_BYTES
        );
    }
    Ok(secret)
}

#[cfg(all(test, target_os = "windows"))]
fn open_remote_binding_secret_file(path: &Path) -> std::io::Result<fs::File> {
    use std::os::windows::fs::OpenOptionsExt;

    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    options.open(path)
}

#[cfg(all(test, unix))]
fn open_remote_binding_secret_file(path: &Path) -> std::io::Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt;

    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    options.open(path)
}

#[cfg(all(test, not(any(unix, target_os = "windows"))))]
fn open_remote_binding_secret_file(path: &Path) -> std::io::Result<fs::File> {
    OpenOptions::new().read(true).open(path)
}

#[cfg(all(test, unix))]
fn recover_remote_binding_secret_temp_link(path: &Path) -> Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let metadata = fs::symlink_metadata(path).with_context(|| {
        format!(
            "failed to inspect publication remote binding key {}",
            path.display()
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() || metadata.nlink() == 1
    {
        return Ok(());
    }
    unsafe extern "C" {
        fn geteuid() -> u32;
    }
    // SAFETY: geteuid has no arguments and returns the effective numeric uid.
    let effective_uid = unsafe { geteuid() };
    if metadata.nlink() != 2
        || metadata.uid() != effective_uid
        || metadata.permissions().mode() & 0o777 != 0o600
        || metadata.len() != REMOTE_BINDING_SECRET_BYTES as u64
    {
        return Ok(());
    }
    let parent = path
        .parent()
        .context("publication remote binding key has no parent directory")?;
    let mut matching_temp = None;
    for entry in fs::read_dir(parent).with_context(|| {
        format!(
            "failed to inspect publication binding key directory {}",
            parent.display()
        )
    })? {
        let entry = entry.with_context(|| {
            format!(
                "failed to read publication binding key directory entry in {}",
                parent.display()
            )
        })?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if !is_remote_binding_secret_temp_name(name) {
            continue;
        }
        let candidate = entry.path();
        let candidate_metadata = fs::symlink_metadata(&candidate).with_context(|| {
            format!(
                "failed to inspect publication binding key temp link {}",
                candidate.display()
            )
        })?;
        if candidate_metadata.file_type().is_file()
            && !candidate_metadata.file_type().is_symlink()
            && candidate_metadata.dev() == metadata.dev()
            && candidate_metadata.ino() == metadata.ino()
            && candidate_metadata.uid() == effective_uid
            && candidate_metadata.permissions().mode() & 0o777 == 0o600
            && candidate_metadata.len() == REMOTE_BINDING_SECRET_BYTES as u64
            && matching_temp.replace(candidate).is_some()
        {
            bail!(
                "publication remote binding key has multiple matching temp hard links; refusing recovery"
            );
        }
    }
    let Some(matching_temp) = matching_temp else {
        return Ok(());
    };
    fs::remove_file(&matching_temp).with_context(|| {
        format!(
            "failed to recover publication binding key temp link {}",
            matching_temp.display()
        )
    })?;
    sync_journal_directory(parent)?;
    let recovered = fs::symlink_metadata(path).with_context(|| {
        format!(
            "failed to verify recovered publication binding key {}",
            path.display()
        )
    })?;
    if recovered.dev() != metadata.dev()
        || recovered.ino() != metadata.ino()
        || recovered.nlink() != 1
    {
        bail!(
            "publication remote binding key {} did not recover to one link",
            path.display()
        );
    }
    Ok(())
}

#[cfg(test)]
fn is_remote_binding_secret_temp_name(name: &str) -> bool {
    let prefix = format!(".{REMOTE_BINDING_SECRET_FILE}-");
    let Some(stem) = name
        .strip_prefix(&prefix)
        .and_then(|name| name.strip_suffix(".tmp"))
    else {
        return false;
    };
    let Some((pid, nanos)) = stem.split_once('-') else {
        return false;
    };
    !pid.is_empty()
        && !nanos.is_empty()
        && !nanos.contains('-')
        && pid.parse::<u32>().is_ok_and(|pid| pid > 0)
        && nanos.parse::<u128>().is_ok_and(|nanos| nanos > 0)
}

#[cfg(test)]
fn validate_remote_binding_secret_metadata(path: &Path, metadata: &fs::Metadata) -> Result<()> {
    if metadata.file_type().is_symlink()
        || publication_metadata_is_windows_reparse_point(metadata)
        || !metadata.file_type().is_file()
    {
        bail!(
            "publication remote binding key {} is not a regular non-reparse file",
            path.display()
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        unsafe extern "C" {
            fn geteuid() -> u32;
        }
        // SAFETY: geteuid has no arguments and returns the effective numeric uid.
        let effective_uid = unsafe { geteuid() };
        if metadata.uid() != effective_uid {
            bail!(
                "publication remote binding key {} is not owned by the current effective user",
                path.display()
            );
        }
        if metadata.nlink() != 1 {
            bail!(
                "publication remote binding key {} has multiple hard links",
                path.display()
            );
        }
        if metadata.permissions().mode() & 0o777 != 0o600 {
            bail!(
                "publication remote binding key {} must have Unix mode 0600",
                path.display()
            );
        }
    }
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::fs::MetadataExt;

        if metadata.number_of_links() != Some(1) {
            bail!(
                "publication remote binding key {} must have exactly one hard link",
                path.display()
            );
        }
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn publication_metadata_is_windows_reparse_point(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(target_os = "windows"))]
fn publication_metadata_is_windows_reparse_point(_metadata: &fs::Metadata) -> bool {
    false
}

#[cfg(all(test, unix))]
fn fill_os_random(destination: &mut [u8]) -> Result<()> {
    fs::File::open("/dev/urandom")
        .context("failed to open operating-system random source")?
        .read_exact(destination)
        .context("failed to read operating-system random source")
}

#[cfg(all(test, target_os = "windows"))]
fn fill_os_random(destination: &mut [u8]) -> Result<()> {
    use std::ffi::c_void;

    const BCRYPT_USE_SYSTEM_PREFERRED_RNG: u32 = 0x0000_0002;
    #[link(name = "bcrypt")]
    unsafe extern "system" {
        fn BCryptGenRandom(
            algorithm: *mut c_void,
            buffer: *mut u8,
            buffer_length: u32,
            flags: u32,
        ) -> i32;
    }
    let length = u32::try_from(destination.len()).context("random buffer was too large")?;
    // SAFETY: destination is writable for `length` bytes, a null algorithm
    // handle is required with BCRYPT_USE_SYSTEM_PREFERRED_RNG, and NTSTATUS is checked.
    let status = unsafe {
        BCryptGenRandom(
            std::ptr::null_mut(),
            destination.as_mut_ptr(),
            length,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };
    if status < 0 {
        bail!("Windows BCryptGenRandom failed with NTSTATUS {status:#x}");
    }
    Ok(())
}

#[cfg(all(test, not(any(unix, target_os = "windows"))))]
fn fill_os_random(_destination: &mut [u8]) -> Result<()> {
    bail!("publication remote binding keys are unsupported on this platform")
}

impl PublicationTransaction {
    fn open(
        repo_root: &Path,
        report: &PrPublicationReport,
        remote_name: &str,
        remote_url: &str,
        expected_oid: &str,
        source_guard: Option<ExternalSourceGuard>,
    ) -> Result<Self> {
        let expected =
            Oid::from_str(expected_oid).context("publication expected OID was invalid")?;
        if expected.to_string() != expected_oid {
            bail!("publication expected OID was not canonical lowercase hexadecimal");
        }
        validate_publication_remote_url(remote_url)?;
        if matches!(report.forge, ForgeKind::Git | ForgeKind::Github) {
            publication_remote_transport(remote_url)?;
        }
        let expected_base_oid = report
            .base_head
            .as_deref()
            .map(Oid::from_str)
            .transpose()
            .context("publication expected base OID was invalid")?
            .map(|oid| oid.to_string());
        if report.forge == ForgeKind::Github && expected_base_oid.is_none() {
            bail!("GitHub publication requires an exact reviewed base OID");
        }
        let github_repository = match report.forge {
            ForgeKind::Github => Some(github_repository_identity(remote_url)?),
            ForgeKind::Git | ForgeKind::Fake => None,
        };
        let source_repository = source_guard
            .as_ref()
            .map(|source| -> Result<GithubRepositoryIdentity> {
                let repository = github_repository_identity(remote_url)?;
                if repository.host != source.repository_host
                    || repository.selector() != source.repository_selector
                {
                    bail!("publication origin changed from the exact guarded source repository");
                }
                Ok(repository)
            })
            .transpose()?;
        let expected_pr_author = match report.forge {
            ForgeKind::Github => Some(select_github_expected_author_with(|key| {
                env::var(key).ok()
            })?),
            ForgeKind::Git | ForgeKind::Fake => None,
        };
        let expected_pr_title = (report.forge == ForgeKind::Github).then(|| report.title.clone());
        let unmarked_pr_body =
            (report.forge == ForgeKind::Github).then(|| pr_body(&report.preview));
        let repo = Repository::open(repo_root).with_context(|| {
            format!(
                "failed to open repository for publication journal {}",
                repo_root.display()
            )
        })?;
        refuse_legacy_publication_journals(&repo)?;
        let auth = repository_auth_writer(repo_root)?
            .into_authenticator()
            .context("failed to establish authenticated publication effect ledger")?;
        let repository_identity = auth.binding().repository_id.clone();
        let repository_selector = source_repository
            .as_ref()
            .or(github_repository.as_ref())
            .map(GithubRepositoryIdentity::selector)
            .unwrap_or_else(|| redact_remote_url(remote_url));
        drop(auth);
        let remote_display = redact_remote_url(remote_url);
        let push_effect_request = ExternalEffectRequest::new(
            "git",
            &repository_selector,
            &repository_identity,
            source_guard.clone(),
            ExternalEffectOperation::GitPush,
            serde_json::json!({
                "version": 1,
                "repository": repository_selector,
                "remote_name": remote_name,
                "remote_url": remote_url,
                "base": report.base,
                "expected_base_oid": expected_base_oid,
            }),
            serde_json::json!({
                "version": 1,
                "expected_oid": expected_oid,
            }),
        )?;
        let remote_branch = format!("maco/effects/{}", &push_effect_request.effect_id[..32]);
        let remote_ref = format!("refs/heads/{remote_branch}");
        let pr_effect_request = match report.forge {
            ForgeKind::Github => Some(ExternalEffectRequest::new(
                "github",
                &repository_selector,
                &repository_identity,
                source_guard,
                ExternalEffectOperation::GithubPullRequest,
                serde_json::json!({
                    "version": 1,
                    "repository": repository_selector,
                    "expected_oid": expected_oid,
                    "expected_base_oid": expected_base_oid,
                    "base": report.base,
                }),
                serde_json::json!({
                    "version": 1,
                    "title": expected_pr_title,
                    "body": unmarked_pr_body,
                    "draft": report.draft,
                    "expected_author": expected_pr_author,
                }),
            )?),
            ForgeKind::Git | ForgeKind::Fake => None,
        };
        let pr_marker_nonce = pr_effect_request
            .as_ref()
            .map(|request| request.effect_id.clone());
        let expected_pr_body = match (&pr_effect_request, &unmarked_pr_body) {
            (Some(request), Some(body)) => {
                Some(external_effect_marked_body(body, &request.marker)?)
            }
            (None, None) => None,
            _ => bail!("publication transaction marker did not match its forge"),
        };

        let transaction_id = format!("effect-{}", push_effect_request.effect_id);
        let remote_binding_digest = stable_json_digest(&(
            "maco_publication_remote_binding_v1",
            remote_name,
            remote_url,
        ))?;
        Ok(Self {
            directory: PathBuf::new(),
            journal: PublicationTransactionJournal {
                version: PUBLICATION_JOURNAL_VERSION,
                transaction_id,
                sequence: 0,
                agent_id: report.agent_id.clone(),
                forge: report.forge,
                expected_oid: expected_oid.to_string(),
                expected_base_oid,
                remote_name: remote_name.to_string(),
                remote_binding_digest,
                remote_display,
                remote_ref,
                remote_branch,
                github_repository,
                pr_marker_nonce,
                expected_pr_title,
                expected_pr_body,
                expected_pr_author,
                base: report.base.clone(),
                draft: report.draft,
                phase: PublicationTransactionPhase::Prepared,
                push_observed_oid: None,
                pr_url: None,
                pr_head_oid: None,
                pr_base: None,
                pr_state: None,
                pr_is_draft: None,
                pr_number: None,
                pr_title: None,
                pr_body: None,
                pr_head_ref_name: None,
                pr_head_repository_owner: None,
                pr_head_repository_name: None,
                pr_is_cross_repository: None,
                pr_author: None,
                create_attempted: false,
                created_by_transaction: false,
                observed_existing_pr: false,
                last_error: None,
                updated_unix_seconds: 0,
            },
            remote_url: remote_url.to_string(),
            push_effect_request: Some(push_effect_request),
            pr_effect_request,
        })
    }

    fn persist(&mut self) -> Result<()> {
        if self.push_effect_request.is_some() {
            self.journal.sequence = self
                .journal
                .sequence
                .checked_add(1)
                .context("publication receipt sequence overflow")?;
            self.journal.updated_unix_seconds = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .context("system time before UNIX epoch")?
                .as_secs();
            return Ok(());
        }
        self.journal.sequence = self
            .journal
            .sequence
            .checked_add(1)
            .context("publication journal sequence overflow")?;
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system time before UNIX epoch")?;
        self.journal.updated_unix_seconds = timestamp.as_secs();
        let final_path = self
            .directory
            .join(format!("{:020}.json", self.journal.sequence));
        let temporary_path = self.directory.join(format!(
            ".{:020}-{}-{}.tmp",
            self.journal.sequence,
            std::process::id(),
            timestamp.as_nanos()
        ));
        let mut bytes = serde_json::to_vec_pretty(&self.journal)
            .context("failed to encode publication transaction journal")?;
        bytes.push(b'\n');
        if bytes.len() as u64 > PUBLICATION_JOURNAL_MAX_RECORD_BYTES {
            self.journal.sequence = self.journal.sequence.saturating_sub(1);
            bail!(
                "publication journal record exceeded the {}-byte safety limit",
                PUBLICATION_JOURNAL_MAX_RECORD_BYTES
            );
        }
        let mut published = false;
        let write_result = (|| -> Result<()> {
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options.open(&temporary_path).with_context(|| {
                format!(
                    "failed to create publication journal temp file {}",
                    temporary_path.display()
                )
            })?;
            file.write_all(&bytes)
                .context("failed to write publication transaction journal")?;
            file.sync_all()
                .context("failed to persist publication transaction journal")?;
            fs::hard_link(&temporary_path, &final_path).with_context(|| {
                format!(
                    "failed to atomically publish journal record {}",
                    final_path.display()
                )
            })?;
            published = true;
            sync_journal_directory(&self.directory)?;
            fs::remove_file(&temporary_path).with_context(|| {
                format!(
                    "failed to remove published journal temp file {}",
                    temporary_path.display()
                )
            })?;
            sync_journal_directory(&self.directory)?;
            prune_publication_journal(&self.directory, 32)?;
            Ok(())
        })();
        if write_result.is_err() {
            let _ = fs::remove_file(&temporary_path);
            if !published {
                self.journal.sequence = self.journal.sequence.saturating_sub(1);
            }
        }
        write_result
    }

    fn persist_if_changed(&mut self, previous: &PublicationTransactionJournal) -> Result<()> {
        if &self.journal == previous {
            Ok(())
        } else {
            self.persist()
        }
    }

    fn advance_phase(&mut self, phase: PublicationTransactionPhase) {
        if phase > self.journal.phase {
            self.journal.phase = phase;
        }
    }

    fn receipt(&self) -> PrPublicationReceipt {
        PrPublicationReceipt {
            version: self.journal.version,
            transaction_id: self.journal.transaction_id.clone(),
            sequence: self.journal.sequence,
            phase: self.journal.phase,
            expected_oid: self.journal.expected_oid.clone(),
            expected_base_oid: self.journal.expected_base_oid.clone(),
            remote_ref: self.journal.remote_ref.clone(),
            github_repository: self
                .journal
                .github_repository
                .as_ref()
                .map(GithubRepositoryIdentity::selector),
            push_observed_oid: self.journal.push_observed_oid.clone(),
            pr_url: self.journal.pr_url.clone(),
            pr_head_oid: self.journal.pr_head_oid.clone(),
            pr_base: self.journal.pr_base.clone(),
            pr_state: self.journal.pr_state.clone(),
            pr_is_draft: self.journal.pr_is_draft,
            create_attempted: self.journal.create_attempted,
            created_by_transaction: self.journal.created_by_transaction,
            observed_existing_pr: self.journal.observed_existing_pr,
            last_error: self.journal.last_error.clone(),
        }
    }
}

#[cfg(test)]
fn load_latest_publication_journal(
    directory: &Path,
) -> Result<Option<PublicationTransactionJournal>> {
    let records = publication_journal_records(directory)?;
    let mut latest = None;
    for (sequence, path) in records {
        let bytes = read_publication_journal_record(&path)?;
        let journal: PublicationTransactionJournal = serde_json::from_slice(&bytes)
            .with_context(|| format!("invalid journal record {}", path.display()))?;
        if journal.sequence != sequence {
            bail!(
                "publication journal record {} has a mismatched sequence",
                path.display()
            );
        }
        validate_publication_journal(&journal)?;
        if let Some(previous) = latest.as_ref() {
            validate_publication_journal_transition(previous, &journal)?;
        }
        latest = Some(journal);
    }
    Ok(latest)
}

fn prune_publication_journal(directory: &Path, retain: usize) -> Result<()> {
    let records = publication_journal_records(directory)?;
    let remove_count = records.len().saturating_sub(retain.max(1));
    for (_, path) in records.into_iter().take(remove_count) {
        fs::remove_file(&path)
            .with_context(|| format!("failed to prune journal record {}", path.display()))?;
    }
    if remove_count > 0 {
        sync_journal_directory(directory)?;
    }
    Ok(())
}

fn publication_journal_records(directory: &Path) -> Result<Vec<(u64, PathBuf)>> {
    let directory_metadata = validate_publication_journal_directory(directory)?;
    let mut paths = Vec::new();
    let mut entry_count = 0_usize;
    for entry in fs::read_dir(directory)
        .with_context(|| format!("failed to list journal directory {}", directory.display()))?
    {
        entry_count = entry_count
            .checked_add(1)
            .context("publication journal directory entry count overflow")?;
        if entry_count > PUBLICATION_JOURNAL_MAX_DIRECTORY_ENTRIES {
            bail!(
                "publication journal directory exceeded the {}-entry safety limit",
                PUBLICATION_JOURNAL_MAX_DIRECTORY_ENTRIES
            );
        }
        let entry = entry.with_context(|| {
            format!(
                "failed to read journal directory entry in {}",
                directory.display()
            )
        })?;
        paths.push(entry.path());
    }
    let listed = validate_publication_journal_directory(directory)?;
    if !publication_same_filesystem_identity(&directory_metadata, &listed) {
        bail!("publication journal directory changed identity while it was listed");
    }

    let mut records = Vec::new();
    for path in paths {
        let metadata = fs::symlink_metadata(&path)
            .with_context(|| format!("failed to inspect journal record {}", path.display()))?;
        validate_publication_journal_record_metadata(&path, &metadata)?;
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .context("publication journal filename was not UTF-8")?;
        if is_publication_journal_temp_name(name) {
            bail!(
                "publication journal contains incomplete temporary record {}",
                path.display()
            );
        }
        let sequence = name
            .strip_suffix(".json")
            .filter(|sequence| {
                sequence.len() == 20 && sequence.bytes().all(|byte| byte.is_ascii_digit())
            })
            .context("publication journal JSON filename was not a canonical sequence")?
            .parse::<u64>()
            .context("publication journal sequence was invalid")?;
        records.push((sequence, path));
        if records.len() > PUBLICATION_JOURNAL_MAX_RECORDS {
            bail!(
                "publication journal exceeded the {}-record safety limit",
                PUBLICATION_JOURNAL_MAX_RECORDS
            );
        }
    }
    records.sort_by_key(|(sequence, _)| *sequence);
    let after = validate_publication_journal_directory(directory)?;
    if !publication_same_filesystem_identity(&directory_metadata, &after) {
        bail!("publication journal directory changed identity while records were inspected");
    }
    Ok(records)
}

fn is_publication_journal_temp_name(name: &str) -> bool {
    let Some(remainder) = name.strip_prefix('.') else {
        return false;
    };
    let Some(remainder) = remainder.strip_suffix(".tmp") else {
        return false;
    };
    let mut fields = remainder.split('-');
    fields.next().is_some_and(|sequence| {
        sequence.len() == 20 && sequence.bytes().all(|byte| byte.is_ascii_digit())
    }) && fields
        .next()
        .is_some_and(|pid| !pid.is_empty() && pid.bytes().all(|byte| byte.is_ascii_digit()))
        && fields.next().is_some_and(|nanos| {
            !nanos.is_empty() && nanos.bytes().all(|byte| byte.is_ascii_digit())
        })
        && fields.next().is_none()
}

fn validate_publication_journal_directory(directory: &Path) -> Result<fs::Metadata> {
    let metadata = fs::symlink_metadata(directory).with_context(|| {
        format!(
            "failed to inspect publication journal directory {}",
            directory.display()
        )
    })?;
    if metadata.file_type().is_symlink()
        || publication_metadata_is_windows_reparse_point(&metadata)
        || !metadata.file_type().is_dir()
    {
        bail!(
            "publication journal directory {} is not a real directory",
            directory.display()
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        // SAFETY: geteuid has no arguments and returns the effective numeric uid.
        let uid = unsafe { libc::geteuid() };
        if metadata.uid() != uid || metadata.permissions().mode() & 0o077 != 0 {
            bail!(
                "publication journal directory {} has a foreign owner or unsafe mode",
                directory.display()
            );
        }
    }
    Ok(metadata)
}

fn validate_publication_journal_record_metadata(
    path: &Path,
    metadata: &fs::Metadata,
) -> Result<()> {
    if metadata.file_type().is_symlink()
        || publication_metadata_is_windows_reparse_point(metadata)
        || !metadata.file_type().is_file()
    {
        bail!(
            "publication journal record {} is not a real regular file",
            path.display()
        );
    }
    if metadata.len() == 0 || metadata.len() > PUBLICATION_JOURNAL_MAX_RECORD_BYTES {
        bail!(
            "publication journal record {} has an invalid size",
            path.display()
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        // SAFETY: geteuid has no arguments and returns the effective numeric uid.
        let uid = unsafe { libc::geteuid() };
        if metadata.uid() != uid
            || metadata.permissions().mode() & 0o077 != 0
            || metadata.nlink() != 1
        {
            bail!(
                "publication journal record {} has a foreign owner, unsafe mode, or multiple links",
                path.display()
            );
        }
    }
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.number_of_links() != Some(1) {
            bail!(
                "publication journal record {} has multiple links",
                path.display()
            );
        }
    }
    Ok(())
}

#[cfg(test)]
fn read_publication_journal_record(path: &Path) -> Result<Vec<u8>> {
    let path_metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect journal record {}", path.display()))?;
    validate_publication_journal_record_metadata(path, &path_metadata)?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let file = options
        .open(path)
        .with_context(|| format!("failed to open journal record {}", path.display()))?;
    let file_metadata = file
        .metadata()
        .with_context(|| format!("failed to inspect opened journal record {}", path.display()))?;
    validate_publication_journal_record_metadata(path, &file_metadata)?;
    if !publication_same_filesystem_identity(&path_metadata, &file_metadata) {
        bail!(
            "publication journal record {} changed while it was opened",
            path.display()
        );
    }
    let mut bytes = Vec::new();
    file.take(PUBLICATION_JOURNAL_MAX_RECORD_BYTES + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("failed to read journal record {}", path.display()))?;
    if bytes.is_empty()
        || bytes.len() as u64 > PUBLICATION_JOURNAL_MAX_RECORD_BYTES
        || bytes.len() as u64 != file_metadata.len()
    {
        bail!(
            "publication journal record {} changed size while it was read",
            path.display()
        );
    }
    let after = fs::symlink_metadata(path)
        .with_context(|| format!("failed to recheck journal record {}", path.display()))?;
    validate_publication_journal_record_metadata(path, &after)?;
    if !publication_same_filesystem_identity(&file_metadata, &after)
        || after.len() != file_metadata.len()
    {
        bail!(
            "publication journal record {} changed after it was read",
            path.display()
        );
    }
    Ok(bytes)
}

fn publication_same_filesystem_identity(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        left.dev() == right.dev() && left.ino() == right.ino()
    }
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::fs::MetadataExt;
        left.volume_serial_number() == right.volume_serial_number()
            && left.file_index() == right.file_index()
    }
    #[cfg(not(any(unix, target_os = "windows")))]
    {
        let _ = (left, right);
        false
    }
}

#[cfg(test)]
fn validate_publication_journal(journal: &PublicationTransactionJournal) -> Result<()> {
    if journal.version != PUBLICATION_JOURNAL_VERSION || journal.sequence == 0 {
        bail!("publication journal version or sequence was invalid");
    }
    Oid::from_str(&journal.expected_oid).context("publication journal expected OID was invalid")?;
    if let Some(oid) = journal.expected_base_oid.as_deref() {
        Oid::from_str(oid).context("publication journal expected base OID was invalid")?;
    }
    let is_external_effect_receipt = journal.transaction_id.starts_with("effect-");
    if is_external_effect_receipt {
        validate_external_digest(
            &journal.remote_binding_digest,
            "publication receipt remote binding digest",
        )?;
    } else {
        Oid::from_str(&journal.remote_binding_digest)
            .context("legacy publication journal remote binding digest was invalid")?;
    }
    if let Some(oid) = journal.push_observed_oid.as_deref() {
        Oid::from_str(oid).context("publication journal observed push OID was invalid")?;
    }
    if let Some(oid) = journal.pr_head_oid.as_deref() {
        Oid::from_str(oid).context("publication journal PR head OID was invalid")?;
    }
    if journal.phase >= PublicationTransactionPhase::PushObserved
        && journal.push_observed_oid.as_deref() != Some(journal.expected_oid.as_str())
    {
        bail!("publication journal push phase did not contain the expected observed OID");
    }
    if journal.phase < PublicationTransactionPhase::PushObserved
        && journal.push_observed_oid.is_some()
    {
        bail!("publication journal recorded a push receipt before the push phase");
    }
    if journal.forge == ForgeKind::Github {
        if journal.expected_base_oid.is_none() {
            bail!("GitHub publication journal omitted the exact reviewed base OID");
        }
        let marker = journal
            .pr_marker_nonce
            .as_deref()
            .context("GitHub publication journal omitted its unpredictable PR marker")?;
        validate_publication_pr_marker_nonce(marker)?;
        let expected_title = journal
            .expected_pr_title
            .as_deref()
            .context("GitHub publication journal omitted its exact PR title")?;
        let expected_body = journal
            .expected_pr_body
            .as_deref()
            .context("GitHub publication journal omitted its marker-bound PR body")?;
        let expected_author = journal
            .expected_pr_author
            .as_deref()
            .context("GitHub publication journal omitted its explicit expected author")?;
        let canonical_author = canonical_github_author_login(expected_author)
            .context("GitHub publication journal expected author was malformed")?;
        let marker_literal = if is_external_effect_receipt {
            format!("<!-- {EXTERNAL_EFFECT_MARKER_PREFIX}:v2:{marker} -->")
        } else {
            format!("<!-- maco-publication-marker:{marker} -->")
        };
        if expected_title.is_empty()
            || expected_title.len() > MAX_GITHUB_RECEIPT_STRING_BYTES
            || expected_body.len() > MAX_GITHUB_RECEIPT_BODY_BYTES
            || expected_body.matches(&marker_literal).count() != 1
            || canonical_author != expected_author
        {
            bail!("GitHub publication journal PR identity fields were invalid");
        }
        if journal.phase >= PublicationTransactionPhase::PrObserved {
            if !journal.created_by_transaction || journal.observed_existing_pr {
                bail!(
                    "publication journal PR phase did not prove marker-bound transaction creation"
                );
            }
            let repository = journal
                .github_repository
                .as_ref()
                .context("GitHub publication journal omitted its bound repository")?;
            let url = journal
                .pr_url
                .as_deref()
                .context("publication journal PR phase omitted its URL")?;
            let head = journal
                .pr_head_oid
                .as_deref()
                .context("publication journal PR phase omitted its head OID")?;
            let base = journal
                .pr_base
                .as_deref()
                .context("publication journal PR phase omitted its base branch")?;
            let state = journal
                .pr_state
                .as_deref()
                .context("publication journal PR phase omitted its state")?;
            let is_draft = journal
                .pr_is_draft
                .context("publication journal PR phase omitted its draft state")?;
            let number = journal
                .pr_number
                .filter(|number| *number > 0)
                .context("publication journal PR phase omitted its number")?;
            let title = journal
                .pr_title
                .as_deref()
                .context("publication journal PR phase omitted its title")?;
            let body = journal
                .pr_body
                .as_deref()
                .context("publication journal PR phase omitted its body")?;
            let head_ref_name = journal
                .pr_head_ref_name
                .as_deref()
                .context("publication journal PR phase omitted its head ref")?;
            let head_owner = journal
                .pr_head_repository_owner
                .as_deref()
                .context("publication journal PR phase omitted its head owner")?;
            let head_name = journal
                .pr_head_repository_name
                .as_deref()
                .context("publication journal PR phase omitted its head repository")?;
            let is_cross_repository = journal
                .pr_is_cross_repository
                .context("publication journal PR phase omitted its cross-repository state")?;
            let author = journal
                .pr_author
                .as_deref()
                .context("publication journal PR phase omitted its author")?;
            if head != journal.expected_oid {
                bail!("publication journal PR head did not match the expected OID");
            }
            if base != journal.base {
                bail!("publication journal PR base did not match the requested base");
            }
            if state != "OPEN" {
                bail!("publication journal PR state was not OPEN");
            }
            if is_draft != journal.draft {
                bail!("publication journal PR draft state changed from the request");
            }
            if title != expected_title
                || body != expected_body
                || head_ref_name != journal.remote_branch
                || head_owner != repository.owner
                || head_name != repository.name
                || is_cross_repository
                || author != expected_author
            {
                bail!(
                    "publication journal PR provenance changed from its exact transaction binding"
                );
            }
            validate_github_receipt_url(url, repository, number)?;
        } else if journal.pr_url.is_some()
            || journal.pr_head_oid.is_some()
            || journal.pr_base.is_some()
            || journal.pr_state.is_some()
            || journal.pr_is_draft.is_some()
            || journal.pr_number.is_some()
            || journal.pr_title.is_some()
            || journal.pr_body.is_some()
            || journal.pr_head_ref_name.is_some()
            || journal.pr_head_repository_owner.is_some()
            || journal.pr_head_repository_name.is_some()
            || journal.pr_is_cross_repository.is_some()
            || journal.pr_author.is_some()
            || journal.created_by_transaction
            || journal.observed_existing_pr
        {
            bail!("publication journal recorded PR receipt fields before the PR phase");
        }
    } else if journal.pr_url.is_some()
        || journal.pr_head_oid.is_some()
        || journal.pr_base.is_some()
        || journal.pr_state.is_some()
        || journal.pr_is_draft.is_some()
        || journal.pr_number.is_some()
        || journal.pr_marker_nonce.is_some()
        || journal.expected_pr_title.is_some()
        || journal.expected_pr_body.is_some()
        || journal.expected_pr_author.is_some()
        || journal.pr_title.is_some()
        || journal.pr_body.is_some()
        || journal.pr_head_ref_name.is_some()
        || journal.pr_head_repository_owner.is_some()
        || journal.pr_head_repository_name.is_some()
        || journal.pr_is_cross_repository.is_some()
        || journal.pr_author.is_some()
        || journal.create_attempted
        || journal.created_by_transaction
        || journal.observed_existing_pr
    {
        bail!("non-GitHub publication journal contained GitHub PR state");
    }
    if (journal.forge == ForgeKind::Github) != journal.github_repository.is_some() {
        bail!("publication journal forge repository binding was inconsistent");
    }
    if journal.created_by_transaction && !journal.create_attempted {
        bail!("publication journal attributed PR creation without a recorded create attempt");
    }
    if journal.created_by_transaction && journal.observed_existing_pr {
        bail!("publication journal contains contradictory PR creation provenance");
    }
    Ok(())
}

#[cfg(test)]
fn validate_publication_journal_transition(
    previous: &PublicationTransactionJournal,
    current: &PublicationTransactionJournal,
) -> Result<()> {
    if current.sequence
        != previous
            .sequence
            .checked_add(1)
            .context("publication journal sequence overflow while validating retained records")?
    {
        bail!("publication journal retained sequence was not contiguous");
    }
    if previous.version != current.version
        || previous.transaction_id != current.transaction_id
        || previous.agent_id != current.agent_id
        || previous.forge != current.forge
        || previous.expected_oid != current.expected_oid
        || previous.expected_base_oid != current.expected_base_oid
        || previous.remote_name != current.remote_name
        || previous.remote_binding_digest != current.remote_binding_digest
        || previous.remote_display != current.remote_display
        || previous.remote_ref != current.remote_ref
        || previous.remote_branch != current.remote_branch
        || previous.github_repository != current.github_repository
        || previous.pr_marker_nonce != current.pr_marker_nonce
        || previous.expected_pr_title != current.expected_pr_title
        || previous.expected_pr_body != current.expected_pr_body
        || previous.expected_pr_author != current.expected_pr_author
        || previous.base != current.base
        || previous.draft != current.draft
    {
        bail!("publication journal immutable transaction identity changed between records");
    }
    if current.phase < previous.phase {
        bail!("publication journal phase regressed between records");
    }
    if previous.push_observed_oid.is_some()
        && previous.push_observed_oid != current.push_observed_oid
    {
        bail!("publication journal push receipt changed between records");
    }
    if (previous.pr_url.is_some() && previous.pr_url != current.pr_url)
        || (previous.pr_head_oid.is_some() && previous.pr_head_oid != current.pr_head_oid)
        || (previous.pr_base.is_some() && previous.pr_base != current.pr_base)
        || (previous.pr_state.is_some() && previous.pr_state != current.pr_state)
        || (previous.pr_is_draft.is_some() && previous.pr_is_draft != current.pr_is_draft)
        || (previous.pr_number.is_some() && previous.pr_number != current.pr_number)
        || (previous.pr_title.is_some() && previous.pr_title != current.pr_title)
        || (previous.pr_body.is_some() && previous.pr_body != current.pr_body)
        || (previous.pr_head_ref_name.is_some()
            && previous.pr_head_ref_name != current.pr_head_ref_name)
        || (previous.pr_head_repository_owner.is_some()
            && previous.pr_head_repository_owner != current.pr_head_repository_owner)
        || (previous.pr_head_repository_name.is_some()
            && previous.pr_head_repository_name != current.pr_head_repository_name)
        || (previous.pr_is_cross_repository.is_some()
            && previous.pr_is_cross_repository != current.pr_is_cross_repository)
        || (previous.pr_author.is_some() && previous.pr_author != current.pr_author)
    {
        bail!("publication journal immutable PR receipt changed between records");
    }
    if (previous.create_attempted && !current.create_attempted)
        || (previous.created_by_transaction && !current.created_by_transaction)
        || (previous.observed_existing_pr && !current.observed_existing_pr)
    {
        bail!("publication journal PR provenance regressed between records");
    }
    Ok(())
}

#[cfg(unix)]
fn sync_journal_directory(directory: &Path) -> Result<()> {
    fs::File::open(directory)
        .with_context(|| format!("failed to open journal directory {}", directory.display()))?
        .sync_all()
        .with_context(|| {
            format!(
                "failed to persist journal directory {}",
                directory.display()
            )
        })
}

#[cfg(not(unix))]
fn sync_journal_directory(_directory: &Path) -> Result<()> {
    Ok(())
}

fn validate_publication_object_store_is_self_contained(
    repo: &Repository,
    common_objects: &Path,
) -> Result<()> {
    for alternate in [
        common_objects.join("info/alternates"),
        common_objects.join("info/http-alternates"),
    ] {
        match fs::symlink_metadata(&alternate) {
            Ok(_) => {
                bail!("HTTPS publication refuses object stores with alternate object directories")
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "failed to inspect publication object alternate {}",
                        alternate.display()
                    )
                })
            }
        }
    }

    let config_path = repo.commondir().join("config");
    let path_metadata = fs::symlink_metadata(&config_path).with_context(|| {
        format!(
            "failed to inspect publication source config {}",
            config_path.display()
        )
    })?;
    if path_metadata.file_type().is_symlink()
        || !path_metadata.file_type().is_file()
        || path_metadata.len() > MAX_PUBLICATION_SOURCE_CONFIG_BYTES
    {
        bail!("HTTPS publication source config is not a bounded real regular file");
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let mut config_file = options.open(&config_path).with_context(|| {
        format!(
            "failed to open publication source config {}",
            config_path.display()
        )
    })?;
    let file_metadata = config_file
        .metadata()
        .context("failed to inspect open publication source config")?;
    if !publication_same_filesystem_identity(&path_metadata, &file_metadata)
        || file_metadata.len() != path_metadata.len()
    {
        bail!("HTTPS publication source config changed while it was opened");
    }
    let mut config_bytes = Vec::new();
    Read::by_ref(&mut config_file)
        .take(MAX_PUBLICATION_SOURCE_CONFIG_BYTES + 1)
        .read_to_end(&mut config_bytes)
        .context("failed to read publication source config")?;
    let after = fs::symlink_metadata(&config_path)
        .context("failed to recheck publication source config")?;
    if config_bytes.len() as u64 != file_metadata.len()
        || !publication_same_filesystem_identity(&file_metadata, &after)
        || after.len() != file_metadata.len()
    {
        bail!("HTTPS publication source config changed while it was read");
    }
    let config_text = std::str::from_utf8(&config_bytes)
        .map(str::to_ascii_lowercase)
        .context("publication source config was not UTF-8");
    zeroize_bytes(&mut config_bytes);
    let config_text = ZeroizingString(config_text?);
    if config_text.as_str().contains("partialclone") || config_text.as_str().contains("promisor") {
        bail!("HTTPS publication refuses partial-clone or promisor object stores");
    }

    let mut pending = vec![(common_objects.to_path_buf(), 0usize)];
    let mut entry_count = 0usize;
    while let Some((directory, depth)) = pending.pop() {
        for entry in fs::read_dir(&directory).with_context(|| {
            format!(
                "failed to inspect publication object directory {}",
                directory.display()
            )
        })? {
            let entry = entry.context("failed to read publication object entry")?;
            entry_count = entry_count
                .checked_add(1)
                .context("publication object entry count overflow")?;
            if entry_count > MAX_PUBLICATION_OBJECT_ENTRIES {
                bail!("HTTPS publication object store exceeded its entry safety bound");
            }
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path).with_context(|| {
                format!("failed to inspect publication object {}", path.display())
            })?;
            if metadata.file_type().is_symlink()
                || (!metadata.file_type().is_file() && !metadata.file_type().is_dir())
            {
                bail!("HTTPS publication object store contains a special or linked entry");
            }
            if path
                .extension()
                .is_some_and(|extension| extension == "promisor")
            {
                bail!("HTTPS publication refuses promisor pack metadata");
            }
            if metadata.file_type().is_dir() {
                if depth >= MAX_PUBLICATION_OBJECT_DEPTH {
                    bail!("HTTPS publication object store exceeded its depth safety bound");
                }
                pending.push((path, depth + 1));
            }
        }
    }
    Ok(())
}

fn materialize_publication_object_closure(
    source: &Repository,
    private: &Repository,
    expected_oid: &str,
) -> Result<PrivateObjectClosureSeal> {
    let expected_text = expected_oid;
    let expected_oid =
        Oid::from_str(expected_text).context("publication closure OID was invalid")?;
    if expected_oid.to_string() != expected_text {
        bail!("publication closure OID was not canonical");
    }
    let destination_odb = private
        .odb()
        .context("failed to open private publication object database")?;
    let seal = walk_publication_object_closure(source, expected_oid, Some(&destination_odb))?;
    verify_private_publication_object_closure(private, &seal)?;
    Ok(seal)
}

fn verify_private_publication_object_closure(
    private: &Repository,
    expected: &PrivateObjectClosureSeal,
) -> Result<()> {
    let observed = walk_publication_object_closure(private, expected.expected_oid, None)?;
    if observed.object_ids != expected.object_ids || observed.total_bytes != expected.total_bytes {
        bail!("private publication object closure changed after materialization");
    }
    let odb = private
        .odb()
        .context("failed to reopen private publication object database")?;
    let mut all_objects = BTreeSet::new();
    odb.foreach(|oid| {
        all_objects.insert(*oid);
        all_objects.len() <= MAX_PUBLICATION_CLOSURE_OBJECTS
    })
    .context("failed to enumerate private publication object database")?;
    if all_objects != expected.object_ids {
        bail!("private publication object database contained objects outside the exact closure");
    }
    for forbidden in [
        private.path().join("objects/info/alternates"),
        private.path().join("objects/info/http-alternates"),
    ] {
        if fs::symlink_metadata(&forbidden).is_ok() {
            bail!("private publication object database acquired an alternate object source");
        }
    }
    Ok(())
}

fn walk_publication_object_closure(
    source: &Repository,
    expected_oid: Oid,
    destination: Option<&git2::Odb<'_>>,
) -> Result<PrivateObjectClosureSeal> {
    let source_odb = source
        .odb()
        .context("failed to open publication source object database")?;
    let mut pending = vec![ClosureObject::Commit(expected_oid)];
    let mut object_ids = BTreeSet::new();
    let mut object_kinds = BTreeMap::<Oid, ObjectType>::new();
    let mut commit_edges = BTreeMap::<Oid, Vec<Oid>>::new();
    let mut tree_depths = BTreeMap::<Oid, usize>::new();
    let mut total_bytes = 0_u64;
    let mut traversal_steps = 0usize;

    while let Some(next) = pending.pop() {
        traversal_steps = traversal_steps
            .checked_add(1)
            .context("publication closure traversal count overflow")?;
        if traversal_steps > MAX_PUBLICATION_CLOSURE_OBJECTS.saturating_mul(4) {
            bail!("publication closure graph exceeded its traversal safety bound");
        }
        let (oid, expected_kind) = match next {
            ClosureObject::Commit(oid) => (oid, ObjectType::Commit),
            ClosureObject::Tree { oid, depth } => {
                if depth > MAX_PUBLICATION_TREE_DEPTH {
                    bail!("publication tree closure exceeded its depth safety bound");
                }
                if tree_depths
                    .get(&oid)
                    .is_some_and(|prior_depth| *prior_depth >= depth)
                {
                    continue;
                }
                tree_depths.insert(oid, depth);
                (oid, ObjectType::Tree)
            }
            ClosureObject::Blob(oid) => (oid, ObjectType::Blob),
        };
        if let Some(prior_kind) = object_kinds.get(&oid) {
            if *prior_kind != expected_kind {
                bail!("publication closure reused an object with contradictory kinds");
            }
            if expected_kind != ObjectType::Tree {
                continue;
            }
        }

        let is_new = !object_ids.contains(&oid);
        if is_new && object_ids.len() >= MAX_PUBLICATION_CLOSURE_OBJECTS {
            bail!("publication object closure exceeded its object-count bound");
        }
        let (declared_size, declared_kind) = source_odb
            .read_header(oid)
            .with_context(|| format!("publication closure omitted object header {oid}"))?;
        if declared_kind != expected_kind {
            bail!("publication closure object {oid} had an unexpected kind");
        }
        let declared_size = u64::try_from(declared_size)
            .context("publication closure object size did not fit its byte bound")?;
        if is_new {
            let projected_bytes = total_bytes
                .checked_add(declared_size)
                .context("publication object closure byte count overflow")?;
            if projected_bytes > MAX_PUBLICATION_CLOSURE_BYTES {
                bail!("publication object closure exceeded its aggregate byte bound");
            }
        }
        let object = source_odb
            .read(oid)
            .with_context(|| format!("publication closure omitted object {oid}"))?;
        if object.kind() != expected_kind || object.data().len() as u64 != declared_size {
            bail!("publication closure object changed after its bounded header was read");
        }
        if object_ids.insert(oid) {
            total_bytes = total_bytes
                .checked_add(declared_size)
                .context("publication object closure byte count overflow")?;
            object_kinds.insert(oid, expected_kind);
            if let Some(destination) = destination {
                let written = destination
                    .write(expected_kind, object.data())
                    .with_context(|| format!("failed to materialize publication object {oid}"))?;
                if written != oid {
                    bail!("private publication object materialization changed an object ID");
                }
            }
        }

        match expected_kind {
            ObjectType::Commit => {
                let commit = source
                    .find_commit(oid)
                    .with_context(|| format!("failed to parse publication commit {oid}"))?;
                let mut parents = Vec::new();
                let mut unique_parents = BTreeSet::new();
                for parent in commit.parent_ids() {
                    if parent == oid || !unique_parents.insert(parent) {
                        bail!("publication commit graph contained a self or duplicate parent");
                    }
                    parents.push(parent);
                    pending.push(ClosureObject::Commit(parent));
                }
                commit_edges.insert(oid, parents);
                pending.push(ClosureObject::Tree {
                    oid: commit.tree_id(),
                    depth: 0,
                });
            }
            ObjectType::Tree => {
                let tree = source
                    .find_tree(oid)
                    .with_context(|| format!("failed to parse publication tree {oid}"))?;
                let depth = *tree_depths
                    .get(&oid)
                    .context("publication tree depth tracking was missing")?;
                for entry in tree.iter() {
                    let entry_oid = entry.id();
                    match entry.filemode() {
                        0o160000 => {
                            // A gitlink names a commit in another repository. It is provenance
                            // metadata only and must never make publication read that repository.
                        }
                        0o040000 => pending.push(ClosureObject::Tree {
                            oid: entry_oid,
                            depth: depth + 1,
                        }),
                        _ => pending.push(ClosureObject::Blob(entry_oid)),
                    }
                }
            }
            ObjectType::Blob => {}
            _ => bail!("publication closure contained an unsupported object kind"),
        }
    }

    validate_publication_commit_graph(&commit_edges, expected_oid)?;
    Ok(PrivateObjectClosureSeal {
        expected_oid,
        object_ids,
        total_bytes,
    })
}

fn validate_publication_commit_graph(edges: &BTreeMap<Oid, Vec<Oid>>, root: Oid) -> Result<()> {
    let mut stack = vec![(root, false, 0usize)];
    let mut active = BTreeSet::new();
    let mut complete = BTreeSet::new();
    while let Some((oid, exiting, depth)) = stack.pop() {
        if depth > MAX_PUBLICATION_COMMIT_DEPTH {
            bail!("publication commit graph exceeded its depth safety bound");
        }
        if exiting {
            active.remove(&oid);
            complete.insert(oid);
            continue;
        }
        if complete.contains(&oid) {
            continue;
        }
        if !active.insert(oid) {
            bail!("publication commit graph contained a cycle");
        }
        stack.push((oid, true, depth));
        let parents = edges
            .get(&oid)
            .with_context(|| format!("publication commit graph omitted {oid}"))?;
        for parent in parents.iter().rev() {
            stack.push((*parent, false, depth + 1));
        }
    }
    Ok(())
}

impl PublicationGitContext {
    fn create(
        worktree_path: &Path,
        remote_url: &str,
        operation: PublicationGitOperation,
    ) -> Result<Self> {
        Self::create_with_token_source(worktree_path, remote_url, operation, |key| {
            env::var(key).ok()
        })
    }

    fn create_with_token_source(
        worktree_path: &Path,
        remote_url: &str,
        operation: PublicationGitOperation,
        mut value_for: impl FnMut(&str) -> Option<String>,
    ) -> Result<Self> {
        let transport = publication_remote_transport(remote_url)?;
        let repo = Repository::open(worktree_path).with_context(|| {
            format!(
                "failed to open publication worktree {}",
                worktree_path.display()
            )
        })?;
        let mut runtime_directory = merge::PrivateRuntimeDirectory::create(
            worktree_path,
            merge::PrivateRuntimeKind::PublicationGit,
        )?;
        let directory = runtime_directory.path().to_path_buf();
        let result = (|| -> Result<PublicationGitContextSetup> {
            let objects = directory.join("objects");
            merge::create_private_directory(&objects)?;
            merge::create_private_directory(&directory.join("refs"))?;
            merge::create_private_directory(&directory.join("refs/heads"))?;
            merge::create_private_directory(&directory.join("refs/tags"))?;
            merge::create_private_directory(&directory.join("disabled-hooks"))?;
            merge::write_private_file(
                &directory.join("HEAD"),
                b"ref: refs/heads/maco-publication\n",
            )?;
            let config_path = directory.join("config");
            merge::write_private_file(&config_path, b"")?;
            let mut config = git2::Config::open(&config_path)
                .context("failed to open private publication Git config")?;
            config
                .set_i32("core.repositoryformatversion", 0)
                .context("failed to set publication repository version")?;
            config
                .set_bool("core.bare", true)
                .context("failed to set publication repository bare mode")?;
            config
                .set_bool("core.fsmonitor", false)
                .context("failed to disable publication fsmonitor")?;
            config
                .set_bool("core.untrackedcache", false)
                .context("failed to disable publication untracked cache")?;
            config
                .set_str(
                    "core.hookspath",
                    directory
                        .join("disabled-hooks")
                        .to_str()
                        .context("publication hooks path was not UTF-8")?,
                )
                .context("failed to disable publication hooks")?;
            config
                .set_str("protocol.ext.allow", "never")
                .context("failed to disable external publication protocol")?;
            let global_config = directory.join("disabled-global-config");
            merge::write_private_file(&global_config, b"")?;
            drop(config);

            let object_seal = match operation.requires_object_closure() {
                Some(expected_oid) => {
                    let common_objects = fs::canonicalize(repo.commondir().join("objects"))
                        .context("failed to resolve publication source object directory")?;
                    validate_publication_object_store_is_self_contained(&repo, &common_objects)?;
                    let private = Repository::open_bare(&directory)
                        .context("failed to open private publication Git repository")?;
                    Some(materialize_publication_object_closure(
                        &repo,
                        &private,
                        expected_oid,
                    )?)
                }
                None => None,
            };
            let common_state = fs::canonicalize(merge::ensure_repo_common_state_directory(&repo)?)
                .context("failed to resolve publication repository state directory")?;
            let common_directory = fs::canonicalize(repo.commondir())
                .context("failed to resolve publication common Git directory")?;
            let primary_worktree = common_directory
                .parent()
                .context("publication common Git directory omitted its repository root")?
                .to_path_buf();
            let source_worktree = fs::canonicalize(worktree_path).with_context(|| {
                format!(
                    "failed to resolve publication source worktree {}",
                    worktree_path.display()
                )
            })?;

            let PublicationRemoteTransport::Https {
                host, command_url, ..
            } = &transport;
            let token = select_network_token_with(host, &mut value_for)?;
            let mut config = git2::Config::open(&config_path)
                .context("failed to reopen private publication Git config")?;
            let auth_scope_key = format!("http.{command_url}.extraheader");
            let authorization_header =
                ZeroizingString(format!("Authorization: Basic {}", token.basic_str()?));
            config
                .set_str(&auth_scope_key, authorization_header.as_str())
                .context("failed to bind the host-and-repository HTTPS authorization header")?;
            config
                .set_str("http.followredirects", "false")
                .context("failed to constrain publication redirects")?;
            config
                .set_bool("http.sslverify", true)
                .context("failed to require publication TLS verification")?;
            config
                .set_str("http.proxy", "")
                .context("failed to disable publication proxy discovery")?;
            config
                .set_str("credential.helper", "")
                .context("failed to disable publication credential helpers")?;
            config
                .set_str("core.askpass", "")
                .context("failed to disable publication askpass helpers")?;
            let command_url = command_url.clone();
            config
                .set_str("remote.maco-publication.url", &command_url)
                .context("failed to bind the validated publication remote")?;
            drop(config);
            harden_private_config_mode(&config_path)?;

            let config_files = vec![
                capture_private_config_file(&config_path)?,
                capture_private_config_file(&global_config)?,
            ];
            let mut environment = merge::minimal_network_environment()?;
            environment.insert(
                "GIT_CONFIG_GLOBAL".to_string(),
                global_config
                    .to_str()
                    .context("publication global config path was not UTF-8")?
                    .to_string(),
            );
            validate_publication_git_environment(&environment, &global_config)?;

            let profile = TrustedFixedNetworkProfile::read_write(&directory)
                .with_resource_limits(Default::default())
                .with_visible_read_only_root(&objects)
                .with_visible_read_only_file(&config_path)
                .with_visible_read_only_file(&global_config)
                .with_hidden_root(&primary_worktree)
                .with_hidden_root(&source_worktree)
                .with_hidden_root(&common_state);
            Ok((
                environment,
                PublicationGitBoundary::Https(profile),
                config_files,
                Some(token),
                object_seal,
            ))
        })();
        match result {
            Ok((environment, boundary, config_files, token, object_seal)) => Ok(Self {
                directory,
                runtime_directory,
                environment,
                boundary,
                config_files,
                token,
                operation,
                object_seal,
            }),
            Err(error) => {
                let erase = erase_private_config_paths_if_present(&[
                    directory.join("config"),
                    directory.join("disabled-global-config"),
                ]);
                let close = runtime_directory.close();
                match (erase, close) {
                    (Ok(()), Ok(())) => Err(error),
                    (erase, close) => Err(anyhow::anyhow!(
                        "{error:#}; publication setup cleanup failed: erase={:?}, close={:?}",
                        erase.err().map(|error| format!("{error:#}")),
                        close.err().map(|error| format!("{error:#}")),
                    )),
                }
            }
        }
    }

    fn run(mut self) -> Result<merge::RequiredCommandOutput> {
        let execution = self.run_inner();
        let cleanup = self.close();
        match (execution, cleanup) {
            (Ok(output), Ok(())) => Ok(output),
            (Err(error), Ok(())) => Err(error),
            (Ok(_), Err(cleanup)) => Err(cleanup
                .context("publication command completed but private token runtime cleanup failed")),
            (Err(error), Err(cleanup)) => Err(anyhow::anyhow!(
                "{error:#}; private token runtime cleanup also failed: {cleanup:#}"
            )),
        }
    }

    fn run_inner(&self) -> Result<merge::RequiredCommandOutput> {
        let label = self.operation.label();
        self.runtime_directory
            .verify_identity()
            .context("private publication Git runtime changed before command execution")?;
        verify_private_config_files(&self.config_files)?;
        let global_config = self.directory.join("disabled-global-config");
        validate_publication_git_environment(&self.environment, &global_config)?;
        self.verify_object_seal()?;
        let operation = self.operation.arguments();
        validate_publication_git_operation(&operation)?;
        let args = self.command_args(operation);
        let output = match &self.boundary {
            PublicationGitBoundary::Https(profile) => merge::run_required_network_direct(
                label,
                merge::resolve_trusted_executable("git")?,
                args,
                &self.directory,
                self.environment.clone(),
                StdinMode::Null,
                merge::NETWORK_PROCESS_TIMEOUT,
                GH_CAPTURE_LIMIT_BYTES,
                0,
                profile.clone(),
            ),
        };
        let mut output = output.map_err(|error| self.redact_error(error))?;
        self.runtime_directory
            .verify_identity()
            .context("private publication Git runtime changed during command execution")?;
        verify_private_config_files(&self.config_files)?;
        self.verify_object_seal()?;
        self.redact_output(&mut output);
        Ok(output)
    }

    fn close(&mut self) -> Result<()> {
        let erase = erase_private_config_files(&mut self.config_files);
        self.environment.clear();
        drop(self.token.take());
        let close = self.runtime_directory.close();
        match (erase, close) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
            (Err(erase), Err(close)) => Err(anyhow::anyhow!(
                "private config erasure failed: {erase:#}; private runtime close failed: {close:#}"
            )),
        }
    }

    fn verify_object_seal(&self) -> Result<()> {
        if let Some(seal) = &self.object_seal {
            let private = Repository::open_bare(&self.directory)
                .context("failed to reopen private publication object database")?;
            verify_private_publication_object_closure(&private, seal)?;
        } else {
            let private = Repository::open_bare(&self.directory)
                .context("failed to inspect observation-only publication object database")?;
            let odb = private
                .odb()
                .context("failed to open observation-only publication object database")?;
            let mut found = false;
            odb.foreach(|_| {
                found = true;
                false
            })
            .context("failed to inspect observation-only publication object database")?;
            if found {
                bail!("observation-only publication context unexpectedly contained Git objects");
            }
        }
        Ok(())
    }

    fn command_args(&self, operation: Vec<OsString>) -> Vec<OsString> {
        let mut args = vec![
            OsString::from("--git-dir"),
            self.directory.as_os_str().to_os_string(),
            OsString::from("-c"),
            OsString::from("core.fsmonitor=false"),
            OsString::from("-c"),
            OsString::from("core.untrackedCache=false"),
            OsString::from("-c"),
            OsString::from("protocol.ext.allow=never"),
            OsString::from("-c"),
            OsString::from(format!(
                "core.hooksPath={}",
                self.directory.join("disabled-hooks").display()
            )),
        ];
        args.extend(operation);
        args
    }

    fn redact_output(&self, output: &mut merge::RequiredCommandOutput) {
        if let Some(token) = &self.token {
            redact_private_bytes(&mut output.stdout, &token.bytes);
            redact_private_bytes(&mut output.stderr, &token.bytes);
            redact_private_bytes(&mut output.stdout, &token.basic);
            redact_private_bytes(&mut output.stderr, &token.basic);
        }
    }

    fn redact_error(&self, error: anyhow::Error) -> anyhow::Error {
        let mut text = format!("{error:#}");
        if let Some(token) = &self.token {
            if let Ok(private) = token.as_str() {
                text = text.replace(private, "<redacted:network-token>");
            }
            if let Ok(private) = token.basic_str() {
                text = text.replace(private, "<redacted:network-token>");
            }
        }
        anyhow::anyhow!(text)
    }
}

impl Drop for PublicationGitContext {
    fn drop(&mut self) {
        self.environment.clear();
    }
}

impl PrivateNetworkToken {
    fn as_str(&self) -> Result<&str> {
        std::str::from_utf8(&self.bytes).context("network token was not UTF-8")
    }

    fn basic_str(&self) -> Result<&str> {
        std::str::from_utf8(&self.basic).context("encoded network token was not UTF-8")
    }
}

fn select_network_token_with(
    host: &str,
    mut value_for: impl FnMut(&str) -> Option<String>,
) -> Result<PrivateNetworkToken> {
    authorize_network_host_with(host, &mut value_for)?;
    let keys = if host == "github.com" {
        ["GH_TOKEN", "GITHUB_TOKEN"]
    } else {
        ["GH_ENTERPRISE_TOKEN", "GITHUB_ENTERPRISE_TOKEN"]
    };
    let values = keys
        .into_iter()
        .filter_map(|key| value_for(key).map(|value| (key, ZeroizingString(value))))
        .filter(|(_, value)| !value.as_str().is_empty())
        .collect::<Vec<_>>();
    let (_, first) = values.first().with_context(|| {
        format!(
            "HTTPS publication to {host} requires {} or {} before any remote effect",
            keys[0], keys[1]
        )
    })?;
    if values
        .iter()
        .any(|(_, value)| value.as_str() != first.as_str())
    {
        bail!(
            "HTTPS publication token variables {} and {} disagree; refusing ambiguous authentication",
            keys[0], keys[1]
        );
    }
    if first.as_str().len() < 4
        || first.as_str().len() > MAX_NETWORK_TOKEN_BYTES
        || first
            .as_str()
            .as_bytes()
            .iter()
            .any(|byte| !byte.is_ascii_alphanumeric() && !matches!(byte, b'_' | b'-' | b'.'))
    {
        bail!("HTTPS publication token is empty, malformed, or exceeds its safety bound");
    }
    let mut basic_source = b"x-access-token:".to_vec();
    basic_source.extend_from_slice(first.as_bytes());
    let basic = encode_base64(&basic_source).into_bytes();
    zeroize_bytes(&mut basic_source);
    Ok(PrivateNetworkToken {
        bytes: first.as_bytes().to_vec(),
        basic,
    })
}

fn authorize_network_host_with(
    host: &str,
    mut value_for: impl FnMut(&str) -> Option<String>,
) -> Result<()> {
    let canonical = normalize_github_host(host)?;
    if canonical != host {
        bail!("HTTPS publication host authority was not canonical");
    }
    if host == "github.com" {
        return Ok(());
    }
    let keys = ["GH_HOST", "GITHUB_HOST"];
    let values = keys
        .into_iter()
        .filter_map(|key| value_for(key).map(|value| (key, value)))
        .filter(|(_, value)| !value.is_empty())
        .collect::<Vec<_>>();
    let (_, first) = values.first().with_context(|| {
        format!(
            "enterprise HTTPS publication to {host} requires an explicit exact {} or {} host allowlist entry before token selection",
            keys[0], keys[1]
        )
    })?;
    if values.iter().any(|(_, value)| value != first) {
        bail!(
            "enterprise publication host variables {} and {} disagree",
            keys[0],
            keys[1]
        );
    }
    let approved = normalize_github_host(first)
        .context("enterprise publication host allowlist entry was invalid")?;
    if approved != *first || approved != host {
        bail!(
            "enterprise publication host allowlist entry must exactly match the canonical remote authority"
        );
    }
    Ok(())
}

fn select_github_expected_author_with(
    mut value_for: impl FnMut(&str) -> Option<String>,
) -> Result<String> {
    let keys = ["GH_EXPECTED_AUTHOR", "GITHUB_EXPECTED_AUTHOR"];
    let values = keys
        .into_iter()
        .filter_map(|key| value_for(key).map(|value| (key, value)))
        .filter(|(_, value)| !value.is_empty())
        .collect::<Vec<_>>();
    let (_, first) = values.first().with_context(|| {
        format!(
            "GitHub publication requires an explicit {} or {} provenance binding before token selection",
            keys[0], keys[1]
        )
    })?;
    if values.iter().any(|(_, value)| value != first) {
        bail!(
            "GitHub expected-author variables {} and {} disagree",
            keys[0],
            keys[1]
        );
    }
    canonical_github_author_login(first)
}

fn encode_base64(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let first = chunk[0];
        let second = chunk.get(1).copied().unwrap_or(0);
        let third = chunk.get(2).copied().unwrap_or(0);
        output.push(ALPHABET[usize::from(first >> 2)] as char);
        output.push(ALPHABET[usize::from(((first & 0x03) << 4) | (second >> 4))] as char);
        output.push(if chunk.len() > 1 {
            ALPHABET[usize::from(((second & 0x0f) << 2) | (third >> 6))] as char
        } else {
            '='
        });
        output.push(if chunk.len() > 2 {
            ALPHABET[usize::from(third & 0x3f)] as char
        } else {
            '='
        });
    }
    output
}

fn capture_private_config_file(path: &Path) -> Result<PrivateConfigFileIdentity> {
    capture_bound_config_file(path, true)
}

fn harden_private_config_mode(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

        let mut options = OpenOptions::new();
        options.read(true).write(true);
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
        let file = options
            .open(path)
            .with_context(|| format!("failed to reopen private config {}", path.display()))?;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .with_context(|| format!("failed to harden private config {}", path.display()))?;
        file.sync_all()
            .with_context(|| format!("failed to persist private config {}", path.display()))?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        bail!("private network config hardening is unsupported on this platform")
    }
}

fn capture_bound_config_file(
    path: &Path,
    private_owner_only: bool,
) -> Result<PrivateConfigFileIdentity> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let path_metadata_before = fs::symlink_metadata(path)
            .with_context(|| format!("failed to inspect private config {}", path.display()))?;
        let mut options = OpenOptions::new();
        options.read(true);
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
        let mut file = options
            .open(path)
            .with_context(|| format!("failed to open private config {}", path.display()))?;
        let file_metadata = file
            .metadata()
            .with_context(|| format!("failed to inspect open private config {}", path.display()))?;
        let path_metadata_after = fs::symlink_metadata(path).with_context(|| {
            format!(
                "failed to re-inspect private config {} after open",
                path.display()
            )
        })?;
        let safe = |metadata: &fs::Metadata| {
            let mode = metadata.permissions().mode() & 0o777;
            let owner_is_trusted = metadata.uid() == unsafe { libc::geteuid() }
                || (!private_owner_only && metadata.uid() == 0);
            !metadata.file_type().is_symlink()
                && metadata.file_type().is_file()
                && if private_owner_only {
                    mode == 0o600
                } else {
                    mode & 0o022 == 0
                }
                && owner_is_trusted
                && metadata.nlink() == 1
        };
        let same_identity = |left: &fs::Metadata, right: &fs::Metadata| {
            left.dev() == right.dev() && left.ino() == right.ino()
        };
        if !safe(&path_metadata_before)
            || !safe(&file_metadata)
            || !safe(&path_metadata_after)
            || !same_identity(&path_metadata_before, &file_metadata)
            || !same_identity(&file_metadata, &path_metadata_after)
        {
            bail!(
                "private config {} is not a single-link, owner-only, path-bound regular file",
                path.display()
            );
        }
        let mut bytes = Vec::new();
        Read::by_ref(&mut file)
            .take((MAX_NETWORK_TOKEN_BYTES * 4 + 64 * 1024 + 1) as u64)
            .read_to_end(&mut bytes)
            .with_context(|| format!("failed to read private config {}", path.display()))?;
        if bytes.len() > MAX_NETWORK_TOKEN_BYTES * 4 + 64 * 1024 {
            zeroize_bytes(&mut bytes);
            bail!("private config {} exceeds its safety bound", path.display());
        }
        Ok(PrivateConfigFileIdentity {
            path: path.to_path_buf(),
            private_owner_only,
            device: file_metadata.dev(),
            inode: file_metadata.ino(),
            bytes,
        })
    }
    #[cfg(not(unix))]
    {
        let _ = (path, private_owner_only);
        bail!("private network config identity verification is unsupported on this platform")
    }
}

fn verify_private_config_files(files: &[PrivateConfigFileIdentity]) -> Result<()> {
    for expected in files {
        let actual = capture_bound_config_file(&expected.path, expected.private_owner_only)?;
        #[cfg(unix)]
        let identity_matches = actual.device == expected.device && actual.inode == expected.inode;
        #[cfg(not(unix))]
        let identity_matches = false;
        if !identity_matches || actual.bytes != expected.bytes {
            bail!(
                "private network config {} changed identity or contents while in use",
                expected.path.display()
            );
        }
    }
    Ok(())
}

fn erase_private_config_files(files: &mut [PrivateConfigFileIdentity]) -> Result<()> {
    verify_private_config_files(files)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

        for expected in files {
            let mut options = OpenOptions::new();
            options.read(true).write(true);
            options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
            let mut file = options.open(&expected.path).with_context(|| {
                format!(
                    "failed to reopen private config for erasure {}",
                    expected.path.display()
                )
            })?;
            let metadata = file.metadata().with_context(|| {
                format!(
                    "failed to inspect private config for erasure {}",
                    expected.path.display()
                )
            })?;
            if metadata.dev() != expected.device
                || metadata.ino() != expected.inode
                || metadata.len() != expected.bytes.len() as u64
            {
                bail!(
                    "private config {} changed before explicit erasure",
                    expected.path.display()
                );
            }
            file.seek(SeekFrom::Start(0))
                .context("failed to seek private config for erasure")?;
            let zeros = vec![0_u8; expected.bytes.len()];
            file.write_all(&zeros)
                .context("failed to overwrite private config during erasure")?;
            file.sync_all()
                .context("failed to persist private config erasure")?;
            zeroize_bytes(&mut expected.bytes);
            expected.bytes.clear();
            expected.bytes.resize(zeros.len(), 0);
            let erased = capture_bound_config_file(&expected.path, expected.private_owner_only)?;
            if erased.device != expected.device
                || erased.inode != expected.inode
                || erased.bytes != expected.bytes
            {
                bail!(
                    "private config {} did not verify as erased",
                    expected.path.display()
                );
            }
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = files;
        bail!("explicit private config erasure is unsupported on this platform")
    }
}

fn erase_private_config_paths_if_present(paths: &[PathBuf]) -> Result<()> {
    let mut files = Vec::new();
    for path in paths {
        match fs::symlink_metadata(path) {
            Ok(_) => {
                harden_private_config_mode(path)?;
                files.push(capture_private_config_file(path)?);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "failed to inspect setup config for erasure {}",
                        path.display()
                    )
                })
            }
        }
    }
    erase_private_config_files(&mut files)
}

fn redact_private_bytes(output: &mut Vec<u8>, private: &[u8]) {
    if private.is_empty() || private.len() > output.len() {
        return;
    }
    const REPLACEMENT: &[u8] = b"<redacted:network-token>";
    let mut redacted = Vec::with_capacity(output.len());
    let mut offset = 0usize;
    while let Some(position) = output[offset..]
        .windows(private.len())
        .position(|window| window == private)
    {
        let absolute = offset + position;
        redacted.extend_from_slice(&output[offset..absolute]);
        redacted.extend_from_slice(REPLACEMENT);
        offset = absolute + private.len();
    }
    if offset != 0 {
        redacted.extend_from_slice(&output[offset..]);
        zeroize_bytes(output);
        *output = redacted;
    }
}

fn validate_publication_git_environment(
    environment: &BTreeMap<String, String>,
    global_config: &Path,
) -> Result<()> {
    let required = [
        ("GIT_CONFIG_NOSYSTEM", "1"),
        ("GIT_ATTR_NOSYSTEM", "1"),
        ("GIT_OPTIONAL_LOCKS", "0"),
        ("GIT_TERMINAL_PROMPT", "0"),
    ];
    for (key, expected) in required {
        if environment.get(key).map(String::as_str) != Some(expected) {
            bail!("publication Git environment omitted the exact required {key}={expected}");
        }
    }
    let expected_global = global_config
        .to_str()
        .context("publication global Git config path was not UTF-8")?;
    if environment.get("GIT_CONFIG_GLOBAL").map(String::as_str) != Some(expected_global) {
        bail!("publication Git environment changed its private global config binding");
    }
    if environment
        .keys()
        .any(|key| key.starts_with("GH_") || key.starts_with("GITHUB_"))
    {
        bail!("publication Git environment may not contain gh authentication inputs");
    }
    Ok(())
}

fn validate_publication_git_operation(operation: &[OsString]) -> Result<()> {
    let operation = operation
        .iter()
        .map(|argument| {
            argument
                .to_str()
                .context("publication Git argument was not strict UTF-8")
        })
        .collect::<Result<Vec<_>>>()?;
    match operation.as_slice() {
        ["ls-remote", "--refs", "maco-publication", remote_ref] => {
            validate_publication_ref(remote_ref)
        }
        ["push", "--no-verify", lease, "maco-publication", refspec] => {
            let leased_ref = lease
                .strip_prefix("--force-with-lease=")
                .and_then(|value| value.strip_suffix(':'))
                .context("publication Git push omitted its create-only lease")?;
            validate_publication_ref(leased_ref)?;
            let (oid, remote_ref) = refspec
                .split_once(':')
                .context("publication Git push omitted its bound refspec")?;
            if remote_ref != leased_ref
                || oid.len() != 40
                || !oid
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
                || Oid::from_str(oid).is_err()
            {
                bail!("publication Git push refspec did not match its exact create-only lease");
            }
            Ok(())
        }
        _ => bail!("publication Git command is outside the fixed ls-remote/push allowlist"),
    }
}

fn validate_publication_ref(value: &str) -> Result<()> {
    if value.len() > MAX_PUBLICATION_REF_BYTES {
        bail!("publication ref exceeds its safety bound");
    }
    let suffix = value
        .strip_prefix("refs/heads/")
        .context("publication ref is outside refs/heads")?;
    if suffix.is_empty()
        || suffix.starts_with('/')
        || suffix.ends_with(['/', '.'])
        || suffix.contains("..")
        || suffix.contains("//")
        || suffix.contains("@{")
        || suffix.split('/').count() > MAX_PUBLICATION_REF_COMPONENTS
        || !suffix
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'-' | b'_' | b'.'))
    {
        bail!("publication ref is malformed");
    }
    Ok(())
}

fn validate_publication_remote_url(remote_url: &str) -> Result<()> {
    if remote_url.is_empty()
        || remote_url.len() > MAX_PUBLICATION_REMOTE_URL_BYTES
        || remote_url
            .as_bytes()
            .iter()
            .any(|byte| byte.is_ascii_control())
    {
        bail!("publication remote URL is empty or contains control bytes");
    }
    if remote_url.contains(['?', '#']) {
        bail!("publication remote URLs may not contain a query or fragment");
    }
    if remote_url.contains(['%', '\\', '@']) {
        bail!("publication remote URLs may not contain escapes, backslashes, or userinfo");
    }
    Ok(())
}

fn publication_remote_transport(remote_url: &str) -> Result<PublicationRemoteTransport> {
    validate_publication_remote_url(remote_url)?;
    if remote_url.starts_with("file://") || remote_url.starts_with('/') {
        bail!(
            "local/file publication is disabled because a concurrent same-UID process could mutate bare-repository config during receive-pack; use a canonical HTTPS remote"
        );
    }
    let remainder = remote_url.strip_prefix("https://").context(
        "publication supports only canonical HTTPS remotes; local/file, SSH, HTTP, git, helpers, and SCP syntax are refused",
    )?;
    if remote_url.contains('%') || remote_url.contains('\\') {
        bail!("HTTPS publication remote may not contain escapes or backslashes");
    }
    let (authority, path) = remainder
        .split_once('/')
        .context("HTTPS publication remote omitted a repository path")?;
    if authority.contains('@') {
        bail!("HTTPS publication remote may not contain userinfo");
    }
    let host = normalize_github_host(authority)?;
    let authority_is_canonical =
        host == authority || (host == "github.com" && authority == "github.com:443");
    if !authority_is_canonical
        || path.is_empty()
        || path.len() > MAX_PUBLICATION_PATH_BYTES
        || path.split('/').count() > MAX_PUBLICATION_PATH_COMPONENTS
        || path.starts_with('/')
        || path.ends_with('/')
    {
        bail!("HTTPS publication remote is not canonical");
    }
    for component in path.split('/') {
        if component.is_empty()
            || matches!(component, "." | "..")
            || !component.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'~')
            })
        {
            bail!("HTTPS publication repository path is malformed");
        }
    }
    let path = if path.ends_with(".git") {
        path.to_string()
    } else {
        format!("{path}.git")
    };
    let command_url = format!("https://{host}/{path}");
    Ok(PublicationRemoteTransport::Https {
        host,
        path,
        command_url,
    })
}

fn ensure_remote_expected_commit(
    worktree_path: &Path,
    transaction: &mut PublicationTransaction,
) -> Result<()> {
    if let Some(request) = transaction.push_effect_request.clone() {
        let mut provider = GitPushExternalEffectProvider {
            worktree_path,
            remote_url: &transaction.remote_url,
            remote_ref: &transaction.journal.remote_ref,
            expected_oid: &transaction.journal.expected_oid,
            source_guard: request.source.as_ref(),
        };
        let receipt =
            execute_external_effect_exactly_once(worktree_path, request.clone(), &mut provider)?;
        if receipt.provider_id != transaction.journal.expected_oid {
            bail!("authenticated push receipt did not contain the expected remote OID");
        }
        transaction.journal.push_observed_oid = Some(receipt.provider_id);
        transaction.advance_phase(PublicationTransactionPhase::PushObserved);
        transaction.journal.last_error = None;
        transaction.persist()?;
        return Ok(());
    }
    let previous = transaction.journal.clone();
    let before = observe_remote_ref(
        worktree_path,
        &transaction.remote_url,
        &transaction.journal.remote_ref,
    )?;
    if let Some(observed) = before {
        if observed != transaction.journal.expected_oid {
            bail!(
                "unique publication ref {} points to {}, expected {}; refusing overwrite",
                transaction.journal.remote_ref,
                observed,
                transaction.journal.expected_oid
            );
        }
        transaction.journal.push_observed_oid = Some(observed);
        transaction.advance_phase(PublicationTransactionPhase::PushObserved);
        transaction.journal.last_error = None;
        transaction.persist_if_changed(&previous)?;
        return Ok(());
    }

    let push = push_git_commit_create_only(
        worktree_path,
        &transaction.remote_url,
        &transaction.journal.remote_ref,
        &transaction.journal.expected_oid,
    )?;
    let after = observe_remote_ref(
        worktree_path,
        &transaction.remote_url,
        &transaction.journal.remote_ref,
    )?;
    if after.as_deref() == Some(transaction.journal.expected_oid.as_str()) {
        transaction.journal.push_observed_oid = after;
        transaction.advance_phase(PublicationTransactionPhase::PushObserved);
        transaction.journal.last_error = None;
        transaction.persist_if_changed(&previous)?;
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&push.stderr).trim().to_string();
    if push.success {
        bail!(
            "git push returned success but remote ref {} was not bound to expected OID {}",
            transaction.journal.remote_ref,
            transaction.journal.expected_oid
        );
    }
    bail!(
        "git push failed and expected remote OID was not observed: {}",
        if stderr.is_empty() {
            "no stderr was returned"
        } else {
            &stderr
        }
    )
}

struct GitPushExternalEffectProvider<'a> {
    worktree_path: &'a Path,
    remote_url: &'a str,
    remote_ref: &'a str,
    expected_oid: &'a str,
    source_guard: Option<&'a ExternalSourceGuard>,
}

impl GitPushExternalEffectProvider<'_> {
    fn revalidate_source_full(&self) -> Result<()> {
        if let Some(source) = self.source_guard {
            revalidate_external_source(self.worktree_path, source)?;
        }
        Ok(())
    }

    fn revalidate_source_action_revision(&self) -> Result<()> {
        if let Some(source) = self.source_guard {
            revalidate_external_source_action_revision(self.worktree_path, source)?;
        }
        Ok(())
    }

    fn exact_receipt(&self, request: &ExternalEffectRequest) -> ExternalEffectReceipt {
        ExternalEffectReceipt {
            version: EXTERNAL_EFFECT_VERSION,
            transport_provider: request.transport_provider.clone(),
            repository_identity: request.repository_identity.clone(),
            repository_selector: request.repository_selector.clone(),
            effect_id: request.effect_id.clone(),
            operation: request.operation,
            source_provenance_digest: request
                .source
                .as_ref()
                .map(|source| source.provenance_digest.clone()),
            provider_id: self.expected_oid.to_string(),
            url: format!("{}#{}", redact_remote_url(self.remote_url), self.remote_ref),
            repository: request.repository_selector.clone(),
            marker: request.marker.clone(),
            target: request.target.clone(),
            payload: request.payload.clone(),
            target_digest: request.target_digest.clone(),
            payload_digest: request.payload_digest.clone(),
        }
    }
}

impl ExternalEffectProvider for GitPushExternalEffectProvider<'_> {
    fn preflight_before_start(&mut self, _request: &ExternalEffectRequest) -> Result<()> {
        self.revalidate_source_full()
    }

    fn lookup(&mut self, request: &ExternalEffectRequest) -> Result<Vec<ExternalEffectReceipt>> {
        self.revalidate_source_action_revision()?;
        match observe_remote_ref(self.worktree_path, self.remote_url, self.remote_ref)? {
            None => Ok(Vec::new()),
            Some(observed) if observed == self.expected_oid => {
                Ok(vec![self.exact_receipt(request)])
            }
            Some(_) => bail!("stable external-effect remote ref points to a different OID"),
        }
    }

    fn invoke(&mut self, request: &ExternalEffectRequest) -> Result<ExternalEffectReceipt> {
        self.revalidate_source_full()?;
        let output = push_git_commit_create_only(
            self.worktree_path,
            self.remote_url,
            self.remote_ref,
            self.expected_oid,
        )?;
        if !output.success {
            bail!("git push did not return success");
        }
        let matches = self.lookup(request)?;
        if matches.len() != 1 {
            bail!("git push response could not be reconciled to its stable remote ref");
        }
        Ok(matches[0].clone())
    }

    fn verify(
        &mut self,
        request: &ExternalEffectRequest,
        receipt: &ExternalEffectReceipt,
    ) -> Result<ExternalEffectReceipt> {
        validate_external_effect_receipt(request, receipt)?;
        let matches = self.lookup(request)?;
        if matches.as_slice() != [receipt.clone()] {
            bail!("git push receipt no longer matches the exact remote ref observation");
        }
        Ok(receipt.clone())
    }
}

fn ensure_github_remote_expected_commit(
    worktree_path: &Path,
    transaction: &mut PublicationTransaction,
) -> Result<()> {
    require_remote_expected_base(
        worktree_path,
        transaction,
        "before publication ref creation",
    )?;
    ensure_remote_expected_commit(worktree_path, transaction)
}

fn observe_remote_ref(
    worktree_path: &Path,
    remote_url: &str,
    remote_ref: &str,
) -> Result<Option<String>> {
    let operation = PublicationGitOperation::observe(remote_ref)?;
    let context = PublicationGitContext::create(worktree_path, remote_url, operation)?;
    let output = context.run()?;
    if !output.success {
        bail!(
            "git ls-remote failed for {}: {}",
            remote_ref,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let mut observed = None;
    for line in output.stdout.split(|byte| *byte == b'\n') {
        if line.is_empty() {
            continue;
        }
        let mut fields = line.split(|byte| byte.is_ascii_whitespace());
        let oid = fields.next().context("git ls-remote omitted object id")?;
        let reported_ref = fields.next().context("git ls-remote omitted ref name")?;
        if fields.any(|field| !field.is_empty()) {
            bail!("git ls-remote returned unexpected extra fields");
        }
        if reported_ref != remote_ref.as_bytes() {
            bail!("git ls-remote returned an unexpected ref");
        }
        let oid = std::str::from_utf8(oid).context("remote OID was not ASCII")?;
        let oid = Oid::from_str(oid)
            .context("remote OID was invalid")?
            .to_string();
        if observed.replace(oid).is_some() {
            bail!("git ls-remote returned duplicate publication refs");
        }
    }
    Ok(observed)
}

fn push_git_commit_create_only(
    worktree_path: &Path,
    remote_url: &str,
    remote_ref: &str,
    expected_oid: &str,
) -> Result<merge::RequiredCommandOutput> {
    let operation = PublicationGitOperation::push_create_only(expected_oid, remote_ref)?;
    let context = PublicationGitContext::create(worktree_path, remote_url, operation)?;
    context.run()
}

fn reconcile_github_pr(
    worktree_path: &Path,
    transaction: &mut PublicationTransaction,
) -> Result<GithubPrResult> {
    if let Some(request) = transaction.pr_effect_request.clone() {
        let mut api = CliGithubApi;
        let mut provider = GithubPrExternalEffectProvider {
            worktree_path,
            remote_url: &transaction.remote_url,
            journal: transaction.journal.clone(),
            api: &mut api,
            source_guard: request.source.as_ref(),
        };
        let receipt =
            execute_external_effect_exactly_once(worktree_path, request.clone(), &mut provider)?;
        let result = provider.view_exact_receipt(&receipt)?;
        return verify_github_receipt_with_remote_check(
            worktree_path,
            transaction,
            result,
            true,
            false,
            |_, _, _| Ok(()),
        );
    }
    reconcile_github_pr_with_api(worktree_path, transaction, &mut CliGithubApi)
}

struct GithubPrExternalEffectProvider<'a, A: GithubApi> {
    worktree_path: &'a Path,
    remote_url: &'a str,
    journal: PublicationTransactionJournal,
    api: &'a mut A,
    source_guard: Option<&'a ExternalSourceGuard>,
}

impl<A: GithubApi> GithubPrExternalEffectProvider<'_, A> {
    fn revalidate_bound_inputs(&mut self, require_full_source: bool) -> Result<()> {
        if let Some(source) = self.source_guard {
            if require_full_source {
                revalidate_external_source(self.worktree_path, source)?;
            } else {
                revalidate_external_source_action_revision(self.worktree_path, source)?;
            }
        }
        let base_oid = self
            .journal
            .expected_base_oid
            .as_deref()
            .context("GitHub PR effect omitted exact base OID")?;
        let base_ref = format!("refs/heads/{}", self.journal.base);
        if observe_remote_ref(self.worktree_path, self.remote_url, &base_ref)?.as_deref()
            != Some(base_oid)
        {
            bail!("GitHub PR effect base ref changed from its exact reviewed OID");
        }
        if observe_remote_ref(
            self.worktree_path,
            self.remote_url,
            &self.journal.remote_ref,
        )?
        .as_deref()
            != Some(self.journal.expected_oid.as_str())
        {
            bail!("GitHub PR effect head ref changed from its stable expected OID");
        }
        Ok(())
    }

    fn repository(&self) -> Result<&GithubRepositoryIdentity> {
        self.journal
            .github_repository
            .as_ref()
            .context("GitHub PR effect omitted repository identity")
    }

    fn receipt_from_result(
        &self,
        request: &ExternalEffectRequest,
        result: &GithubPrResult,
    ) -> ExternalEffectReceipt {
        ExternalEffectReceipt {
            version: EXTERNAL_EFFECT_VERSION,
            transport_provider: request.transport_provider.clone(),
            repository_identity: request.repository_identity.clone(),
            repository_selector: request.repository_selector.clone(),
            effect_id: request.effect_id.clone(),
            operation: request.operation,
            source_provenance_digest: request
                .source
                .as_ref()
                .map(|source| source.provenance_digest.clone()),
            provider_id: result.number.to_string(),
            url: result.url.clone(),
            repository: request.repository_selector.clone(),
            marker: request.marker.clone(),
            target: request.target.clone(),
            payload: request.payload.clone(),
            target_digest: request.target_digest.clone(),
            payload_digest: request.payload_digest.clone(),
        }
    }

    fn exact_remote_results(&mut self) -> Result<Vec<GithubPrResult>> {
        self.revalidate_bound_inputs(false)?;
        let repository = self.repository()?.clone();
        let candidates =
            self.api
                .list(self.worktree_path, &self.journal.remote_branch, &repository)?;
        if candidates.len() > MAX_GITHUB_PR_LIST_RECEIPTS {
            bail!("GitHub PR effect lookup returned too many candidates");
        }
        let mut exact = Vec::with_capacity(candidates.len());
        for candidate in candidates {
            let viewed = self.api.view(
                self.worktree_path,
                &candidate.number.to_string(),
                &repository,
            )?;
            validate_github_receipt_contract(&viewed, &self.journal)?;
            exact.push(viewed);
        }
        exact.sort_by_key(|result| result.number);
        exact.dedup_by_key(|result| result.number);
        Ok(exact)
    }

    fn view_exact_receipt(&mut self, receipt: &ExternalEffectReceipt) -> Result<GithubPrResult> {
        self.revalidate_bound_inputs(false)?;
        let repository = self.repository()?.clone();
        let viewed = self
            .api
            .view(self.worktree_path, &receipt.provider_id, &repository)?;
        validate_github_receipt_contract(&viewed, &self.journal)?;
        if viewed.url != receipt.url {
            bail!("GitHub PR exact view URL changed from authenticated receipt");
        }
        Ok(viewed)
    }
}

impl<A: GithubApi> ExternalEffectProvider for GithubPrExternalEffectProvider<'_, A> {
    fn preflight_before_start(&mut self, _request: &ExternalEffectRequest) -> Result<()> {
        self.revalidate_bound_inputs(true)
    }

    fn lookup(&mut self, request: &ExternalEffectRequest) -> Result<Vec<ExternalEffectReceipt>> {
        Ok(self
            .exact_remote_results()?
            .iter()
            .map(|result| self.receipt_from_result(request, result))
            .collect())
    }

    fn invoke(&mut self, request: &ExternalEffectRequest) -> Result<ExternalEffectReceipt> {
        self.revalidate_bound_inputs(true)?;
        let repository = self.repository()?.clone();
        let title = self
            .journal
            .expected_pr_title
            .as_deref()
            .context("GitHub PR effect omitted title")?;
        let body = self
            .journal
            .expected_pr_body
            .as_deref()
            .context("GitHub PR effect omitted marker-bound body")?;
        let output = self.api.create(
            self.worktree_path,
            &self.journal.remote_branch,
            &self.journal.base,
            title,
            body,
            self.journal.draft,
            &repository,
        )?;
        if !output.stderr.is_empty() && output.stdout.is_empty() {
            bail!("GitHub PR provider returned no usable creation response");
        }
        let matches = self.exact_remote_results()?;
        if matches.len() != 1 {
            bail!("GitHub PR creation response could not be reconciled exactly");
        }
        Ok(self.receipt_from_result(request, &matches[0]))
    }

    fn verify(
        &mut self,
        request: &ExternalEffectRequest,
        receipt: &ExternalEffectReceipt,
    ) -> Result<ExternalEffectReceipt> {
        validate_external_effect_receipt(request, receipt)?;
        let viewed = self.view_exact_receipt(receipt)?;
        Ok(self.receipt_from_result(request, &viewed))
    }
}

fn reconcile_github_pr_with_api(
    worktree_path: &Path,
    transaction: &mut PublicationTransaction,
    api: &mut impl GithubApi,
) -> Result<GithubPrResult> {
    reconcile_github_pr_with_api_and_remote_check(
        worktree_path,
        transaction,
        api,
        require_remote_expected,
    )
}

fn reconcile_github_pr_with_api_and_remote_check(
    worktree_path: &Path,
    transaction: &mut PublicationTransaction,
    api: &mut impl GithubApi,
    mut remote_check: impl FnMut(&Path, &PublicationTransaction, &str) -> Result<()>,
) -> Result<GithubPrResult> {
    let github_repository = transaction
        .journal
        .github_repository
        .clone()
        .context("GitHub publication transaction omitted forge repository binding")?;
    remote_check(
        worktree_path,
        transaction,
        "before GitHub PR reconciliation",
    )?;

    if transaction.journal.pr_url.is_some() {
        let selector = transaction
            .journal
            .pr_number
            .map(|number| number.to_string())
            .unwrap_or_else(|| transaction.journal.remote_branch.clone());
        if let Ok(receipt) = api.view(worktree_path, &selector, &github_repository) {
            return verify_github_receipt_with_remote_check(
                worktree_path,
                transaction,
                receipt,
                transaction.journal.created_by_transaction,
                transaction.journal.observed_existing_pr,
                &mut remote_check,
            );
        }
    }

    let existing = api.list(
        worktree_path,
        &transaction.journal.remote_branch,
        &github_repository,
    )?;
    if existing.len() > 1 {
        bail!(
            "multiple GitHub PRs exist for unique publication branch {}",
            transaction.journal.remote_branch
        );
    }
    if let Some(existing) = existing.into_iter().next() {
        if !transaction.journal.create_attempted {
            bail!(
                "a GitHub PR already exists for the publication branch before this transaction attempted creation; refusing front-run reconciliation"
            );
        }
        let selector = existing.number.to_string();
        let receipt = api.view(worktree_path, &selector, &github_repository)?;
        return verify_github_receipt_with_remote_check(
            worktree_path,
            transaction,
            receipt,
            true,
            false,
            &mut remote_check,
        );
    }

    remote_check(
        worktree_path,
        transaction,
        "immediately before gh pr create",
    )?;
    transaction.journal.create_attempted = true;
    transaction.persist()?;
    let title = transaction
        .journal
        .expected_pr_title
        .as_deref()
        .context("GitHub publication transaction omitted its bound title")?;
    let body = transaction
        .journal
        .expected_pr_body
        .as_deref()
        .context("GitHub publication transaction omitted its marker-bound body")?;
    let create = api.create(
        worktree_path,
        &transaction.journal.remote_branch,
        &transaction.journal.base,
        title,
        body,
        transaction.journal.draft,
        &github_repository,
    )?;
    let hinted_url = first_non_empty_line(&String::from_utf8_lossy(&create.stdout));

    let receipt = if hinted_url.is_some() {
        api.view(
            worktree_path,
            &transaction.journal.remote_branch,
            &github_repository,
        )
        .ok()
    } else {
        None
    };
    let receipt = match receipt {
        Some(receipt) => receipt,
        None => {
            let recovered = api.list(
                worktree_path,
                &transaction.journal.remote_branch,
                &github_repository,
            )?;
            if recovered.len() > 1 {
                bail!("gh pr create outcome is ambiguous: multiple matching PRs were observed");
            }
            let Some(recovered) = recovered.into_iter().next() else {
                let stderr = String::from_utf8_lossy(&create.stderr).trim().to_string();
                bail!(
                    "gh pr create outcome could not be reconciled: {}",
                    if stderr.is_empty() {
                        "no PR receipt was returned or discovered"
                    } else {
                        &stderr
                    }
                );
            };
            let selector = recovered.number.to_string();
            api.view(worktree_path, &selector, &github_repository)?
        }
    };
    verify_github_receipt_with_remote_check(
        worktree_path,
        transaction,
        receipt,
        true,
        false,
        &mut remote_check,
    )
}

fn verify_github_receipt_with_remote_check(
    worktree_path: &Path,
    transaction: &mut PublicationTransaction,
    receipt: GithubPrResult,
    created_by_transaction: bool,
    observed_existing_pr: bool,
    mut remote_check: impl FnMut(&Path, &PublicationTransaction, &str) -> Result<()>,
) -> Result<GithubPrResult> {
    validate_github_receipt_contract(&receipt, &transaction.journal)?;
    remote_check(worktree_path, transaction, "after GitHub PR creation")?;
    let previous = transaction.journal.clone();
    transaction.journal.pr_url = Some(receipt.url.clone());
    transaction.journal.pr_head_oid = Some(receipt.head_oid.clone());
    transaction.journal.pr_base = Some(receipt.base_ref_name.clone());
    transaction.journal.pr_state = Some(receipt.state.clone());
    transaction.journal.pr_is_draft = Some(receipt.is_draft);
    transaction.journal.pr_number = Some(receipt.number);
    transaction.journal.pr_title = Some(receipt.title.clone());
    transaction.journal.pr_body = Some(receipt.body.clone());
    transaction.journal.pr_head_ref_name = Some(receipt.head_ref_name.clone());
    transaction.journal.pr_head_repository_owner = Some(receipt.head_repository_owner.clone());
    transaction.journal.pr_head_repository_name = Some(receipt.head_repository_name.clone());
    transaction.journal.pr_is_cross_repository = Some(receipt.is_cross_repository);
    transaction.journal.pr_author = Some(receipt.author.clone());
    transaction.journal.created_by_transaction =
        transaction.journal.created_by_transaction || created_by_transaction;
    transaction.journal.observed_existing_pr = !transaction.journal.created_by_transaction
        && (transaction.journal.observed_existing_pr || observed_existing_pr);
    transaction.advance_phase(PublicationTransactionPhase::PrObserved);
    transaction.persist_if_changed(&previous)?;
    Ok(GithubPrResult {
        url: receipt.url,
        head_oid: receipt.head_oid,
        base_oid: receipt.base_oid,
        number: receipt.number,
        base_ref_name: receipt.base_ref_name,
        state: receipt.state,
        is_draft: receipt.is_draft,
        title: receipt.title,
        body: receipt.body,
        head_ref_name: receipt.head_ref_name,
        head_repository_owner: receipt.head_repository_owner,
        head_repository_name: receipt.head_repository_name,
        is_cross_repository: receipt.is_cross_repository,
        author: receipt.author,
        created: transaction.journal.created_by_transaction,
    })
}

fn validate_github_receipt_contract(
    receipt: &GithubPrResult,
    journal: &PublicationTransactionJournal,
) -> Result<()> {
    let github_repository = journal
        .github_repository
        .as_ref()
        .context("GitHub PR journal omitted forge repository binding")?;
    validate_github_receipt_url(&receipt.url, github_repository, receipt.number)?;
    if receipt.head_oid != journal.expected_oid {
        bail!(
            "GitHub PR receipt headRefOid {} does not match reviewed OID {}",
            receipt.head_oid,
            journal.expected_oid
        );
    }
    let expected_base_oid = journal
        .expected_base_oid
        .as_deref()
        .context("GitHub publication journal omitted exact base OID")?;
    if receipt.base_oid != expected_base_oid {
        bail!(
            "GitHub PR receipt baseRefOid {} does not match reviewed base OID {}",
            receipt.base_oid,
            expected_base_oid
        );
    }
    if receipt.base_ref_name != journal.base {
        bail!(
            "GitHub PR receipt baseRefName {} does not match requested base {}",
            receipt.base_ref_name,
            journal.base
        );
    }
    let expected_title = journal
        .expected_pr_title
        .as_deref()
        .context("GitHub publication journal omitted its exact PR title")?;
    let expected_body = journal
        .expected_pr_body
        .as_deref()
        .context("GitHub publication journal omitted its marker-bound PR body")?;
    let expected_author = journal
        .expected_pr_author
        .as_deref()
        .context("GitHub publication journal omitted its explicit expected author")?;
    if receipt.title != expected_title || receipt.body != expected_body {
        bail!("GitHub PR receipt title/body did not match the marker-bound transaction content");
    }
    if receipt.head_ref_name != journal.remote_branch {
        bail!("GitHub PR receipt headRefName did not match the unique publication branch");
    }
    if receipt.head_repository_owner != github_repository.owner
        || receipt.head_repository_name != github_repository.name
        || receipt.is_cross_repository
    {
        bail!(
            "GitHub PR receipt head repository provenance did not match the bound same-repository publication"
        );
    }
    if receipt.author != expected_author {
        bail!("GitHub PR receipt author did not match the explicit expected author");
    }
    if receipt.is_draft != journal.draft {
        bail!(
            "GitHub PR receipt draft state {} does not match requested draft state {}",
            receipt.is_draft,
            journal.draft
        );
    }
    if receipt.state != "OPEN" {
        bail!(
            "GitHub PR receipt state {} is not OPEN; the existing receipt is recorded but is not review-ready",
            receipt.state
        );
    }
    Ok(())
}

fn require_remote_expected(
    worktree_path: &Path,
    transaction: &PublicationTransaction,
    stage: &str,
) -> Result<()> {
    let observed = observe_remote_ref(
        worktree_path,
        &transaction.remote_url,
        &transaction.journal.remote_ref,
    )?;
    if observed.as_deref() != Some(transaction.journal.expected_oid.as_str()) {
        bail!(
            "publication remote ref {} changed {stage}: observed {:?}, expected {}",
            transaction.journal.remote_ref,
            observed,
            transaction.journal.expected_oid
        );
    }
    require_remote_expected_base_with_context(worktree_path, transaction, stage)?;
    Ok(())
}

fn require_remote_expected_base(
    worktree_path: &Path,
    transaction: &PublicationTransaction,
    stage: &str,
) -> Result<()> {
    require_remote_expected_base_with_context(worktree_path, transaction, stage)
}

fn require_remote_expected_base_with_context(
    worktree_path: &Path,
    transaction: &PublicationTransaction,
    stage: &str,
) -> Result<()> {
    let expected_base_oid = transaction
        .journal
        .expected_base_oid
        .as_deref()
        .context("GitHub publication journal omitted exact base OID")?;
    let base_ref = format!("refs/heads/{}", transaction.journal.base);
    let observed_base = observe_remote_ref(worktree_path, &transaction.remote_url, &base_ref)?;
    if observed_base.as_deref() != Some(expected_base_oid) {
        bail!(
            "publication base ref {} changed {stage}: observed {:?}, expected {}",
            base_ref,
            observed_base,
            expected_base_oid
        );
    }
    Ok(())
}

impl GhCommandContext {
    fn create(worktree_path: &Path, repository: &GithubRepositoryIdentity) -> Result<Self> {
        Self::create_with_token_source(worktree_path, repository, |key| env::var(key).ok())
    }

    fn create_with_token_source(
        worktree_path: &Path,
        repository: &GithubRepositoryIdentity,
        mut value_for: impl FnMut(&str) -> Option<String>,
    ) -> Result<Self> {
        let mut runtime_directory = merge::PrivateRuntimeDirectory::create(
            worktree_path,
            merge::PrivateRuntimeKind::GhConfig,
        )?;
        let directory = runtime_directory.path().to_path_buf();
        let result = (|| -> Result<GhCommandContextSetup> {
            let source = Repository::discover(worktree_path).with_context(|| {
                format!(
                    "failed to discover gh source repository from {}",
                    worktree_path.display()
                )
            })?;
            let token = select_network_token_with(&repository.host, &mut value_for)?;
            let hosts_path = directory.join("hosts.yml");
            let escaped_token = ZeroizingString(token.as_str()?.replace('\'', "''"));
            let hosts = ZeroizingString(format!(
                "'{}':\n    oauth_token: '{}'\n    git_protocol: https\n",
                repository.host,
                escaped_token.as_str()
            ));
            merge::write_private_file(&hosts_path, hosts.as_bytes())?;
            let config_files = vec![capture_private_config_file(&hosts_path)?];

            let common_state =
                fs::canonicalize(merge::ensure_repo_common_state_directory(&source)?)
                    .context("failed to resolve gh repository state directory")?;
            let common_directory = fs::canonicalize(source.commondir())
                .context("failed to resolve gh common Git directory")?;
            let primary_worktree = common_directory
                .parent()
                .context("gh common Git directory omitted its repository root")?
                .to_path_buf();
            let source_worktree = source
                .workdir()
                .map(fs::canonicalize)
                .transpose()
                .context("failed to resolve gh source worktree")?
                .unwrap_or_else(|| common_directory.clone());

            let mut environment = merge::minimal_network_environment()?;
            for key in [
                "GIT_CONFIG_NOSYSTEM",
                "GIT_ATTR_NOSYSTEM",
                "GIT_OPTIONAL_LOCKS",
                "GIT_TERMINAL_PROMPT",
            ] {
                environment.remove(key);
            }
            environment.insert(
                "GH_CONFIG_DIR".to_string(),
                directory
                    .to_str()
                    .context("private gh config path was not UTF-8")?
                    .to_string(),
            );
            environment.insert("GH_PROMPT_DISABLED".to_string(), "1".to_string());
            validate_gh_environment(&environment, &directory)?;
            let profile = TrustedFixedNetworkProfile::read_write(&directory)
                .with_resource_limits(Default::default())
                .with_visible_read_only_file(&hosts_path)
                .with_hidden_root(&primary_worktree)
                .with_hidden_root(&source_worktree)
                .with_hidden_root(&common_state);
            Ok((environment, profile, config_files, token))
        })();
        match result {
            Ok((environment, profile, config_files, token)) => Ok(Self {
                runtime_directory,
                environment,
                profile,
                config_files,
                repository: repository.clone(),
                token,
            }),
            Err(error) => {
                let erase = erase_private_config_paths_if_present(&[directory.join("hosts.yml")]);
                let close = runtime_directory.close();
                match (erase, close) {
                    (Ok(()), Ok(())) => Err(error),
                    (erase, close) => Err(anyhow::anyhow!(
                        "{error:#}; gh setup cleanup failed: erase={:?}, close={:?}",
                        erase.err().map(|error| format!("{error:#}")),
                        close.err().map(|error| format!("{error:#}")),
                    )),
                }
            }
        }
    }

    fn run(
        mut self,
        label: &str,
        args: Vec<OsString>,
        stdin: StdinMode,
    ) -> Result<merge::RequiredCommandOutput> {
        let execution = self.run_inner(label, args, stdin);
        let cleanup = self.close();
        match (execution, cleanup) {
            (Ok(output), Ok(())) => Ok(output),
            (Err(error), Ok(())) => Err(error),
            (Ok(_), Err(cleanup)) => {
                Err(cleanup
                    .context("gh command completed but private token runtime cleanup failed"))
            }
            (Err(error), Err(cleanup)) => Err(anyhow::anyhow!(
                "{error:#}; gh private token runtime cleanup also failed: {cleanup:#}"
            )),
        }
    }

    fn run_inner(
        &self,
        label: &str,
        args: Vec<OsString>,
        stdin: StdinMode,
    ) -> Result<merge::RequiredCommandOutput> {
        self.runtime_directory
            .verify_identity()
            .context("private gh runtime changed before command execution")?;
        verify_private_config_files(&self.config_files)?;
        validate_gh_environment(&self.environment, self.runtime_directory.path())?;
        validate_gh_operation(&args, &stdin, &self.repository)?;
        let output = merge::run_required_network_direct(
            label,
            merge::resolve_trusted_executable("gh")?,
            args,
            self.runtime_directory.path(),
            self.environment.clone(),
            stdin,
            merge::NETWORK_PROCESS_TIMEOUT,
            GH_CAPTURE_LIMIT_BYTES,
            GH_STDIN_LIMIT_BYTES,
            self.profile.clone(),
        )
        .map_err(|error| {
            let mut message = format!("{error:#}");
            for private in [self.token.as_str(), self.token.basic_str()]
                .into_iter()
                .flatten()
            {
                message = message.replace(private, "<redacted:network-token>");
            }
            anyhow::anyhow!(message)
        })?;
        self.runtime_directory
            .verify_identity()
            .context("private gh runtime changed during command execution")?;
        verify_private_config_files(&self.config_files)?;
        let mut output = output;
        redact_private_bytes(&mut output.stdout, &self.token.bytes);
        redact_private_bytes(&mut output.stderr, &self.token.bytes);
        redact_private_bytes(&mut output.stdout, &self.token.basic);
        redact_private_bytes(&mut output.stderr, &self.token.basic);
        Ok(output)
    }

    fn close(&mut self) -> Result<()> {
        let erase = erase_private_config_files(&mut self.config_files);
        self.environment.clear();
        self.token.zeroize();
        let close = self.runtime_directory.close();
        match (erase, close) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
            (Err(erase), Err(close)) => Err(anyhow::anyhow!(
                "gh private config erasure failed: {erase:#}; private runtime close failed: {close:#}"
            )),
        }
    }
}

fn validate_gh_environment(
    environment: &BTreeMap<String, String>,
    config_directory: &Path,
) -> Result<()> {
    let expected_directory = config_directory
        .to_str()
        .context("private gh config directory was not UTF-8")?;
    if environment.get("GH_CONFIG_DIR").map(String::as_str) != Some(expected_directory)
        || environment.get("GH_PROMPT_DISABLED").map(String::as_str) != Some("1")
    {
        bail!("gh environment omitted its exact private config and prompt bindings");
    }
    if environment.keys().any(|key| {
        key.starts_with("GIT_")
            || matches!(
                key.as_str(),
                "GH_TOKEN" | "GITHUB_TOKEN" | "GH_ENTERPRISE_TOKEN" | "GITHUB_ENTERPRISE_TOKEN"
            )
    }) {
        bail!("gh environment contains ambient Git or token inputs");
    }
    Ok(())
}

fn validate_gh_operation(
    args: &[OsString],
    stdin: &StdinMode,
    repository: &GithubRepositoryIdentity,
) -> Result<()> {
    let args = args
        .iter()
        .map(|argument| {
            argument
                .to_str()
                .context("gh command argument was not strict UTF-8")
        })
        .collect::<Result<Vec<_>>>()?;
    let selector = repository.selector();
    let receipt_fields = GITHUB_PR_RECEIPT_FIELDS;
    match args.as_slice() {
        ["issue", "view", number, "--repo", bound, "--json", fields]
            if *bound == selector
                && *fields == GITHUB_ISSUE_SOURCE_FIELDS
                && matches!(stdin, StdinMode::Null) =>
        {
            validate_gh_positive_number(number, "issue source number")
        }
        ["issue", "view", number, "--repo", bound, "--json", fields]
            if *bound == selector
                && *fields == GITHUB_ISSUE_EFFECT_FIELDS
                && matches!(stdin, StdinMode::Null) =>
        {
            validate_gh_positive_number(number, "issue effect number")
        }
        ["issue", "list", "--repo", bound, "--state", "open", "--json", fields, "--limit", limit, labels @ ..]
            if *bound == selector
                && *fields == GITHUB_ISSUE_SOURCE_FIELDS
                && matches!(stdin, StdinMode::Null) =>
        {
            validate_github_source_list_tail(limit, labels)
        }
        ["issue", "list", "--repo", bound, "--state", "all", "--search", marker, "--limit", limit, "--json", fields]
            if *bound == selector
                && *limit == GITHUB_ISSUE_EFFECT_LOOKUP_LIMIT
                && *fields == GITHUB_ISSUE_EFFECT_FIELDS
                && matches!(stdin, StdinMode::Null) =>
        {
            validate_external_effect_marker_argument(marker)
        }
        ["pr", "view", number, "--repo", bound, "--json", fields]
            if *bound == selector
                && *fields == GITHUB_PR_SOURCE_FIELDS
                && matches!(stdin, StdinMode::Null) =>
        {
            validate_gh_positive_number(number, "pull-request source number")
        }
        ["pr", "list", "--repo", bound, "--state", "open", "--json", fields, "--limit", limit, labels @ ..]
            if *bound == selector
                && *fields == GITHUB_PR_SOURCE_FIELDS
                && matches!(stdin, StdinMode::Null) =>
        {
            validate_github_source_list_tail(limit, labels)
        }
        ["pr", "list", "--repo", bound, "--head", branch, "--state", "all", "--limit", limit, "--json", fields]
            if *bound == selector
                && *limit == GITHUB_PR_EFFECT_LOOKUP_LIMIT
                && *fields == receipt_fields
                && matches!(stdin, StdinMode::Null) =>
        {
            validate_gh_argument_value(branch, "PR branch")
        }
        ["pr", "view", view, "--repo", bound, "--json", fields]
            if *bound == selector
                && *fields == receipt_fields
                && matches!(stdin, StdinMode::Null) =>
        {
            validate_gh_argument_value(view, "PR selector")
        }
        ["pr", "create", "--repo", bound, "--base", base, "--head", branch, "--title", title, "--body-file", "-"]
        | ["pr", "create", "--repo", bound, "--base", base, "--head", branch, "--title", title, "--body-file", "-", "--draft"]
            if *bound == selector && matches!(stdin, StdinMode::Bytes(_)) =>
        {
            validate_gh_argument_value(base, "PR base")?;
            validate_gh_argument_value(branch, "PR branch")?;
            validate_gh_argument_value(title, "PR title")
        }
        ["issue", "create", "--repo", bound, "--title", title, "--body-file", "-", labels @ ..]
            if *bound == selector && matches!(stdin, StdinMode::Bytes(_)) =>
        {
            validate_gh_argument_value(title, "issue title")?;
            if labels.len() % 2 != 0 {
                bail!("gh issue label arguments were not paired");
            }
            for pair in labels.chunks_exact(2) {
                if pair[0] != "--label" {
                    bail!("gh issue command contains an unapproved option");
                }
                validate_gh_argument_value(pair[1], "issue label")?;
            }
            Ok(())
        }
        [subcommand @ ("issue" | "pr"), "comment", number, "--repo", bound, "--body-file", "-"]
            if *bound == selector && matches!(stdin, StdinMode::Bytes(_)) =>
        {
            let _ = subcommand;
            validate_gh_positive_number(number, "comment source number")
        }
        ["api", "--method", "GET", endpoint] if matches!(stdin, StdinMode::Null) => {
            validate_github_comment_api_endpoint(endpoint, repository)
        }
        ["api", "--method", "GET", "--paginate", "--slurp", endpoint]
            if matches!(stdin, StdinMode::Null) =>
        {
            validate_github_comment_list_api_endpoint(endpoint, repository)
        }
        _ => bail!("gh command is outside the fixed PR/issue allowlist"),
    }
}

fn validate_github_source_list_tail(limit: &str, labels: &[&str]) -> Result<()> {
    let parsed_limit = limit
        .parse::<usize>()
        .ok()
        .filter(|limit| (1..=MAX_GITHUB_SOURCE_LIST_ITEMS).contains(limit))
        .context("GitHub source list limit was not canonical and bounded")?;
    if parsed_limit.to_string() != limit {
        bail!("GitHub source list limit was not canonical");
    }
    if !labels.len().is_multiple_of(2) || labels.len() / 2 > MAX_GITHUB_SOURCE_LIST_LABELS {
        bail!("GitHub source list labels were malformed or excessive");
    }
    for pair in labels.chunks_exact(2) {
        if pair[0] != "--label" {
            bail!("GitHub source list contains an unapproved option");
        }
        validate_gh_argument_value(pair[1], "GitHub source list label")?;
        if pair[1].len() > MAX_GITHUB_SLUG_BYTES {
            bail!("GitHub source list label exceeded its bound");
        }
    }
    Ok(())
}

fn validate_gh_positive_number(value: &str, label: &str) -> Result<()> {
    if value.len() > 20 || value.parse::<u64>().is_err() || value == "0" {
        bail!("{label} is not a canonical positive integer");
    }
    Ok(())
}

fn validate_gh_argument_value(value: &str, label: &str) -> Result<()> {
    if value.is_empty()
        || value.starts_with('-')
        || value.len() > 64 * 1024
        || value.as_bytes().iter().any(|byte| byte.is_ascii_control())
    {
        bail!("{label} is empty, malformed, or oversized");
    }
    Ok(())
}

fn validate_external_effect_marker_argument(value: &str) -> Result<()> {
    let effect_id = value
        .strip_prefix(&format!("<!-- {EXTERNAL_EFFECT_MARKER_PREFIX}:v2:"))
        .and_then(|value| value.strip_suffix(" -->"))
        .context("GitHub effect lookup marker was malformed")?;
    validate_external_digest(effect_id, "GitHub effect lookup marker id")
}

fn validate_github_comment_api_endpoint(
    endpoint: &str,
    repository: &GithubRepositoryIdentity,
) -> Result<()> {
    let prefix = format!(
        "repos/{}/{}/issues/comments/",
        repository.owner, repository.name
    );
    let id = endpoint
        .strip_prefix(&prefix)
        .context("GitHub comment API endpoint did not match the bound repository")?;
    validate_gh_positive_number(id, "comment API id")?;
    if endpoint != format!("{prefix}{id}") {
        bail!("GitHub comment API endpoint was not canonical");
    }
    Ok(())
}

fn validate_github_comment_list_api_endpoint(
    endpoint: &str,
    repository: &GithubRepositoryIdentity,
) -> Result<()> {
    let prefix = format!("repos/{}/{}/issues/", repository.owner, repository.name);
    let number = endpoint
        .strip_prefix(&prefix)
        .and_then(|value| value.strip_suffix("/comments?per_page=100"))
        .context("GitHub comment list API endpoint did not match the bound repository")?;
    validate_gh_positive_number(number, "comment list source number")?;
    if endpoint != format!("{prefix}{number}/comments?per_page=100") {
        bail!("GitHub comment list API endpoint was not canonical");
    }
    Ok(())
}

impl Drop for GhCommandContext {
    fn drop(&mut self) {
        self.environment.clear();
    }
}

fn cli_github_source_view(
    worktree_path: &Path,
    number: u64,
    kind: ExternalSourceObjectKind,
    repository: &GithubRepositoryIdentity,
) -> Result<serde_json::Value> {
    if number == 0 {
        bail!("GitHub source number must be positive");
    }
    let (subcommand, fields) = match kind {
        ExternalSourceObjectKind::Issue => ("issue", GITHUB_ISSUE_SOURCE_FIELDS),
        ExternalSourceObjectKind::PullRequest => ("pr", GITHUB_PR_SOURCE_FIELDS),
    };
    let context = GhCommandContext::create(worktree_path, repository)?;
    let output = context.run(
        "gh exact source view",
        [
            subcommand,
            "view",
            &number.to_string(),
            "--repo",
            &repository.selector(),
            "--json",
            fields,
        ]
        .into_iter()
        .map(OsString::from)
        .collect(),
        StdinMode::Null,
    )?;
    let stdout = required_command_stdout(output, "gh exact source view")?;
    let value: serde_json::Value =
        serde_json::from_str(&stdout).context("gh exact source view did not return valid JSON")?;
    if serde_json::to_vec(&value)?.len() > MAX_EXTERNAL_SOURCE_SERIALIZED_BYTES {
        bail!("gh exact source view exceeded its JSON byte limit");
    }
    Ok(value)
}

fn github_source_list_args(
    repository: &GithubRepositoryIdentity,
    kind: ExternalSourceObjectKind,
    max_items: usize,
    labels: &[String],
) -> Result<Vec<OsString>> {
    if !(1..=MAX_GITHUB_SOURCE_LIST_ITEMS).contains(&max_items)
        || labels.len() > MAX_GITHUB_SOURCE_LIST_LABELS
    {
        bail!("GitHub source list request exceeded its item or label bound");
    }
    let (subcommand, fields) = match kind {
        ExternalSourceObjectKind::Issue => ("issue", GITHUB_ISSUE_SOURCE_FIELDS),
        ExternalSourceObjectKind::PullRequest => ("pr", GITHUB_PR_SOURCE_FIELDS),
    };
    let selector = repository.selector();
    let limit = max_items.to_string();
    let mut args = [
        subcommand, "list", "--repo", &selector, "--state", "open", "--json", fields, "--limit",
        &limit,
    ]
    .into_iter()
    .map(OsString::from)
    .collect::<Vec<_>>();
    for label in labels {
        validate_gh_argument_value(label, "GitHub source list label")?;
        if label.len() > MAX_GITHUB_SLUG_BYTES {
            bail!("GitHub source list label exceeded its bound");
        }
        args.push(OsString::from("--label"));
        args.push(OsString::from(label));
    }
    validate_gh_operation(&args, &StdinMode::Null, repository)?;
    Ok(args)
}

pub(crate) fn list_github_source_items(
    repo: &Path,
    repository_selector: &str,
    kind: ExternalSourceObjectKind,
    max_items: usize,
    labels: &[String],
) -> Result<serde_json::Value> {
    let repository = github_repository_identity_from_selector(repository_selector)?;
    let args = github_source_list_args(&repository, kind, max_items, labels)?;
    let context = GhCommandContext::create(repo, &repository)?;
    let output = context.run("gh exact source list", args, StdinMode::Null)?;
    let stdout = required_command_stdout(output, "gh exact source list")?;
    if stdout.len() > MAX_EXTERNAL_SOURCE_SERIALIZED_BYTES {
        bail!("gh exact source list exceeded its JSON byte limit");
    }
    let value: serde_json::Value =
        serde_json::from_str(&stdout).context("gh exact source list did not return valid JSON")?;
    let values = value
        .as_array()
        .context("gh exact source list did not return a JSON array")?;
    if values.len() > max_items {
        bail!("gh exact source list returned more items than requested");
    }
    Ok(value)
}

fn cli_github_pr_list(
    worktree_path: &Path,
    branch: &str,
    repository: &GithubRepositoryIdentity,
) -> Result<Vec<GithubPrResult>> {
    let context = GhCommandContext::create(worktree_path, repository)?;
    let output = context.run(
        "gh pr list",
        [
            "pr",
            "list",
            "--repo",
            &repository.selector(),
            "--head",
            branch,
            "--state",
            "all",
            "--limit",
            GITHUB_PR_EFFECT_LOOKUP_LIMIT,
            "--json",
            GITHUB_PR_RECEIPT_FIELDS,
        ]
        .into_iter()
        .map(OsString::from)
        .collect(),
        StdinMode::Null,
    )?;
    let stdout = required_command_stdout(output, "gh pr list")?;
    let value: serde_json::Value =
        serde_json::from_str(&stdout).context("gh pr list did not return valid JSON")?;
    github_pr_list_from_json(&value)
}

fn github_pr_list_from_json(value: &serde_json::Value) -> Result<Vec<GithubPrResult>> {
    let receipts = value
        .as_array()
        .context("gh pr list JSON was not an array")?;
    if receipts.len() > MAX_GITHUB_PR_LIST_RECEIPTS {
        bail!("gh pr list returned too many receipts");
    }
    receipts.iter().map(github_pr_receipt_from_json).collect()
}

fn cli_github_pr_view(
    worktree_path: &Path,
    selector: &str,
    repository: &GithubRepositoryIdentity,
) -> Result<GithubPrResult> {
    let context = GhCommandContext::create(worktree_path, repository)?;
    let output = context.run(
        "gh pr view",
        [
            "pr",
            "view",
            selector,
            "--repo",
            &repository.selector(),
            "--json",
            GITHUB_PR_RECEIPT_FIELDS,
        ]
        .into_iter()
        .map(OsString::from)
        .collect(),
        StdinMode::Null,
    )?;
    let stdout = required_command_stdout(output, "gh pr view")?;
    let value: serde_json::Value =
        serde_json::from_str(&stdout).context("gh pr view did not return valid JSON")?;
    github_pr_receipt_from_json(&value)
}

fn github_pr_receipt_from_json(value: &serde_json::Value) -> Result<GithubPrResult> {
    let url = value
        .get("url")
        .and_then(serde_json::Value::as_str)
        .context("GitHub PR receipt omitted url")?;
    validate_github_receipt_url_text(url)?;
    let head_oid = value
        .get("headRefOid")
        .and_then(serde_json::Value::as_str)
        .context("GitHub PR receipt omitted headRefOid")?;
    let parsed_head =
        Oid::from_str(head_oid).context("GitHub PR receipt headRefOid was invalid")?;
    if parsed_head.to_string() != head_oid {
        bail!("GitHub PR receipt headRefOid was not canonical lowercase hexadecimal");
    }
    let head_oid = parsed_head.to_string();
    let base_oid = value
        .get("baseRefOid")
        .and_then(serde_json::Value::as_str)
        .context("GitHub PR receipt omitted baseRefOid")?;
    let parsed_base =
        Oid::from_str(base_oid).context("GitHub PR receipt baseRefOid was invalid")?;
    if parsed_base.to_string() != base_oid {
        bail!("GitHub PR receipt baseRefOid was not canonical lowercase hexadecimal");
    }
    let base_oid = parsed_base.to_string();
    let number = value
        .get("number")
        .and_then(serde_json::Value::as_u64)
        .context("GitHub PR receipt omitted number")?;
    if number == 0 {
        bail!("GitHub PR receipt number was zero");
    }
    let base_ref_name = value
        .get("baseRefName")
        .and_then(serde_json::Value::as_str)
        .context("GitHub PR receipt omitted baseRefName")?;
    let state = value
        .get("state")
        .and_then(serde_json::Value::as_str)
        .context("GitHub PR receipt omitted state")?;
    for (label, text) in [("baseRefName", base_ref_name), ("state", state)] {
        if text.is_empty()
            || text.len() > MAX_GITHUB_RECEIPT_STRING_BYTES
            || text.as_bytes().iter().any(|byte| byte.is_ascii_control())
        {
            bail!("GitHub PR receipt {label} was empty, malformed, or oversized");
        }
    }
    let is_draft = value
        .get("isDraft")
        .and_then(serde_json::Value::as_bool)
        .context("GitHub PR receipt omitted isDraft")?;
    let title = value
        .get("title")
        .and_then(serde_json::Value::as_str)
        .context("GitHub PR receipt omitted title")?;
    let body = value
        .get("body")
        .and_then(serde_json::Value::as_str)
        .context("GitHub PR receipt omitted body")?;
    let head_ref_name = value
        .get("headRefName")
        .and_then(serde_json::Value::as_str)
        .context("GitHub PR receipt omitted headRefName")?;
    for (label, text, limit) in [
        ("title", title, MAX_GITHUB_RECEIPT_STRING_BYTES),
        ("body", body, MAX_GITHUB_RECEIPT_BODY_BYTES),
        ("headRefName", head_ref_name, MAX_PUBLICATION_REF_BYTES),
    ] {
        if text.is_empty() || text.len() > limit || text.as_bytes().contains(&0) {
            bail!("GitHub PR receipt {label} was empty, malformed, or oversized");
        }
    }
    let head_repository = value
        .get("headRepository")
        .and_then(serde_json::Value::as_object)
        .context("GitHub PR receipt omitted headRepository")?;
    let head_repository_name = head_repository
        .get("name")
        .and_then(serde_json::Value::as_str)
        .context("GitHub PR receipt omitted headRepository.name")?;
    let head_repository_owner = value
        .get("headRepositoryOwner")
        .and_then(serde_json::Value::as_object)
        .and_then(|owner| owner.get("login"))
        .and_then(serde_json::Value::as_str)
        .context("GitHub PR receipt omitted headRepositoryOwner.login")?;
    validate_github_slug(head_repository_owner, "receipt head owner")?;
    validate_github_slug(head_repository_name, "receipt head repository")?;
    if let Some(name_with_owner) = head_repository
        .get("nameWithOwner")
        .and_then(serde_json::Value::as_str)
    {
        let expected = format!("{head_repository_owner}/{head_repository_name}");
        if !name_with_owner.eq_ignore_ascii_case(&expected) {
            bail!("GitHub PR receipt headRepository.nameWithOwner was inconsistent");
        }
    }
    let is_cross_repository = value
        .get("isCrossRepository")
        .and_then(serde_json::Value::as_bool)
        .context("GitHub PR receipt omitted isCrossRepository")?;
    let author = value
        .get("author")
        .and_then(serde_json::Value::as_object)
        .and_then(|author| author.get("login"))
        .and_then(serde_json::Value::as_str)
        .context("GitHub PR receipt omitted author.login")?;
    let author =
        canonical_github_author_login(author).context("GitHub PR receipt author was malformed")?;
    Ok(GithubPrResult {
        url: url.to_string(),
        head_oid,
        base_oid,
        number,
        base_ref_name: base_ref_name.to_string(),
        state: state.to_string(),
        is_draft,
        title: title.to_string(),
        body: body.to_string(),
        head_ref_name: head_ref_name.to_string(),
        head_repository_owner: head_repository_owner.to_ascii_lowercase(),
        head_repository_name: head_repository_name.to_ascii_lowercase(),
        is_cross_repository,
        author,
        created: false,
    })
}

fn cli_github_pr_create(
    worktree_path: &Path,
    branch: &str,
    base: &str,
    title: &str,
    body: &str,
    draft: bool,
    repository: &GithubRepositoryIdentity,
) -> Result<GithubCreateOutput> {
    let context = GhCommandContext::create(worktree_path, repository)?;
    let mut args = [
        "pr",
        "create",
        "--repo",
        &repository.selector(),
        "--base",
        base,
        "--head",
        branch,
        "--title",
        title,
        "--body-file",
        "-",
    ]
    .into_iter()
    .map(OsString::from)
    .collect::<Vec<_>>();
    if draft {
        args.push(OsString::from("--draft"));
    }
    let output = context.run(
        "gh pr create",
        args,
        StdinMode::Bytes(body.as_bytes().to_vec()),
    )?;
    Ok(GithubCreateOutput {
        stdout: output.stdout,
        stderr: output.stderr,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GithubIssueEffectObserved {
    number: u64,
    url: String,
    title: String,
    body: String,
    labels: Vec<String>,
    author: String,
    state: String,
}

struct GithubIssueExternalEffectProvider<'a> {
    worktree_path: &'a Path,
    repository: &'a GithubRepositoryIdentity,
    title: &'a str,
    marked_body: String,
    labels: &'a [String],
    expected_author: &'a str,
}

impl GithubIssueExternalEffectProvider<'_> {
    fn exact_candidates(
        &self,
        request: &ExternalEffectRequest,
    ) -> Result<Vec<GithubIssueEffectObserved>> {
        let candidates =
            cli_github_issue_effect_list(self.worktree_path, &request.marker, self.repository)?;
        let mut exact = Vec::new();
        for candidate in candidates {
            let viewed = cli_github_issue_effect_view(
                self.worktree_path,
                candidate.number,
                self.repository,
            )?;
            if self.matches_contract(&viewed)? {
                exact.push(viewed);
            }
        }
        exact.sort_by_key(|candidate| candidate.number);
        exact.dedup_by_key(|candidate| candidate.number);
        Ok(exact)
    }

    fn matches_contract(&self, observed: &GithubIssueEffectObserved) -> Result<bool> {
        validate_github_issue_receipt_url(&observed.url, self.repository, observed.number)?;
        Ok(observed.title == self.title
            && observed.body == self.marked_body
            && observed.labels == self.labels
            && observed.author == self.expected_author
            && observed.state == "OPEN")
    }

    fn receipt(
        &self,
        request: &ExternalEffectRequest,
        observed: &GithubIssueEffectObserved,
    ) -> ExternalEffectReceipt {
        ExternalEffectReceipt {
            version: EXTERNAL_EFFECT_VERSION,
            transport_provider: request.transport_provider.clone(),
            repository_identity: request.repository_identity.clone(),
            repository_selector: request.repository_selector.clone(),
            effect_id: request.effect_id.clone(),
            operation: request.operation,
            source_provenance_digest: request
                .source
                .as_ref()
                .map(|source| source.provenance_digest.clone()),
            provider_id: observed.number.to_string(),
            url: observed.url.clone(),
            repository: request.repository_selector.clone(),
            marker: request.marker.clone(),
            target: request.target.clone(),
            payload: request.payload.clone(),
            target_digest: request.target_digest.clone(),
            payload_digest: request.payload_digest.clone(),
        }
    }
}

impl ExternalEffectProvider for GithubIssueExternalEffectProvider<'_> {
    fn preflight_before_start(&mut self, _request: &ExternalEffectRequest) -> Result<()> {
        Ok(())
    }

    fn lookup(&mut self, request: &ExternalEffectRequest) -> Result<Vec<ExternalEffectReceipt>> {
        Ok(self
            .exact_candidates(request)?
            .iter()
            .map(|observed| self.receipt(request, observed))
            .collect())
    }

    fn invoke(&mut self, request: &ExternalEffectRequest) -> Result<ExternalEffectReceipt> {
        let context = GhCommandContext::create(self.worktree_path, self.repository)?;
        let mut args = [
            "issue",
            "create",
            "--repo",
            &self.repository.selector(),
            "--title",
            self.title,
            "--body-file",
            "-",
        ]
        .into_iter()
        .map(OsString::from)
        .collect::<Vec<_>>();
        for label in self.labels {
            args.push(OsString::from("--label"));
            args.push(OsString::from(label));
        }
        context.run(
            "gh issue create",
            args,
            StdinMode::Bytes(self.marked_body.as_bytes().to_vec()),
        )?;
        let matches = self.exact_candidates(request)?;
        if matches.len() != 1 {
            bail!("GitHub issue creation response could not be reconciled exactly");
        }
        Ok(self.receipt(request, &matches[0]))
    }

    fn verify(
        &mut self,
        request: &ExternalEffectRequest,
        receipt: &ExternalEffectReceipt,
    ) -> Result<ExternalEffectReceipt> {
        validate_external_effect_receipt(request, receipt)?;
        let number = receipt
            .provider_id
            .parse::<u64>()
            .ok()
            .filter(|number| *number > 0)
            .context("GitHub issue effect receipt number was malformed")?;
        let viewed = cli_github_issue_effect_view(self.worktree_path, number, self.repository)?;
        if !self.matches_contract(&viewed)? || viewed.url != receipt.url {
            bail!("GitHub issue effect receipt changed from its exact remote object");
        }
        Ok(self.receipt(request, &viewed))
    }
}

fn cli_github_issue_effect_list(
    worktree_path: &Path,
    marker: &str,
    repository: &GithubRepositoryIdentity,
) -> Result<Vec<GithubIssueEffectObserved>> {
    let context = GhCommandContext::create(worktree_path, repository)?;
    let output = context.run(
        "gh issue effect list",
        [
            "issue",
            "list",
            "--repo",
            &repository.selector(),
            "--state",
            "all",
            "--search",
            marker,
            "--limit",
            GITHUB_ISSUE_EFFECT_LOOKUP_LIMIT,
            "--json",
            GITHUB_ISSUE_EFFECT_FIELDS,
        ]
        .into_iter()
        .map(OsString::from)
        .collect(),
        StdinMode::Null,
    )?;
    let stdout = required_command_stdout(output, "gh issue effect list")?;
    let value: serde_json::Value =
        serde_json::from_str(&stdout).context("gh issue effect list did not return valid JSON")?;
    github_issue_effect_list_from_json(&value)
}

fn github_issue_effect_list_from_json(
    value: &serde_json::Value,
) -> Result<Vec<GithubIssueEffectObserved>> {
    let values = value
        .as_array()
        .context("gh issue effect list JSON was not an array")?;
    if values.len() > MAX_GITHUB_EFFECT_CANDIDATES {
        bail!("gh issue effect list returned too many candidates");
    }
    values.iter().map(github_issue_effect_from_json).collect()
}

fn cli_github_issue_effect_view(
    worktree_path: &Path,
    number: u64,
    repository: &GithubRepositoryIdentity,
) -> Result<GithubIssueEffectObserved> {
    if number == 0 {
        bail!("GitHub issue effect number must be positive");
    }
    let context = GhCommandContext::create(worktree_path, repository)?;
    let output = context.run(
        "gh issue effect view",
        [
            "issue",
            "view",
            &number.to_string(),
            "--repo",
            &repository.selector(),
            "--json",
            GITHUB_ISSUE_EFFECT_FIELDS,
        ]
        .into_iter()
        .map(OsString::from)
        .collect(),
        StdinMode::Null,
    )?;
    let stdout = required_command_stdout(output, "gh issue effect view")?;
    let value: serde_json::Value =
        serde_json::from_str(&stdout).context("gh issue effect view did not return valid JSON")?;
    github_issue_effect_from_json(&value)
}

fn github_issue_effect_from_json(value: &serde_json::Value) -> Result<GithubIssueEffectObserved> {
    let object = value
        .as_object()
        .context("GitHub issue effect receipt was not an object")?;
    let number = object
        .get("number")
        .and_then(serde_json::Value::as_u64)
        .filter(|number| *number > 0)
        .context("GitHub issue effect receipt omitted a positive number")?;
    let text = |field: &str, limit: usize| -> Result<String> {
        let value = object
            .get(field)
            .and_then(serde_json::Value::as_str)
            .with_context(|| format!("GitHub issue effect receipt omitted {field}"))?;
        if value.len() > limit || value.as_bytes().contains(&0) {
            bail!("GitHub issue effect receipt {field} was malformed or oversized");
        }
        Ok(value.to_string())
    };
    let url = text("url", MAX_GITHUB_RECEIPT_URL_BYTES)?;
    let title = text("title", MAX_GITHUB_RECEIPT_STRING_BYTES)?;
    let body = text("body", MAX_GITHUB_RECEIPT_BODY_BYTES)?;
    let state = text("state", MAX_GITHUB_RECEIPT_STRING_BYTES)?;
    let author = object
        .get("author")
        .and_then(serde_json::Value::as_object)
        .and_then(|author| author.get("login"))
        .and_then(serde_json::Value::as_str)
        .context("GitHub issue effect receipt omitted author.login")?;
    let author = canonical_github_author_login(author)?;
    let label_values = object
        .get("labels")
        .and_then(serde_json::Value::as_array)
        .context("GitHub issue effect receipt omitted labels")?;
    if label_values.len() > MAX_EXTERNAL_SOURCE_LABELS {
        bail!("GitHub issue effect receipt returned too many labels");
    }
    let mut labels = label_values
        .iter()
        .map(|label| {
            let name = label
                .as_object()
                .and_then(|label| label.get("name"))
                .and_then(serde_json::Value::as_str)
                .context("GitHub issue effect label omitted name")?;
            validate_gh_argument_value(name, "GitHub issue effect label")?;
            Ok(name.to_string())
        })
        .collect::<Result<Vec<_>>>()?;
    labels.sort();
    labels.dedup();
    Ok(GithubIssueEffectObserved {
        number,
        url,
        title,
        body,
        labels,
        author,
        state,
    })
}

fn external_effect_marked_body(body: &str, marker: &str) -> Result<String> {
    validate_external_effect_marker_argument(marker)?;
    if body.contains(EXTERNAL_EFFECT_MARKER_PREFIX) {
        bail!("external effect body already contains a reserved maco marker");
    }
    let marked = if body.is_empty() {
        marker.to_string()
    } else {
        format!("{body}\n\n{marker}")
    };
    if marked.len() > GH_STDIN_LIMIT_BYTES || marked.as_bytes().contains(&0) {
        bail!("external effect body was malformed or oversized");
    }
    Ok(marked)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GithubCommentEffectObserved {
    id: u64,
    url: String,
    body: String,
    author: String,
}

struct GithubCommentExternalEffectProvider<'a> {
    worktree_path: &'a Path,
    repository: &'a GithubRepositoryIdentity,
    source: &'a ExternalSourceGuard,
    marked_body: String,
    expected_author: &'a str,
}

impl GithubCommentExternalEffectProvider<'_> {
    fn revalidate_full(&self) -> Result<()> {
        revalidate_external_source(self.worktree_path, self.source)
    }

    fn revalidate_action_revision(&self) -> Result<()> {
        revalidate_external_source_action_revision(self.worktree_path, self.source)
    }

    fn exact_candidates(
        &self,
        request: &ExternalEffectRequest,
    ) -> Result<Vec<GithubCommentEffectObserved>> {
        self.revalidate_action_revision()?;
        let candidates =
            cli_github_comment_candidates(self.worktree_path, self.source, self.repository)?;
        let mut exact = Vec::new();
        for candidate in candidates
            .into_iter()
            .filter(|candidate| candidate.body.contains(&request.marker))
        {
            let viewed =
                cli_github_comment_exact_view(self.worktree_path, candidate.id, self.repository)?;
            validate_github_comment_contract(
                &viewed,
                self.repository,
                self.source,
                &self.marked_body,
                self.expected_author,
            )?;
            exact.push(viewed);
        }
        exact.sort_by_key(|comment| comment.id);
        exact.dedup_by_key(|comment| comment.id);
        Ok(exact)
    }

    fn receipt(
        &self,
        request: &ExternalEffectRequest,
        comment: &GithubCommentEffectObserved,
    ) -> ExternalEffectReceipt {
        ExternalEffectReceipt {
            version: EXTERNAL_EFFECT_VERSION,
            transport_provider: request.transport_provider.clone(),
            repository_identity: request.repository_identity.clone(),
            repository_selector: request.repository_selector.clone(),
            effect_id: request.effect_id.clone(),
            operation: request.operation,
            source_provenance_digest: request
                .source
                .as_ref()
                .map(|source| source.provenance_digest.clone()),
            provider_id: comment.id.to_string(),
            url: comment.url.clone(),
            repository: request.repository_selector.clone(),
            marker: request.marker.clone(),
            target: request.target.clone(),
            payload: request.payload.clone(),
            target_digest: request.target_digest.clone(),
            payload_digest: request.payload_digest.clone(),
        }
    }
}

impl ExternalEffectProvider for GithubCommentExternalEffectProvider<'_> {
    fn preflight_before_start(&mut self, _request: &ExternalEffectRequest) -> Result<()> {
        self.revalidate_full()
    }

    fn lookup(&mut self, request: &ExternalEffectRequest) -> Result<Vec<ExternalEffectReceipt>> {
        Ok(self
            .exact_candidates(request)?
            .iter()
            .map(|comment| self.receipt(request, comment))
            .collect())
    }

    fn invoke(&mut self, request: &ExternalEffectRequest) -> Result<ExternalEffectReceipt> {
        self.revalidate_full()?;
        let subcommand = match self.source.object_kind {
            ExternalSourceObjectKind::Issue => "issue",
            ExternalSourceObjectKind::PullRequest => "pr",
        };
        let context = GhCommandContext::create(self.worktree_path, self.repository)?;
        context.run(
            "gh source comment",
            [
                subcommand,
                "comment",
                &self.source.number.to_string(),
                "--repo",
                &self.repository.selector(),
                "--body-file",
                "-",
            ]
            .into_iter()
            .map(OsString::from)
            .collect(),
            StdinMode::Bytes(self.marked_body.as_bytes().to_vec()),
        )?;
        let matches = self.exact_candidates(request)?;
        if matches.len() != 1 {
            bail!("GitHub comment creation response could not be reconciled exactly");
        }
        Ok(self.receipt(request, &matches[0]))
    }

    fn verify(
        &mut self,
        request: &ExternalEffectRequest,
        receipt: &ExternalEffectReceipt,
    ) -> Result<ExternalEffectReceipt> {
        validate_external_effect_receipt(request, receipt)?;
        self.revalidate_action_revision()?;
        let id = receipt
            .provider_id
            .parse::<u64>()
            .ok()
            .filter(|id| *id > 0)
            .context("GitHub comment effect receipt id was malformed")?;
        let viewed = cli_github_comment_exact_view(self.worktree_path, id, self.repository)?;
        validate_github_comment_contract(
            &viewed,
            self.repository,
            self.source,
            &self.marked_body,
            self.expected_author,
        )?;
        if viewed.url != receipt.url {
            bail!("GitHub comment receipt URL changed from its exact remote object");
        }
        Ok(self.receipt(request, &viewed))
    }
}

pub(crate) fn publish_github_source_comment(
    repo: &Path,
    source: ExternalSourceGuard,
    body: &str,
) -> Result<String> {
    source.validate()?;
    let repository = Repository::discover(repo)
        .context("failed to discover GitHub comment source repository")?;
    let remote_url = remote_url(&repository, "origin")
        .context("GitHub comment publication requires an origin remote")?;
    let github_repository = github_repository_identity(&remote_url)?;
    refuse_legacy_publication_journals(&repository)?;
    let auth = repository_auth_writer(repo)?
        .into_authenticator()
        .context("failed to bind authenticated GitHub comment effect ledger")?;
    let repository_identity = auth.binding().repository_id.clone();
    drop(auth);
    let expected_author = select_github_expected_author_with(|key| env::var(key).ok())?;
    let operation = match source.object_kind {
        ExternalSourceObjectKind::Issue => ExternalEffectOperation::GithubIssueComment,
        ExternalSourceObjectKind::PullRequest => ExternalEffectOperation::GithubPullRequestComment,
    };
    let request = ExternalEffectRequest::new(
        "github",
        &github_repository.selector(),
        &repository_identity,
        Some(source.clone()),
        operation,
        serde_json::json!({
            "version": 1,
            "repository": github_repository.selector(),
            "source_kind": source.object_kind,
            "source_number": source.number,
        }),
        serde_json::json!({
            "version": 1,
            "body": body,
            "expected_author": expected_author,
        }),
    )?;
    let marked_body = external_effect_marked_body(body, &request.marker)?;
    let mut provider = GithubCommentExternalEffectProvider {
        worktree_path: repo,
        repository: &github_repository,
        source: &source,
        marked_body,
        expected_author: &expected_author,
    };
    let receipt = execute_external_effect_exactly_once(repo, request, &mut provider)?;
    Ok(receipt.url)
}

fn cli_github_comment_candidates(
    worktree_path: &Path,
    source: &ExternalSourceGuard,
    repository: &GithubRepositoryIdentity,
) -> Result<Vec<GithubCommentEffectObserved>> {
    let endpoint = format!(
        "repos/{}/{}/issues/{}/comments?per_page=100",
        repository.owner, repository.name, source.number
    );
    let context = GhCommandContext::create(worktree_path, repository)?;
    let output = context.run(
        "gh source comment candidates",
        ["api", "--method", "GET", "--paginate", "--slurp", &endpoint]
            .into_iter()
            .map(OsString::from)
            .collect(),
        StdinMode::Null,
    )?;
    let stdout = required_command_stdout(output, "gh source comment candidates")?;
    let value: serde_json::Value = serde_json::from_str(&stdout)
        .context("gh source comment candidates did not return valid JSON")?;
    github_comment_candidates_from_slurped_json(&value, repository, source)
}

fn github_comment_candidates_from_slurped_json(
    value: &serde_json::Value,
    repository: &GithubRepositoryIdentity,
    source: &ExternalSourceGuard,
) -> Result<Vec<GithubCommentEffectObserved>> {
    let pages = value
        .as_array()
        .context("GitHub paginated comment result was not an array of pages")?;
    if pages.len() > MAX_GITHUB_COMMENT_PAGES {
        bail!("GitHub comment lookup exceeded its page limit");
    }
    let mut comments = Vec::new();
    for page in pages {
        let page = page
            .as_array()
            .context("GitHub paginated comment page was not an array")?;
        if page.len() > 100 {
            bail!("GitHub comment lookup page exceeded its fixed page size");
        }
        if comments.len().saturating_add(page.len()) > MAX_GITHUB_COMMENT_CANDIDATES {
            bail!("GitHub comment lookup exceeded its total candidate limit");
        }
        for value in page {
            let comment = github_comment_from_rest_json(value)?;
            if github_comment_id_from_url(&comment.url, repository, source)? != comment.id {
                bail!("GitHub comment REST id did not match its canonical HTML URL fragment");
            }
            comments.push(comment);
        }
    }
    Ok(comments)
}

fn github_comment_from_rest_json(value: &serde_json::Value) -> Result<GithubCommentEffectObserved> {
    let object = value
        .as_object()
        .context("GitHub comment candidate was not an object")?;
    let id = object
        .get("id")
        .and_then(serde_json::Value::as_u64)
        .filter(|id| *id > 0)
        .context("GitHub comment candidate omitted id")?;
    let url = object
        .get("html_url")
        .and_then(serde_json::Value::as_str)
        .context("GitHub comment candidate omitted html_url")?;
    let body = object
        .get("body")
        .and_then(serde_json::Value::as_str)
        .context("GitHub comment candidate omitted body")?;
    if body.len() > MAX_GITHUB_RECEIPT_BODY_BYTES || body.as_bytes().contains(&0) {
        bail!("GitHub comment candidate body was malformed or oversized");
    }
    let author = object
        .get("user")
        .and_then(serde_json::Value::as_object)
        .and_then(|user| user.get("login"))
        .and_then(serde_json::Value::as_str)
        .context("GitHub comment candidate omitted user.login")?;
    Ok(GithubCommentEffectObserved {
        id,
        url: url.to_string(),
        body: body.to_string(),
        author: canonical_github_author_login(author)?,
    })
}

fn cli_github_comment_exact_view(
    worktree_path: &Path,
    id: u64,
    repository: &GithubRepositoryIdentity,
) -> Result<GithubCommentEffectObserved> {
    if id == 0 {
        bail!("GitHub comment exact view id must be positive");
    }
    let endpoint = format!(
        "repos/{}/{}/issues/comments/{id}",
        repository.owner, repository.name
    );
    let context = GhCommandContext::create(worktree_path, repository)?;
    let output = context.run(
        "gh comment exact view",
        ["api", "--method", "GET", &endpoint]
            .into_iter()
            .map(OsString::from)
            .collect(),
        StdinMode::Null,
    )?;
    let stdout = required_command_stdout(output, "gh comment exact view")?;
    let value: serde_json::Value =
        serde_json::from_str(&stdout).context("gh comment exact view did not return valid JSON")?;
    let observed = github_comment_from_rest_json(&value)?;
    if observed.id != id {
        bail!("gh comment exact view returned a different id");
    }
    Ok(observed)
}

fn validate_github_comment_contract(
    observed: &GithubCommentEffectObserved,
    repository: &GithubRepositoryIdentity,
    source: &ExternalSourceGuard,
    marked_body: &str,
    expected_author: &str,
) -> Result<()> {
    if github_comment_id_from_url(&observed.url, repository, source)? != observed.id
        || observed.body != marked_body
        || observed.author != expected_author
    {
        bail!("GitHub comment did not match its exact repository, source, body, marker, and author contract");
    }
    Ok(())
}

fn github_comment_id_from_url(
    url: &str,
    expected: &GithubRepositoryIdentity,
    source: &ExternalSourceGuard,
) -> Result<u64> {
    if url.len() > MAX_GITHUB_RECEIPT_URL_BYTES
        || url
            .as_bytes()
            .iter()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
        || url.contains(['?', '%', '\\', '@'])
    {
        bail!("GitHub comment URL was malformed or oversized");
    }
    let (scheme, remainder) = url
        .split_once("://")
        .context("GitHub comment URL was not absolute")?;
    if scheme != "https" {
        bail!("GitHub comment URL was not HTTPS");
    }
    let (path, fragment) = remainder
        .split_once('#')
        .context("GitHub comment URL omitted its exact comment fragment")?;
    let slash = path
        .find('/')
        .context("GitHub comment URL omitted repository path")?;
    let authority = &path[..slash];
    if normalize_github_host(authority)? != authority || authority != expected.host {
        bail!("GitHub comment URL host did not match the repository");
    }
    let components = path[slash + 1..].split('/').collect::<Vec<_>>();
    let expected_kind = match source.object_kind {
        ExternalSourceObjectKind::Issue => "issues",
        ExternalSourceObjectKind::PullRequest => "pull",
    };
    if components.len() != 4
        || !components[0].eq_ignore_ascii_case(&expected.owner)
        || !components[1].eq_ignore_ascii_case(&expected.name)
        || components[2] != expected_kind
        || components[3] != source.number.to_string()
    {
        bail!("GitHub comment URL did not match its exact repository and source object");
    }
    let id = fragment
        .strip_prefix("issuecomment-")
        .and_then(|id| id.parse::<u64>().ok())
        .filter(|id| *id > 0)
        .context("GitHub comment URL fragment did not contain a canonical comment id")?;
    if fragment != format!("issuecomment-{id}") {
        bail!("GitHub comment URL comment id was not canonical");
    }
    Ok(id)
}

fn create_github_issue(repo: &Path, title: &str, body: &str, labels: &[String]) -> Result<String> {
    let repository = Repository::discover(repo).with_context(|| {
        format!(
            "failed to discover issue repository from {}",
            repo.display()
        )
    })?;
    let remote_url = remote_url(&repository, "origin")
        .context("GitHub issue creation requires an 'origin' remote")?;
    let github_repository = github_repository_identity(&remote_url)?;
    refuse_legacy_publication_journals(&repository)?;
    let auth = repository_auth_writer(repo)?
        .into_authenticator()
        .context("failed to bind authenticated GitHub issue effect ledger")?;
    let repository_identity = auth.binding().repository_id.clone();
    drop(auth);
    let expected_author = select_github_expected_author_with(|key| env::var(key).ok())?;
    let request = ExternalEffectRequest::new(
        "github",
        &github_repository.selector(),
        &repository_identity,
        None,
        ExternalEffectOperation::GithubIssue,
        serde_json::json!({
            "version": 1,
            "repository": github_repository.selector(),
            "title": title,
            "labels": labels,
            "expected_author": expected_author,
        }),
        serde_json::json!({
            "version": 1,
            "body": body,
        }),
    )?;
    let marked_body = external_effect_marked_body(body, &request.marker)?;
    let mut provider = GithubIssueExternalEffectProvider {
        worktree_path: repo,
        repository: &github_repository,
        title,
        marked_body,
        labels,
        expected_author: &expected_author,
    };
    let receipt = execute_external_effect_exactly_once(repo, request, &mut provider)?;
    let number = receipt
        .provider_id
        .parse::<u64>()
        .ok()
        .filter(|number| *number > 0)
        .context("GitHub issue receipt provider id was malformed")?;
    validate_github_issue_receipt_url(&receipt.url, &github_repository, number)
}

fn required_command_stdout(output: merge::RequiredCommandOutput, label: &str) -> Result<String> {
    if !output.success {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        bail!("{label} failed: {}", stderr);
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

fn first_non_empty_line(text: &str) -> Option<String> {
    text.lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .map(ToOwned::to_owned)
}

fn redacted_body(body: &str) -> (String, RedactionSummary) {
    let redacted = Redactor::new().redact(body);
    (redacted.text, redacted.summary)
}

fn normalize_title(title: &str) -> Result<String> {
    let title = title.trim();
    if title.is_empty() {
        bail!("issue title cannot be empty");
    }
    Ok(title.to_string())
}

fn normalized_labels(labels: Vec<String>) -> Vec<String> {
    labels
        .into_iter()
        .map(|label| label.trim().to_string())
        .filter(|label| !label.is_empty())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn fake_pr_url(agent_id: &str, branch: &str, changed_paths: &[PathBuf]) -> String {
    #[cfg(all(test, target_os = "linux"))]
    FAKE_PR_URL_CALLS.with(|calls| calls.set(calls.get().saturating_add(1)));
    let mut input = Vec::new();
    input.extend_from_slice(agent_id.as_bytes());
    input.push(b'\n');
    input.extend_from_slice(branch.as_bytes());
    for path in changed_paths {
        input.push(b'\n');
        input.extend_from_slice(&merge::raw_path_bytes(path));
    }
    format!(
        "fake://pr/{}-{:016x}",
        sanitize_url_segment(agent_id),
        stable_hash(&input)
    )
}

fn fake_issue_url(title: &str, body: &str, labels: &[String]) -> String {
    let mut input = String::new();
    input.push_str(title);
    input.push('\n');
    input.push_str(body);
    for label in labels {
        input.push('\n');
        input.push_str(label);
    }
    format!(
        "fake://issue/{}-{:016x}",
        sanitize_url_segment(title),
        stable_hash(input.as_bytes())
    )
}

fn sanitize_url_segment(value: &str) -> String {
    let segment = value
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') {
                c
            } else {
                '-'
            }
        })
        .collect::<String>()
        .trim_matches('-')
        .to_string();
    if segment.is_empty() {
        "item".to_string()
    } else {
        segment
    }
}

fn stable_hash(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf29ce484222325u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

fn serialize_paths<S>(paths: &[PathBuf], serializer: S) -> std::result::Result<S::Ok, S::Error>
where
    S: Serializer,
{
    paths
        .iter()
        .map(|path| merge::path_json_text(path))
        .collect::<Vec<_>>()
        .serialize(serializer)
}

fn summarize_text(text: &str, limit: usize) -> OutputSummary {
    let mut chars = text.chars();
    let value = chars.by_ref().take(limit).collect::<String>();
    OutputSummary {
        text: value,
        truncated: chars.next().is_some(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(target_os = "linux")]
    use crate::worktree::{WorktreeCreateOptions, WorktreeRecord};
    use std::sync::{mpsc, Arc, Mutex};
    #[cfg(target_os = "linux")]
    use std::time::Duration;

    #[derive(Default)]
    struct FakeExternalRemote {
        receipts: Vec<ExternalEffectReceipt>,
        invoke_calls: usize,
    }

    struct FakeExternalProvider {
        remote: Arc<Mutex<FakeExternalRemote>>,
        response_loss: bool,
        lookup_error: bool,
        block_invoke: Option<(mpsc::Sender<()>, mpsc::Receiver<()>)>,
    }

    impl FakeExternalProvider {
        fn new(remote: Arc<Mutex<FakeExternalRemote>>) -> Self {
            Self {
                remote,
                response_loss: false,
                lookup_error: false,
                block_invoke: None,
            }
        }

        fn exact_receipt(request: &ExternalEffectRequest) -> ExternalEffectReceipt {
            ExternalEffectReceipt {
                version: EXTERNAL_EFFECT_VERSION,
                transport_provider: request.transport_provider.clone(),
                repository_identity: request.repository_identity.clone(),
                repository_selector: request.repository_selector.clone(),
                effect_id: request.effect_id.clone(),
                operation: request.operation,
                source_provenance_digest: request
                    .source
                    .as_ref()
                    .map(|source| source.provenance_digest.clone()),
                provider_id: "fake-object-1".to_string(),
                url: "https://example.invalid/acme/repo/effects/1".to_string(),
                repository: request.repository_selector.clone(),
                marker: request.marker.clone(),
                target: request.target.clone(),
                payload: request.payload.clone(),
                target_digest: request.target_digest.clone(),
                payload_digest: request.payload_digest.clone(),
            }
        }
    }

    impl ExternalEffectProvider for FakeExternalProvider {
        fn preflight_before_start(&mut self, _request: &ExternalEffectRequest) -> Result<()> {
            Ok(())
        }

        fn lookup(
            &mut self,
            _request: &ExternalEffectRequest,
        ) -> Result<Vec<ExternalEffectReceipt>> {
            if self.lookup_error {
                bail!("injected lookup failure");
            }
            Ok(self
                .remote
                .lock()
                .expect("fake remote lock")
                .receipts
                .clone())
        }

        fn invoke(&mut self, request: &ExternalEffectRequest) -> Result<ExternalEffectReceipt> {
            let receipt = Self::exact_receipt(request);
            {
                let mut remote = self.remote.lock().expect("fake remote lock");
                remote.invoke_calls += 1;
                remote.receipts.push(receipt.clone());
            }
            if let Some((started, release)) = self.block_invoke.take() {
                started
                    .send(())
                    .expect("signal blocked provider invocation");
                release.recv().expect("release blocked provider invocation");
            }
            if self.response_loss {
                bail!("injected provider response loss");
            }
            Ok(receipt)
        }

        fn verify(
            &mut self,
            request: &ExternalEffectRequest,
            receipt: &ExternalEffectReceipt,
        ) -> Result<ExternalEffectReceipt> {
            validate_external_effect_receipt(request, receipt)?;
            let remote = self.remote.lock().expect("fake remote lock");
            if remote.receipts.as_slice() != [receipt.clone()] {
                bail!("fake remote receipt was missing, duplicated, or mutated");
            }
            Ok(receipt.clone())
        }
    }

    fn fake_effect_repo() -> tempfile::TempDir {
        let temp = tempfile::tempdir().expect("effect repo tempdir");
        WorktreeManager::init_repository(temp.path(), "main").expect("init effect repo");
        temp
    }

    fn fake_source_guard(updated_at: &str, content: char, action: char) -> ExternalSourceGuard {
        ExternalSourceGuard::new(
            "github",
            "github.example",
            "github.example/acme/repo",
            stable_external_digest(b"fake-source-repository"),
            ExternalSourceObjectKind::PullRequest,
            17,
            updated_at,
            "OPEN",
            Some("1".repeat(40)),
            Some("2".repeat(40)),
            content.to_string().repeat(64),
            action.to_string().repeat(64),
        )
        .expect("fake source guard")
    }

    fn fake_effect_request(
        repo: &Path,
        source: ExternalSourceGuard,
        body: &str,
    ) -> ExternalEffectRequest {
        let auth = repository_auth_writer(repo)
            .expect("effect repository auth writer")
            .into_authenticator()
            .expect("effect repository authenticator");
        let repository_identity = auth.binding().repository_id.clone();
        drop(auth);
        ExternalEffectRequest::new(
            "github",
            "github.example/acme/repo",
            &repository_identity,
            Some(source),
            ExternalEffectOperation::GithubPullRequestComment,
            serde_json::json!({"source": 17, "kind": "pull_request"}),
            serde_json::json!({"body": body}),
        )
        .expect("fake external effect request")
    }

    #[test]
    fn external_effect_production_shapes_bind_source_and_transport_providers_separately() {
        let source = fake_source_guard("2026-07-13T00:00:00Z", '3', '4');
        let repository_identity = stable_external_digest(b"production-shape-repository");
        let git_push = ExternalEffectRequest::new(
            "git",
            "github.example/acme/repo",
            &repository_identity,
            Some(source.clone()),
            ExternalEffectOperation::GitPush,
            serde_json::json!({"remote_ref": "refs/heads/maco/effects/1"}),
            serde_json::json!({"expected_oid": "1".repeat(40)}),
        )
        .expect("source-backed Git transport request");
        let github_pr = ExternalEffectRequest::new(
            "github",
            "github.example/acme/repo",
            &repository_identity,
            Some(source.clone()),
            ExternalEffectOperation::GithubPullRequest,
            serde_json::json!({"base": "main"}),
            serde_json::json!({"draft": true}),
        )
        .expect("source-backed GitHub PR transport request");
        let github_comment = ExternalEffectRequest::new(
            "github",
            "github.example/acme/repo",
            &repository_identity,
            Some(source),
            ExternalEffectOperation::GithubPullRequestComment,
            serde_json::json!({"number": 17}),
            serde_json::json!({"body": "done"}),
        )
        .expect("source-backed GitHub comment transport request");

        assert_eq!(git_push.transport_provider, "git");
        assert_eq!(github_pr.transport_provider, "github");
        assert_eq!(github_comment.transport_provider, "github");
        assert_eq!(git_push.source.as_ref().unwrap().provider, "github");
        assert_eq!(github_pr.source.as_ref().unwrap().provider, "github");
        assert_ne!(git_push.effect_id, github_pr.effect_id);
        assert!(ExternalEffectRequest::new(
            "github",
            "github.example/acme/repo",
            &repository_identity,
            git_push.source,
            ExternalEffectOperation::GitPush,
            serde_json::json!({}),
            serde_json::json!({}),
        )
        .is_err());
    }

    fn seed_effect_phase(
        repo: &Path,
        request: &ExternalEffectRequest,
        phase: EffectPhase,
        receipt: Option<ExternalEffectReceipt>,
    ) {
        let auth = repository_auth_writer(repo)
            .expect("seed auth writer")
            .into_authenticator()
            .expect("seed authenticator");
        let planned = ExternalEffectRecord {
            version: EXTERNAL_EFFECT_VERSION,
            request: request.clone(),
            receipt: None,
        };
        let mut wal: EffectWal =
            EffectWal::create_planned(auth, &request.logical_id, &request.effect_id, &planned)
                .expect("seed planned effect");
        if matches!(
            phase,
            EffectPhase::Started | EffectPhase::Observed | EffectPhase::Completed
        ) {
            wal.started(&request.effect_id, &planned)
                .expect("seed started effect");
        }
        if matches!(phase, EffectPhase::Observed | EffectPhase::Completed) {
            let observed = ExternalEffectRecord {
                version: EXTERNAL_EFFECT_VERSION,
                request: request.clone(),
                receipt,
            };
            wal.observed(&request.effect_id, &observed)
                .expect("seed observed effect");
        }
    }

    #[test]
    fn external_effect_started_recovery_is_lookup_only_and_ambiguity_fails_closed() {
        for count in [0_usize, 1, 2] {
            let repo = fake_effect_repo();
            let request = fake_effect_request(
                repo.path(),
                fake_source_guard("2026-07-13T00:00:00Z", '3', '4'),
                "comment",
            );
            seed_effect_phase(repo.path(), &request, EffectPhase::Started, None);
            let receipt = FakeExternalProvider::exact_receipt(&request);
            let remote = Arc::new(Mutex::new(FakeExternalRemote {
                receipts: vec![receipt.clone(); count],
                invoke_calls: 0,
            }));
            let mut provider = FakeExternalProvider::new(remote.clone());
            let result =
                execute_external_effect_exactly_once(repo.path(), request.clone(), &mut provider);
            if count == 1 {
                assert_eq!(result.expect("exactly one recovery receipt"), receipt);
            } else {
                assert!(result.is_err());
            }
            assert_eq!(remote.lock().expect("remote lock").invoke_calls, 0);
        }

        let repo = fake_effect_repo();
        let request = fake_effect_request(
            repo.path(),
            fake_source_guard("2026-07-13T00:00:00Z", '7', '8'),
            "lookup error",
        );
        seed_effect_phase(repo.path(), &request, EffectPhase::Started, None);
        let remote = Arc::new(Mutex::new(FakeExternalRemote::default()));
        let mut provider = FakeExternalProvider::new(remote.clone());
        provider.lookup_error = true;
        assert!(execute_external_effect_exactly_once(repo.path(), request, &mut provider).is_err());
        assert_eq!(remote.lock().expect("remote lock").invoke_calls, 0);
    }

    #[test]
    fn external_effect_observed_resume_and_response_loss_never_resend() {
        let observed_repo = fake_effect_repo();
        let observed_request = fake_effect_request(
            observed_repo.path(),
            fake_source_guard("2026-07-13T00:00:00Z", '3', '4'),
            "observed",
        );
        let observed_receipt = FakeExternalProvider::exact_receipt(&observed_request);
        seed_effect_phase(
            observed_repo.path(),
            &observed_request,
            EffectPhase::Observed,
            Some(observed_receipt.clone()),
        );
        let observed_remote = Arc::new(Mutex::new(FakeExternalRemote {
            receipts: vec![observed_receipt.clone()],
            invoke_calls: 0,
        }));
        let mut observed_provider = FakeExternalProvider::new(observed_remote.clone());
        assert_eq!(
            execute_external_effect_exactly_once(
                observed_repo.path(),
                observed_request,
                &mut observed_provider,
            )
            .expect("observed recovery"),
            observed_receipt
        );
        assert_eq!(
            observed_remote
                .lock()
                .expect("observed remote")
                .invoke_calls,
            0
        );

        let loss_repo = fake_effect_repo();
        let loss_request = fake_effect_request(
            loss_repo.path(),
            fake_source_guard("2026-07-13T00:00:00Z", '5', '6'),
            "lost response",
        );
        let loss_remote = Arc::new(Mutex::new(FakeExternalRemote::default()));
        let mut loss_provider = FakeExternalProvider::new(loss_remote.clone());
        loss_provider.response_loss = true;
        execute_external_effect_exactly_once(loss_repo.path(), loss_request, &mut loss_provider)
            .expect("response loss reconciled by lookup");
        let loss_remote = loss_remote.lock().expect("loss remote");
        assert_eq!(loss_remote.invoke_calls, 1);
        assert_eq!(loss_remote.receipts.len(), 1);
    }

    #[test]
    fn external_effect_completed_reverifies_remote_and_reuses_after_volatile_source_change() {
        let repo = fake_effect_repo();
        let first = fake_effect_request(
            repo.path(),
            fake_source_guard("2026-07-13T00:00:00Z", '3', '4'),
            "stable comment",
        );
        let remote = Arc::new(Mutex::new(FakeExternalRemote::default()));
        let mut provider = FakeExternalProvider::new(remote.clone());
        let receipt =
            execute_external_effect_exactly_once(repo.path(), first.clone(), &mut provider)
                .expect("initial effect");
        assert_eq!(remote.lock().expect("remote").invoke_calls, 1);
        let repository = Repository::open(repo.path()).expect("open effect repository");
        assert!(!repository
            .commondir()
            .join("maco/state/publication-transactions")
            .exists());

        let next_run = fake_effect_request(
            repo.path(),
            fake_source_guard("2026-07-13T00:01:00Z", '5', '4'),
            "stable comment",
        );
        assert_eq!(first.effect_id, next_run.effect_id);
        assert_eq!(first.marker, next_run.marker);
        assert!(same_external_effect_contract(&first, &next_run));
        assert_eq!(
            execute_external_effect_exactly_once(repo.path(), next_run, &mut provider)
                .expect("completed effect reused after updatedAt-only change"),
            receipt
        );
        assert_eq!(remote.lock().expect("remote").invoke_calls, 1);

        remote.lock().expect("remote").receipts.clear();
        assert!(
            execute_external_effect_exactly_once(repo.path(), first.clone(), &mut provider)
                .is_err()
        );
        let mut mutated = receipt;
        mutated.url.push_str("-mutated");
        remote.lock().expect("remote").receipts = vec![mutated];
        assert!(execute_external_effect_exactly_once(repo.path(), first, &mut provider).is_err());
        assert_eq!(remote.lock().expect("remote").invoke_calls, 1);
    }

    #[test]
    fn external_effect_call_uses_snapshot_metadata_without_legacy_effect_metadata() {
        let repo = fake_effect_repo();
        let request = fake_effect_request(
            repo.path(),
            fake_source_guard("2026-07-13T00:00:00Z", '3', '4'),
            "snapshot-backed effect",
        );
        let remote = Arc::new(Mutex::new(FakeExternalRemote::default()));
        let mut provider = FakeExternalProvider::new(remote);
        execute_external_effect_exactly_once(repo.path(), request, &mut provider)
            .expect("snapshot-backed external effect");

        let repository = Repository::open(repo.path()).expect("open effect repository");
        let root = repository
            .commondir()
            .join("maco/state")
            .join(crate::effect_wal::EFFECT_WAL_ROOT_NAME);
        let names = std::fs::read_dir(root)
            .expect("effect snapshot root")
            .map(|entry| {
                entry
                    .expect("effect snapshot entry")
                    .file_name()
                    .into_string()
                    .expect("UTF-8 effect snapshot entry")
            })
            .collect::<Vec<_>>();
        assert!(names
            .iter()
            .any(|name| name.starts_with(".snapshot-locator-")));
        assert!(!names.iter().any(|name| {
            name.starts_with(".effect-locator-")
                || name.starts_with(".effect-init-")
                || name.starts_with(".effect-store-")
        }));
    }

    #[test]
    fn external_effect_planned_payload_and_stable_source_revision_are_exact() {
        let repo = fake_effect_repo();
        let first = fake_effect_request(
            repo.path(),
            fake_source_guard("2026-07-13T00:00:00Z", '3', '4'),
            "first payload",
        );
        let same_next_run = fake_effect_request(
            repo.path(),
            fake_source_guard("2026-07-13T00:00:00Z", '3', '4'),
            "first payload",
        );
        assert_eq!(first, same_next_run);
        let marked = external_effect_marked_body("PR body", &first.marker)
            .expect("stable marker-bound PR body");
        assert_eq!(marked.matches(&first.marker).count(), 1);
        assert!(!marked.contains("maco-publication-marker"));
        let first_ref = format!("refs/heads/maco/effects/{}", &first.effect_id[..32]);
        let next_ref = format!("refs/heads/maco/effects/{}", &same_next_run.effect_id[..32]);
        assert_eq!(first_ref, next_ref);
        let changed_payload = fake_effect_request(
            repo.path(),
            fake_source_guard("2026-07-13T00:01:00Z", '5', '4'),
            "changed payload",
        );
        assert_eq!(first.effect_id, changed_payload.effect_id);
        assert!(!same_external_effect_contract(&first, &changed_payload));
        let remote = Arc::new(Mutex::new(FakeExternalRemote::default()));
        let mut provider = FakeExternalProvider::new(remote.clone());
        execute_external_effect_exactly_once(repo.path(), first.clone(), &mut provider)
            .expect("first exact payload");
        assert!(
            execute_external_effect_exactly_once(repo.path(), changed_payload, &mut provider)
                .is_err()
        );
        assert_eq!(remote.lock().expect("remote").invoke_calls, 1);

        let changed_action = fake_effect_request(
            repo.path(),
            fake_source_guard("2026-07-13T00:01:00Z", '5', '6'),
            "first payload",
        );
        assert_ne!(first.effect_id, changed_action.effect_id);
        assert_ne!(first.logical_id, changed_action.logical_id);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn concurrent_external_effect_calls_cannot_double_invoke() {
        let repo = fake_effect_repo();
        let request = fake_effect_request(
            repo.path(),
            fake_source_guard("2026-07-13T00:00:00Z", '3', '4'),
            "concurrent",
        );
        let remote = Arc::new(Mutex::new(FakeExternalRemote::default()));
        let (started_tx, started_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let mut first_provider = FakeExternalProvider::new(remote.clone());
        first_provider.block_invoke = Some((started_tx, release_rx));
        let first_repo = repo.path().to_path_buf();
        let first_request = request.clone();
        let first = std::thread::spawn(move || {
            execute_external_effect_exactly_once(&first_repo, first_request, &mut first_provider)
        });
        started_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("first provider reached invocation");
        let mut contender = FakeExternalProvider::new(remote.clone());
        assert!(
            execute_external_effect_exactly_once(repo.path(), request, &mut contender).is_err()
        );
        release_tx.send(()).expect("release first provider");
        first.join().expect("first thread").expect("first effect");
        assert_eq!(remote.lock().expect("remote").invoke_calls, 1);
    }

    #[test]
    fn external_source_guard_separates_full_freshness_from_action_revision_and_accepts_40_hex_oids()
    {
        let identity = external_source_repository_identity(7, 11);
        assert_eq!(identity.len(), 64);
        assert_ne!(identity, external_source_repository_identity(7, 12));
        assert_ne!(identity, external_source_repository_identity(8, 11));
        assert!(ExternalSourceGuard::new(
            "github",
            "github.example",
            "github.example/acme/repo",
            "maco-v1-collision-prone-identity",
            ExternalSourceObjectKind::Issue,
            1,
            "2026-07-13T00:00:00Z",
            "OPEN",
            None,
            None,
            "1".repeat(64),
            "2".repeat(64),
        )
        .is_err());
        assert!(ExternalSourceGuard::new(
            "github",
            "other.example",
            "github.example/acme/repo",
            identity.clone(),
            ExternalSourceObjectKind::Issue,
            1,
            "2026-07-13T00:00:00Z",
            "OPEN",
            None,
            None,
            "1".repeat(64),
            "2".repeat(64),
        )
        .is_err());
        assert!(validate_github_source_repository_binding(
            "github.example",
            "other.example/acme/repo"
        )
        .is_err());
        assert!(ExternalSourceGuard::new(
            "github",
            "github.example",
            "github.example/acme/repo/extra",
            identity.clone(),
            ExternalSourceObjectKind::Issue,
            1,
            "2026-07-13T00:00:00Z",
            "OPEN",
            None,
            None,
            "1".repeat(64),
            "2".repeat(64),
        )
        .is_err());
        assert!(ExternalSourceGuard::new(
            "github",
            "github.example",
            "github.example/acme/repo",
            identity.clone(),
            ExternalSourceObjectKind::Issue,
            1,
            "2026-07-13T00:00:00Z",
            "MERGED",
            None,
            None,
            "1".repeat(64),
            "2".repeat(64),
        )
        .is_err());
        let original = serde_json::json!({
            "number": 7,
            "title": "stable title",
            "body": "stable body",
            "url": "https://github.example/acme/repo/pull/7",
            "author": {"login": "author"},
            "labels": [{"name": "bug"}],
            "updatedAt": "2026-07-13T00:00:00Z",
            "state": "OPEN",
            "headRefName": "feature",
            "baseRefName": "main",
            "headRefOid": "1".repeat(40),
            "baseRefOid": "2".repeat(40),
            "isDraft": false,
            "files": [{"path": "src/lib.rs"}],
            "reviewDecision": "",
            "latestReviews": [],
            "statusCheckRollup": []
        });
        let expected = github_source_guard_from_value(
            "github.example",
            "github.example/acme/repo",
            &stable_external_digest(b"source-repo"),
            ExternalSourceObjectKind::PullRequest,
            &original,
        )
        .expect("original guard");
        let mut volatile = original.clone();
        volatile["updatedAt"] = serde_json::json!("2026-07-13T00:01:00Z");
        volatile["statusCheckRollup"] = serde_json::json!([{"name": "maco", "status": "SUCCESS"}]);
        let volatile_guard = github_source_guard_from_value(
            "github.example",
            "github.example/acme/repo",
            &stable_external_digest(b"source-repo"),
            ExternalSourceObjectKind::PullRequest,
            &volatile,
        )
        .expect("volatile guard");
        assert_ne!(expected.provenance_digest, volatile_guard.provenance_digest);
        assert_eq!(
            expected.action_revision_digest,
            volatile_guard.action_revision_digest
        );
        assert!(revalidate_external_source_value(&expected, &volatile).is_err());

        let mut changed = volatile;
        changed["title"] = serde_json::json!("changed title");
        let changed_guard = github_source_guard_from_value(
            "github.example",
            "github.example/acme/repo",
            &stable_external_digest(b"source-repo"),
            ExternalSourceObjectKind::PullRequest,
            &changed,
        )
        .expect("changed guard");
        assert_ne!(
            expected.action_revision_digest,
            changed_guard.action_revision_digest
        );
    }

    #[test]
    fn github_source_guard_requires_exact_typed_fields_and_only_documented_nulls() {
        let valid = serde_json::json!({
            "number": 7,
            "title": "title",
            "body": "",
            "url": "https://github.example/acme/repo/pull/7",
            "author": null,
            "labels": [],
            "updatedAt": "2026-07-13T00:00:00Z",
            "state": "OPEN",
            "headRefName": "feature",
            "baseRefName": "main",
            "headRefOid": "1".repeat(40),
            "baseRefOid": "2".repeat(40),
            "isDraft": false,
            "files": [],
            "reviewDecision": null,
            "latestReviews": [],
            "statusCheckRollup": []
        });
        let parse = |value: &serde_json::Value| {
            github_source_guard_from_value(
                "github.example",
                "github.example/acme/repo",
                &stable_external_digest(b"strict-source-repository"),
                ExternalSourceObjectKind::PullRequest,
                value,
            )
        };
        parse(&valid).expect("documented explicit nulls");

        for field in [
            "number",
            "title",
            "body",
            "url",
            "author",
            "labels",
            "updatedAt",
            "state",
            "headRefName",
            "baseRefName",
            "headRefOid",
            "baseRefOid",
            "isDraft",
            "files",
            "reviewDecision",
            "latestReviews",
            "statusCheckRollup",
        ] {
            let mut missing = valid.clone();
            missing.as_object_mut().unwrap().remove(field);
            assert!(parse(&missing).is_err(), "missing {field} was accepted");
        }
        for (field, wrong) in [
            ("body", serde_json::json!(null)),
            ("author", serde_json::json!("reviewer")),
            ("labels", serde_json::json!(null)),
            ("labels", serde_json::json!([null])),
            ("isDraft", serde_json::json!(null)),
            ("files", serde_json::json!({})),
            ("files", serde_json::json!([null])),
            ("reviewDecision", serde_json::json!(false)),
            ("latestReviews", serde_json::json!(null)),
            ("latestReviews", serde_json::json!([null])),
            ("statusCheckRollup", serde_json::json!({})),
            ("statusCheckRollup", serde_json::json!([null])),
        ] {
            let mut malformed = valid.clone();
            malformed[field] = wrong;
            assert!(
                parse(&malformed).is_err(),
                "wrong type for {field} was accepted"
            );
        }
    }

    #[test]
    fn github_issue_effect_contract_rejects_closed_or_mutated_remote() {
        let repository = GithubRepositoryIdentity {
            host: "github.example".to_string(),
            owner: "acme".to_string(),
            name: "repo".to_string(),
        };
        let provider = GithubIssueExternalEffectProvider {
            worktree_path: Path::new("."),
            repository: &repository,
            title: "title",
            marked_body: "body\n\n<!-- maco-external-effect:v2:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa -->".to_string(),
            labels: &["bug".to_string()],
            expected_author: "publisher",
        };
        let exact = GithubIssueEffectObserved {
            number: 7,
            url: "https://github.example/acme/repo/issues/7".to_string(),
            title: "title".to_string(),
            body: provider.marked_body.clone(),
            labels: vec!["bug".to_string()],
            author: "publisher".to_string(),
            state: "OPEN".to_string(),
        };
        assert!(provider.matches_contract(&exact).expect("exact issue"));
        let mut closed = exact.clone();
        closed.state = "CLOSED".to_string();
        assert!(!provider.matches_contract(&closed).expect("closed issue"));
        let mut wrong_url_number = exact.clone();
        wrong_url_number.url = "https://github.example/acme/repo/issues/8".to_string();
        assert!(provider.matches_contract(&wrong_url_number).is_err());
        let mut mutated = exact;
        mutated.body.push_str("mutated");
        assert!(!provider.matches_contract(&mutated).expect("mutated issue"));

        let over_limit = serde_json::Value::Array(
            std::iter::repeat_n(
                serde_json::json!({
                    "number": 7,
                    "url": "https://github.example/acme/repo/issues/7",
                    "title": "title",
                    "body": provider.marked_body,
                    "labels": [{"name": "bug"}],
                    "author": {"login": "publisher"},
                    "state": "OPEN"
                }),
                MAX_GITHUB_EFFECT_CANDIDATES + 1,
            )
            .collect(),
        );
        assert!(github_issue_effect_list_from_json(&over_limit).is_err());
    }

    #[test]
    fn github_comment_paginated_parser_finds_candidates_after_first_hundred() {
        let repository = GithubRepositoryIdentity {
            host: "github.example".to_string(),
            owner: "acme".to_string(),
            name: "repo".to_string(),
        };
        let source = ExternalSourceGuard::new(
            "github",
            "github.example",
            "github.example/acme/repo",
            stable_external_digest(b"paginated-comment-source"),
            ExternalSourceObjectKind::Issue,
            7,
            "2026-07-13T00:00:00Z",
            "OPEN",
            None,
            None,
            "1".repeat(64),
            "2".repeat(64),
        )
        .expect("comment source guard");
        let page_one = (1_u64..=100)
            .map(|id| {
                serde_json::json!({
                    "id": id,
                    "html_url": format!("https://github.example/acme/repo/issues/7#issuecomment-{id}"),
                    "body": format!("ordinary comment {id}"),
                    "user": {"login": "publisher"}
                })
            })
            .collect::<Vec<_>>();
        let marker = "<!-- maco-external-effect:v2:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa -->";
        let pages = serde_json::json!([
            page_one,
            [{
                "id": 101,
                "html_url": "https://github.example/acme/repo/issues/7#issuecomment-101",
                "body": marker,
                "user": {"login": "publisher"}
            }]
        ]);
        let comments = github_comment_candidates_from_slurped_json(&pages, &repository, &source)
            .expect("parse all comment pages");
        assert_eq!(comments.len(), 101);
        assert_eq!(comments.last().expect("last comment").body, marker);

        let mismatched_id = serde_json::json!([[{
            "id": 102,
            "html_url": "https://github.example/acme/repo/issues/7#issuecomment-103",
            "body": marker,
            "user": {"login": "publisher"}
        }]]);
        assert!(
            github_comment_candidates_from_slurped_json(&mismatched_id, &repository, &source)
                .is_err()
        );

        let too_many_pages = serde_json::Value::Array(
            std::iter::repeat_n(serde_json::json!([]), MAX_GITHUB_COMMENT_PAGES + 1).collect(),
        );
        assert!(
            github_comment_candidates_from_slurped_json(&too_many_pages, &repository, &source)
                .is_err()
        );
    }

    #[test]
    fn legacy_plaintext_publication_journal_requires_explicit_migration_without_mutation() {
        let repo = fake_effect_repo();
        let repository = Repository::open(repo.path()).expect("open legacy test repo");
        let legacy_root = repository
            .commondir()
            .join("maco/state/publication-transactions/legacy");
        fs::create_dir_all(&legacy_root).expect("create legacy journal directory");
        let legacy_record = legacy_root.join("00000000000000000001.json");
        fs::write(&legacy_record, b"legacy plaintext must remain untouched\n")
            .expect("write legacy record");
        let error = refuse_legacy_publication_journals(&repository)
            .expect_err("legacy journal must require migration");
        assert!(error.to_string().contains("explicit signed migration"));
        assert_eq!(
            fs::read(&legacy_record).expect("legacy record remains"),
            b"legacy plaintext must remain untouched\n"
        );
    }

    #[test]
    fn prepared_change_kinds_allow_only_untracked_to_added_transition() {
        let untracked = vec![merge::ChangedPath {
            path: PathBuf::from("new.txt"),
            kind: merge::ChangeKind::Untracked,
        }];
        let added = vec![merge::ChangedPath {
            path: PathBuf::from("new.txt"),
            kind: merge::ChangeKind::Added,
        }];
        let changed_path = vec![merge::ChangedPath {
            path: PathBuf::from("other.txt"),
            kind: merge::ChangeKind::Added,
        }];

        assert!(prepared_change_kinds_match(&untracked, &added));
        assert!(!prepared_change_kinds_match(&added, &untracked));
        assert!(!prepared_change_kinds_match(&untracked, &changed_path));
    }

    #[cfg(target_os = "linux")]
    fn create_publication_lease_fixture(
        root: &Path,
    ) -> (PathBuf, WorktreeManager, WorktreeRecord, WorktreeRecord) {
        let repo_path = root.join("repo");
        let worktree_root = root.join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repository");
        fs::write(repo_path.join("README.md"), "# Publication fixture\n")
            .expect("write fixture README");
        let repo = Repository::open(&repo_path).expect("open fixture repository");
        let mut config = repo.config().expect("open fixture config");
        config
            .set_str("user.name", "maco test")
            .expect("configure test name");
        config
            .set_str("user.email", "maco-test@example.invalid")
            .expect("configure test email");
        drop(config);
        let mut index = repo.index().expect("open fixture index");
        index
            .add_path(Path::new("README.md"))
            .expect("stage fixture README");
        index.write().expect("write fixture index");
        let tree_id = index.write_tree().expect("write fixture tree");
        let tree = repo.find_tree(tree_id).expect("find fixture tree");
        let signature = git2::Signature::now("maco test", "maco-test@example.invalid")
            .expect("fixture signature");
        repo.commit(Some("HEAD"), &signature, &signature, "initial", &tree, &[])
            .expect("commit fixture");
        drop(tree);
        drop(repo);

        let manager = WorktreeManager::new(&repo_path);
        let agent_a = manager
            .create(WorktreeCreateOptions {
                agent_id: "agent-a".to_string(),
                branch: None,
                base: None,
                worktree_root: Some(worktree_root.clone()),
            })
            .expect("create agent-a worktree");
        let agent_b = manager
            .create(WorktreeCreateOptions {
                agent_id: "agent-b".to_string(),
                branch: None,
                base: None,
                worktree_root: Some(worktree_root),
            })
            .expect("create agent-b worktree");
        (repo_path, manager, agent_a, agent_b)
    }

    #[cfg(target_os = "linux")]
    fn fake_publication_options(repo: &Path, agent_id: &str) -> PrPublicationOptions {
        PrPublicationOptions {
            repo: repo.to_path_buf(),
            agent_id: agent_id.to_string(),
            claimed_paths: vec![PathBuf::from("README.md")],
            validations: Vec::new(),
            forge: ForgeKind::Fake,
            draft: true,
        }
    }

    #[cfg(target_os = "linux")]
    fn commit_agent_readme(worktree: &Path, contents: &str, message: &str) -> Oid {
        fs::write(worktree.join("README.md"), contents).expect("write committed README");
        let repo = Repository::open(worktree).expect("open agent repository");
        let mut index = repo.index().expect("open agent index");
        index
            .add_path(Path::new("README.md"))
            .expect("stage agent README");
        index.write().expect("write agent index");
        let tree_id = index.write_tree().expect("write agent tree");
        let tree = repo.find_tree(tree_id).expect("find agent tree");
        let parent = repo
            .head()
            .expect("agent HEAD")
            .peel_to_commit()
            .expect("agent parent commit");
        let signature = repo.signature().expect("agent signature");
        repo.commit(
            Some("HEAD"),
            &signature,
            &signature,
            message,
            &tree,
            &[&parent],
        )
        .expect("commit agent README")
    }

    #[cfg(target_os = "linux")]
    fn passed_prepared_validation() -> ValidationReport {
        ValidationReport {
            name: "prepared-unit".to_string(),
            status: merge::ValidationStatus::Passed,
            message: None,
            paths: vec![PathBuf::from("README.md")],
        }
    }

    #[cfg(target_os = "linux")]
    fn publication_transactions_path(repo: &Path) -> PathBuf {
        repo.join(".git/maco/state/publication-transactions")
    }

    #[cfg(target_os = "linux")]
    fn reset_fake_pr_url_calls() {
        FAKE_PR_URL_CALLS.with(|calls| calls.set(0));
    }

    #[cfg(target_os = "linux")]
    fn fake_pr_url_calls() -> usize {
        FAKE_PR_URL_CALLS.with(std::cell::Cell::get)
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn prepare_dirty_candidate_commits_exact_content_without_external_effects() {
        let temp = tempfile::tempdir().expect("tempdir");
        let (repo_path, manager, agent_a, _) = create_publication_lease_fixture(temp.path());
        fs::write(agent_a.path.join("README.md"), "# Prepared dirty\n")
            .expect("edit dirty candidate");
        let before_head = Repository::open(&agent_a.path)
            .expect("open agent repository")
            .head()
            .expect("agent HEAD")
            .target()
            .expect("direct agent HEAD");
        let write_lease = manager
            .acquire_write_execution_lease("agent-a")
            .expect("publication write lease");
        let options = fake_publication_options(&repo_path, "agent-a");
        reset_fake_pr_url_calls();

        let prepared = prepare_pr_candidate_with_write_lease(options, &write_lease)
            .expect("prepare dirty candidate");

        assert_eq!(prepared.status, PrPublicationStatus::Preview);
        assert!(!prepared.pushed);
        assert!(!prepared.created);
        assert!(prepared.pr_url.is_none());
        assert!(prepared.publication_receipt.is_none());
        let prepared_commit = prepared.commit_id.as_deref().expect("prepared commit id");
        assert_ne!(prepared_commit, before_head.to_string());
        assert_eq!(prepared.head_id.as_deref(), Some(prepared_commit));
        assert_eq!(
            prepared
                .preview
                .candidate
                .validation_binding
                .agent_head
                .as_deref(),
            Some(prepared_commit)
        );
        assert!(!has_uncommitted_changes(&agent_a.path).expect("clean prepared worktree"));
        assert!(!publication_transactions_path(&repo_path).exists());
        assert_eq!(fake_pr_url_calls(), 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn prepare_already_clean_candidate_preserves_existing_commit() {
        let temp = tempfile::tempdir().expect("tempdir");
        let (repo_path, manager, agent_a, _) = create_publication_lease_fixture(temp.path());
        let existing = commit_agent_readme(&agent_a.path, "# Already clean\n", "clean candidate");
        let write_lease = manager
            .acquire_write_execution_lease("agent-a")
            .expect("publication write lease");
        let mut options = fake_publication_options(&repo_path, "agent-a");
        options.forge = ForgeKind::Github;

        let prepared = prepare_pr_candidate_with_write_lease(options, &write_lease)
            .expect("prepare clean candidate without invoking GitHub");

        assert_eq!(prepared.status, PrPublicationStatus::Preview);
        assert_eq!(
            prepared.commit_id.as_deref(),
            Some(existing.to_string()).as_deref()
        );
        assert_eq!(prepared.head_id, prepared.commit_id);
        assert!(!has_uncommitted_changes(&agent_a.path).expect("clean candidate remains clean"));
        assert!(!publication_transactions_path(&repo_path).exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn prepare_refuses_drift_before_creating_local_commit() {
        let temp = tempfile::tempdir().expect("tempdir");
        let (repo_path, manager, agent_a, _) = create_publication_lease_fixture(temp.path());
        fs::write(agent_a.path.join("README.md"), "# Reviewed candidate\n")
            .expect("write reviewed candidate");
        let before_head = Repository::open(&agent_a.path)
            .expect("open agent repository")
            .head()
            .expect("agent HEAD")
            .target()
            .expect("direct agent HEAD");
        let write_lease = manager
            .acquire_write_execution_lease("agent-a")
            .expect("publication write lease");
        let drift_path = agent_a.path.join("README.md");

        let error = prepare_pr_candidate_with_write_lease_after_preview(
            fake_publication_options(&repo_path, "agent-a"),
            &write_lease,
            move |_| {
                fs::write(drift_path, "# Drifted candidate\n").expect("inject candidate drift");
            },
        )
        .expect_err("candidate drift must fail preparation");

        assert!(error
            .to_string()
            .contains("changed before candidate preparation"));
        assert_eq!(
            Repository::open(&agent_a.path)
                .expect("reopen agent repository")
                .head()
                .expect("agent HEAD after drift")
                .target(),
            Some(before_head)
        );
        assert!(!publication_transactions_path(&repo_path).exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn strict_prepared_publish_blocks_candidate_drift_before_effects() {
        let temp = tempfile::tempdir().expect("tempdir");
        let (repo_path, manager, agent_a, _) = create_publication_lease_fixture(temp.path());
        fs::write(agent_a.path.join("README.md"), "# Prepared candidate\n")
            .expect("write prepared candidate");
        let write_lease = manager
            .acquire_write_execution_lease("agent-a")
            .expect("publication write lease");
        let prepared = prepare_pr_candidate_with_write_lease(
            fake_publication_options(&repo_path, "agent-a"),
            &write_lease,
        )
        .expect("prepare candidate");
        let bound = ValidationEvidenceBundle::bound_to(
            prepared.preview.candidate.validation_binding.clone(),
            vec![passed_prepared_validation()],
        )
        .expect("bind prepared validation");
        commit_agent_readme(&agent_a.path, "# Later reviewed drift\n", "candidate drift");
        let mut options = fake_publication_options(&repo_path, "agent-a");
        options.forge = ForgeKind::Github;

        let report = publish_prepared_pr_with_write_lease(options, &bound, &write_lease)
            .expect("strict publication reports candidate mismatch");

        assert_eq!(report.status, PrPublicationStatus::Blocked);
        assert_eq!(
            report.preview.safety.validation_evidence.binding_status,
            merge::ValidationBindingStatus::Mismatched
        );
        assert!(!report.pushed);
        assert!(!report.created);
        assert!(report.pr_url.is_none());
        assert!(!publication_transactions_path(&repo_path).exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn strict_prepared_publish_accepts_matching_bound_evidence() {
        let temp = tempfile::tempdir().expect("tempdir");
        let (repo_path, manager, agent_a, _) = create_publication_lease_fixture(temp.path());
        fs::write(agent_a.path.join("README.md"), "# Matching candidate\n")
            .expect("write matching candidate");
        let write_lease = manager
            .acquire_write_execution_lease("agent-a")
            .expect("publication write lease");
        let options = fake_publication_options(&repo_path, "agent-a");
        let prepared = prepare_pr_candidate_with_write_lease(options.clone(), &write_lease)
            .expect("prepare matching candidate");
        let bound = ValidationEvidenceBundle::bound_to(
            prepared.preview.candidate.validation_binding.clone(),
            vec![passed_prepared_validation()],
        )
        .expect("bind matching validation");
        reset_fake_pr_url_calls();

        let report = publish_prepared_pr_with_write_lease(options, &bound, &write_lease)
            .expect("publish matching prepared candidate");

        assert_eq!(report.status, PrPublicationStatus::Published);
        assert_eq!(
            report.preview.safety.validation_evidence.binding_status,
            merge::ValidationBindingStatus::Bound
        );
        assert!(report.created);
        assert!(!report.pushed);
        assert_eq!(fake_pr_url_calls(), 1);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn prepare_holds_and_releases_worktree_and_repository_locks() {
        let temp = tempfile::tempdir().expect("tempdir");
        let (repo_path, manager, agent_a, agent_b) = create_publication_lease_fixture(temp.path());
        fs::write(agent_a.path.join("README.md"), "# Lock candidate\n")
            .expect("write lock candidate");
        let (ready_tx, ready_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let publisher_repo = repo_path.clone();
        let publisher_manager = manager.clone();
        let publisher = std::thread::spawn(move || {
            let write_lease = publisher_manager
                .acquire_write_execution_lease("agent-a")
                .expect("publisher write lease");
            prepare_pr_candidate_with_write_lease_after_preview(
                fake_publication_options(&publisher_repo, "agent-a"),
                &write_lease,
                |_| {
                    ready_tx.send(()).expect("signal held preparation locks");
                    release_rx
                        .recv_timeout(Duration::from_secs(5))
                        .expect("release preparation locks");
                },
            )
        });

        // Candidate preview performs a bounded status capture with a 60-second
        // total budget. Under a parallel test load that capture can take more
        // than five seconds even though the publication locks are behaving
        // correctly. Keep this coordination assertion above that production
        // budget so safe bounded work is not mistaken for a lock failure.
        ready_rx
            .recv_timeout(Duration::from_secs(65))
            .expect("preparation acquired both locks");
        manager
            .acquire_read_execution_lease("agent-a")
            .expect_err("preparation writer excludes readers");
        manager
            .acquire_write_execution_lease("agent-a")
            .expect_err("preparation writer excludes writers");
        manager
            .remove("agent-a", true, false)
            .expect_err("preparation writer excludes removal");
        match RepoCommonLock::acquire(&repo_path, "merge-apply") {
            Ok(_) => panic!("preparation must retain repository mutation lock"),
            Err(error) => assert!(format!("{error:#}").contains("kernel lock is held")),
        }
        let unrelated = manager
            .acquire_write_execution_lease("agent-b")
            .expect("unrelated worktree remains available");
        assert_eq!(unrelated.path(), agent_b.path);
        drop(unrelated);

        release_tx.send(()).expect("release preparation");
        publisher
            .join()
            .expect("join preparation")
            .expect("complete preparation");
        drop(
            manager
                .acquire_read_execution_lease("agent-a")
                .expect("preparation releases worktree lock"),
        );
        drop(
            RepoCommonLock::acquire(&repo_path, "merge-apply")
                .expect("preparation releases repository lock"),
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn borrowed_write_lease_publishes_without_nested_read_lease() {
        let temp = tempfile::tempdir().expect("tempdir");
        let (repo_path, manager, agent_a, _) = create_publication_lease_fixture(temp.path());
        fs::write(agent_a.path.join("README.md"), "# Borrowed authority\n")
            .expect("edit agent worktree");
        let write_lease = manager
            .acquire_write_execution_lease("agent-a")
            .expect("caller-held write lease");

        let report = publish_pr_with_write_lease(
            fake_publication_options(&repo_path, "agent-a"),
            &write_lease,
        )
        .expect("publish beneath caller-held write lease");

        assert_eq!(report.status, PrPublicationStatus::Published);
        assert!(report.created);
        assert_eq!(write_lease.record().name, "agent-a");
        manager
            .acquire_read_execution_lease("agent-a")
            .expect_err("caller retains write authority after publication returns");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn standalone_publish_excludes_same_worktree_for_full_lifecycle() {
        let temp = tempfile::tempdir().expect("tempdir");
        let (repo_path, manager, agent_a, agent_b) = create_publication_lease_fixture(temp.path());
        fs::write(agent_a.path.join("README.md"), "# Lifecycle authority\n")
            .expect("edit agent worktree");
        let (ready_tx, ready_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let publish_repo = repo_path.clone();
        let publisher = std::thread::spawn(move || {
            publish_pr_with_validation_evidence_after_lock(
                fake_publication_options(&publish_repo, "agent-a"),
                false,
                ValidationEvidenceBundle::default(),
                || {
                    ready_tx.send(()).expect("signal held publication locks");
                    release_rx
                        .recv_timeout(Duration::from_secs(5))
                        .expect("release publication");
                },
            )
        });

        ready_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("publication acquired lifecycle locks");
        manager
            .acquire_read_execution_lease("agent-a")
            .expect_err("publication writer excludes concurrent reader");
        manager
            .acquire_write_execution_lease("agent-a")
            .expect_err("publication writer excludes concurrent writer");
        let removal_error = manager
            .remove("agent-a", true, false)
            .expect_err("publication writer excludes managed removal");
        assert!(removal_error
            .to_string()
            .contains("active cooperative execution lease"));
        match RepoCommonLock::acquire(&repo_path, "merge-apply") {
            Ok(_) => panic!("publication must hold repository mutation lock"),
            Err(error) => assert!(format!("{error:#}").contains("kernel lock is held")),
        }

        let unrelated = manager
            .acquire_write_execution_lease("agent-b")
            .expect("unrelated worktree remains available");
        assert_eq!(unrelated.path(), agent_b.path);
        drop(unrelated);

        release_tx.send(()).expect("release publication lifecycle");
        let report = publisher
            .join()
            .expect("join publisher")
            .expect("complete fake publication");
        assert_eq!(report.status, PrPublicationStatus::Published);
        drop(
            manager
                .acquire_read_execution_lease("agent-a")
                .expect("publication releases worktree lease on return"),
        );
        drop(
            RepoCommonLock::acquire(&repo_path, "merge-apply")
                .expect("publication releases repository lock on return"),
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn borrowed_publication_rejects_agent_and_repository_mismatch() {
        let first = tempfile::tempdir().expect("first tempdir");
        let second = tempfile::tempdir().expect("second tempdir");
        let (first_repo, first_manager, _, _) = create_publication_lease_fixture(first.path());
        let (second_repo, _, _, _) = create_publication_lease_fixture(second.path());
        let write_lease = first_manager
            .acquire_write_execution_lease("agent-a")
            .expect("first repository write lease");

        let agent_error = preview_pr_with_validation_evidence_and_write_lease(
            fake_publication_options(&first_repo, "agent-b"),
            false,
            ValidationEvidenceBundle::default(),
            &write_lease,
        )
        .expect_err("lease for another agent must be rejected");
        assert!(agent_error
            .to_string()
            .contains("belongs to agent 'agent-a'"));

        let repo_error = publish_pr_with_write_lease(
            fake_publication_options(&second_repo, "agent-a"),
            &write_lease,
        )
        .expect_err("lease for another repository must be rejected");
        assert!(repo_error
            .to_string()
            .contains("different managed repository"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn standalone_publication_error_releases_both_locks() {
        let temp = tempfile::tempdir().expect("tempdir");
        let (repo_path, manager, agent_a, _) = create_publication_lease_fixture(temp.path());
        fs::write(agent_a.path.join("README.md"), "# Invalid claim\n")
            .expect("edit agent worktree");
        let mut options = fake_publication_options(&repo_path, "agent-a");
        options.claimed_paths = vec![PathBuf::from("../escape")];

        publish_pr_with_validation_evidence(options, false, ValidationEvidenceBundle::default())
            .expect_err("invalid claim must fail publication");

        drop(
            manager
                .acquire_read_execution_lease("agent-a")
                .expect("error releases standalone write lease"),
        );
        drop(
            RepoCommonLock::acquire(&repo_path, "merge-apply")
                .expect("error releases repository mutation lock"),
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn standalone_preview_coexists_with_reader_and_does_not_commit() {
        let temp = tempfile::tempdir().expect("tempdir");
        let (repo_path, manager, agent_a, _) = create_publication_lease_fixture(temp.path());
        fs::write(agent_a.path.join("README.md"), "# Shared preview\n")
            .expect("edit agent worktree");
        let agent_repo = Repository::open(&agent_a.path).expect("open agent repository");
        let before_head = agent_repo
            .head()
            .expect("agent HEAD")
            .target()
            .expect("direct agent HEAD");
        let existing_reader = manager
            .acquire_read_execution_lease("agent-a")
            .expect("existing shared reader");

        let report = preview_pr_with_validation_evidence(
            fake_publication_options(&repo_path, "agent-a"),
            false,
            ValidationEvidenceBundle::default(),
        )
        .expect("standalone preview shares immutable authority");

        assert_eq!(report.status, PrPublicationStatus::Preview);
        assert_eq!(
            agent_repo
                .head()
                .expect("agent HEAD after preview")
                .target()
                .expect("direct agent HEAD after preview"),
            before_head
        );
        assert!(has_uncommitted_changes(&agent_a.path).expect("dirty preview worktree"));
        manager
            .acquire_write_execution_lease("agent-a")
            .expect_err("existing reader remains held after shared preview");
        drop(existing_reader);
    }

    fn test_publication_pr_marker() -> String {
        "ab".repeat(PUBLICATION_PR_MARKER_BYTES)
    }

    fn test_publication_pr_body() -> String {
        pr_body_with_publication_marker("test publication body", &test_publication_pr_marker())
            .expect("marker-bound test PR body")
    }

    fn enterprise_test_value(host: &str, key: &str) -> Option<String> {
        match key {
            "GH_HOST" => Some(host.to_string()),
            "GH_ENTERPRISE_TOKEN" => Some("test-token".to_string()),
            _ => None,
        }
    }

    fn test_observe_operation() -> PublicationGitOperation {
        PublicationGitOperation::observe("refs/heads/test").expect("test observation operation")
    }

    fn completed_github_journal(sequence: u64) -> PublicationTransactionJournal {
        let marker = test_publication_pr_marker();
        let body = test_publication_pr_body();
        PublicationTransactionJournal {
            version: PUBLICATION_JOURNAL_VERSION,
            transaction_id: "completed-test-transaction".to_string(),
            sequence,
            agent_id: "agent-a".to_string(),
            forge: ForgeKind::Github,
            expected_oid: "1111111111111111111111111111111111111111".to_string(),
            expected_base_oid: Some("3333333333333333333333333333333333333333".to_string()),
            remote_name: "origin".to_string(),
            remote_binding_digest: "2222222222222222222222222222222222222222".to_string(),
            remote_display: "https://example.invalid/owner/repo.git".to_string(),
            remote_ref: "refs/heads/maco/review/agent-a/test".to_string(),
            remote_branch: "maco/review/agent-a/test".to_string(),
            github_repository: Some(GithubRepositoryIdentity {
                host: "example.invalid".to_string(),
                owner: "owner".to_string(),
                name: "repo".to_string(),
            }),
            pr_marker_nonce: Some(marker),
            expected_pr_title: Some("Agent agent-a changes".to_string()),
            expected_pr_body: Some(body.clone()),
            expected_pr_author: Some("publisher".to_string()),
            base: "main".to_string(),
            draft: true,
            phase: PublicationTransactionPhase::Completed,
            push_observed_oid: Some("1111111111111111111111111111111111111111".to_string()),
            pr_url: Some("https://example.invalid/owner/repo/pull/7".to_string()),
            pr_head_oid: Some("1111111111111111111111111111111111111111".to_string()),
            pr_base: Some("main".to_string()),
            pr_state: Some("OPEN".to_string()),
            pr_is_draft: Some(true),
            pr_number: Some(7),
            pr_title: Some("Agent agent-a changes".to_string()),
            pr_body: Some(body),
            pr_head_ref_name: Some("maco/review/agent-a/test".to_string()),
            pr_head_repository_owner: Some("owner".to_string()),
            pr_head_repository_name: Some("repo".to_string()),
            pr_is_cross_repository: Some(false),
            pr_author: Some("publisher".to_string()),
            create_attempted: true,
            created_by_transaction: true,
            observed_existing_pr: false,
            last_error: None,
            updated_unix_seconds: sequence,
        }
    }

    fn prepared_github_transaction(
        directory: &Path,
        create_attempted: bool,
    ) -> PublicationTransaction {
        let mut journal = completed_github_journal(0);
        journal.transaction_id = "prepared-test-transaction".to_string();
        journal.phase = PublicationTransactionPhase::PushObserved;
        journal.pr_url = None;
        journal.pr_head_oid = None;
        journal.pr_base = None;
        journal.pr_state = None;
        journal.pr_is_draft = None;
        journal.pr_number = None;
        journal.pr_title = None;
        journal.pr_body = None;
        journal.pr_head_ref_name = None;
        journal.pr_head_repository_owner = None;
        journal.pr_head_repository_name = None;
        journal.pr_is_cross_repository = None;
        journal.pr_author = None;
        journal.create_attempted = create_attempted;
        journal.created_by_transaction = false;
        journal.observed_existing_pr = false;
        PublicationTransaction {
            directory: directory.to_path_buf(),
            journal,
            remote_url: "https://example.invalid/owner/repo.git".to_string(),
            push_effect_request: None,
            pr_effect_request: None,
        }
    }

    fn exact_github_receipt(journal: &PublicationTransactionJournal) -> GithubPrResult {
        GithubPrResult {
            url: "https://example.invalid/owner/repo/pull/7".to_string(),
            head_oid: journal.expected_oid.clone(),
            base_oid: journal.expected_base_oid.clone().expect("base oid"),
            number: 7,
            base_ref_name: journal.base.clone(),
            state: "OPEN".to_string(),
            is_draft: journal.draft,
            title: journal.expected_pr_title.clone().expect("expected title"),
            body: journal.expected_pr_body.clone().expect("expected body"),
            head_ref_name: journal.remote_branch.clone(),
            head_repository_owner: "owner".to_string(),
            head_repository_name: "repo".to_string(),
            is_cross_repository: false,
            author: journal.expected_pr_author.clone().expect("expected author"),
            created: false,
        }
    }

    struct ScriptedGithubApi {
        lists: std::collections::VecDeque<Vec<GithubPrResult>>,
        views: std::collections::VecDeque<GithubPrResult>,
        create_output: Option<GithubCreateOutput>,
        create_calls: usize,
        created_title: Option<String>,
        created_body: Option<String>,
    }

    impl ScriptedGithubApi {
        fn new(
            lists: impl IntoIterator<Item = Vec<GithubPrResult>>,
            views: impl IntoIterator<Item = GithubPrResult>,
        ) -> Self {
            Self {
                lists: lists.into_iter().collect(),
                views: views.into_iter().collect(),
                create_output: Some(GithubCreateOutput {
                    stdout: Vec::new(),
                    stderr: Vec::new(),
                }),
                create_calls: 0,
                created_title: None,
                created_body: None,
            }
        }
    }

    impl GithubApi for ScriptedGithubApi {
        fn list(
            &mut self,
            _worktree_path: &Path,
            _branch: &str,
            _repository: &GithubRepositoryIdentity,
        ) -> Result<Vec<GithubPrResult>> {
            self.lists
                .pop_front()
                .context("scripted GitHub API omitted a list response")
        }

        fn view(
            &mut self,
            _worktree_path: &Path,
            _selector: &str,
            _repository: &GithubRepositoryIdentity,
        ) -> Result<GithubPrResult> {
            self.views
                .pop_front()
                .context("scripted GitHub API omitted a view response")
        }

        fn create(
            &mut self,
            _worktree_path: &Path,
            _branch: &str,
            _base: &str,
            title: &str,
            body: &str,
            _draft: bool,
            _repository: &GithubRepositoryIdentity,
        ) -> Result<GithubCreateOutput> {
            self.create_calls += 1;
            self.created_title = Some(title.to_string());
            self.created_body = Some(body.to_string());
            self.create_output
                .take()
                .context("scripted GitHub API omitted a create response")
        }
    }

    #[test]
    fn github_reconciliation_rejects_preexisting_branch_pr_as_a_front_run() {
        let temp = tempfile::tempdir().expect("tempdir");
        let mut transaction = prepared_github_transaction(temp.path(), false);
        let receipt = exact_github_receipt(&transaction.journal);
        let mut api = ScriptedGithubApi::new([vec![receipt]], []);
        let error = reconcile_github_pr_with_api_and_remote_check(
            temp.path(),
            &mut transaction,
            &mut api,
            |_, _, _| Ok(()),
        )
        .expect_err("a PR predating the create intent must fail closed");
        assert!(error.to_string().contains("front-run"));
        assert_eq!(api.create_calls, 0);
        assert!(!transaction.journal.create_attempted);
        assert!(transaction.journal.pr_url.is_none());
    }

    #[test]
    fn github_crash_reconciliation_accepts_only_exact_marker_and_provenance() {
        let wrong = tempfile::tempdir().expect("wrong tempdir");
        let mut wrong_transaction = prepared_github_transaction(wrong.path(), true);
        let mut wrong_receipt = exact_github_receipt(&wrong_transaction.journal);
        wrong_receipt.body = pr_body_with_publication_marker(
            "test publication body",
            &"cd".repeat(PUBLICATION_PR_MARKER_BYTES),
        )
        .expect("different marker body");
        let mut wrong_api = ScriptedGithubApi::new([vec![wrong_receipt.clone()]], [wrong_receipt]);
        let error = reconcile_github_pr_with_api_and_remote_check(
            wrong.path(),
            &mut wrong_transaction,
            &mut wrong_api,
            |_, _, _| Ok(()),
        )
        .expect_err("a different marker must never be adopted after a crash");
        assert!(error.to_string().contains("marker-bound"));
        assert!(wrong_transaction.journal.pr_url.is_none());

        let exact = tempfile::tempdir().expect("exact tempdir");
        let exact_journal = exact.path().join("journal");
        merge::create_private_directory(&exact_journal).expect("exact journal directory");
        let mut exact_transaction = prepared_github_transaction(&exact_journal, true);
        let exact_receipt = exact_github_receipt(&exact_transaction.journal);
        let mut exact_api = ScriptedGithubApi::new([vec![exact_receipt.clone()]], [exact_receipt]);
        let reconciled = reconcile_github_pr_with_api_and_remote_check(
            exact.path(),
            &mut exact_transaction,
            &mut exact_api,
            |_, _, _| Ok(()),
        )
        .expect("exact marker-bound receipt is the transaction's crash outcome");
        assert!(reconciled.created);
        assert_eq!(exact_api.create_calls, 0);
        assert!(exact_transaction.journal.created_by_transaction);
        assert!(!exact_transaction.journal.observed_existing_pr);
        validate_publication_journal(&exact_transaction.journal)
            .expect("reconciled receipt journal is exact");
    }

    #[test]
    fn github_create_recovery_binds_exact_title_body_author_and_head_repository() {
        let temp = tempfile::tempdir().expect("tempdir");
        let journal_directory = temp.path().join("journal");
        merge::create_private_directory(&journal_directory).expect("journal directory");
        let mut transaction = prepared_github_transaction(&journal_directory, false);
        let receipt = exact_github_receipt(&transaction.journal);
        let mut api =
            ScriptedGithubApi::new([Vec::new(), vec![receipt.clone()]], [receipt.clone()]);
        let mut remote_checks = 0usize;
        let result = reconcile_github_pr_with_api_and_remote_check(
            temp.path(),
            &mut transaction,
            &mut api,
            |_, _, _| {
                remote_checks += 1;
                Ok(())
            },
        )
        .expect("recover exact receipt after an ambiguous create response");

        assert_eq!(api.create_calls, 1);
        assert_eq!(remote_checks, 3);
        assert_eq!(
            api.created_title.as_deref(),
            transaction.journal.expected_pr_title.as_deref()
        );
        assert_eq!(
            api.created_body.as_deref(),
            transaction.journal.expected_pr_body.as_deref()
        );
        assert_eq!(result.author, "publisher");
        assert_eq!(result.head_repository_owner, "owner");
        assert_eq!(result.head_repository_name, "repo");
        assert!(!result.is_cross_repository);
        assert!(transaction.journal.created_by_transaction);
        validate_publication_journal(&transaction.journal)
            .expect("created receipt journal is exact");
    }

    fn write_test_journal_record(directory: &Path, journal: &PublicationTransactionJournal) {
        let mut bytes = serde_json::to_vec(journal).expect("serialize test journal");
        bytes.push(b'\n');
        merge::write_private_file(
            &directory.join(format!("{:020}.json", journal.sequence)),
            &bytes,
        )
        .expect("write private test journal");
    }

    #[test]
    fn publication_journal_retains_only_latest_32_of_100_retries() {
        let temp = tempfile::tempdir().expect("tempdir");
        let journal_directory = temp.path().join("journal");
        merge::create_private_directory(&journal_directory).expect("private journal directory");
        let remote_display = "https://example.invalid/repo";
        let remote_binding_digest = "2222222222222222222222222222222222222222".to_string();
        let mut transaction = PublicationTransaction {
            directory: journal_directory.clone(),
            journal: PublicationTransactionJournal {
                version: PUBLICATION_JOURNAL_VERSION,
                transaction_id: "test-transaction".to_string(),
                sequence: 0,
                agent_id: "agent-a".to_string(),
                forge: ForgeKind::Github,
                expected_oid: "1111111111111111111111111111111111111111".to_string(),
                expected_base_oid: Some("3333333333333333333333333333333333333333".to_string()),
                remote_name: "origin".to_string(),
                remote_binding_digest,
                remote_display: remote_display.to_string(),
                remote_ref: "refs/heads/maco/review/agent-a/test".to_string(),
                remote_branch: "maco/review/agent-a/test".to_string(),
                github_repository: Some(GithubRepositoryIdentity {
                    host: "example.invalid".to_string(),
                    owner: "owner".to_string(),
                    name: "repo".to_string(),
                }),
                pr_marker_nonce: Some(test_publication_pr_marker()),
                expected_pr_title: Some("Agent agent-a changes".to_string()),
                expected_pr_body: Some(test_publication_pr_body()),
                expected_pr_author: Some("publisher".to_string()),
                base: "main".to_string(),
                draft: true,
                phase: PublicationTransactionPhase::Prepared,
                push_observed_oid: None,
                pr_url: None,
                pr_head_oid: None,
                pr_base: None,
                pr_state: None,
                pr_is_draft: None,
                pr_number: None,
                pr_title: None,
                pr_body: None,
                pr_head_ref_name: None,
                pr_head_repository_owner: None,
                pr_head_repository_name: None,
                pr_is_cross_repository: None,
                pr_author: None,
                create_attempted: false,
                created_by_transaction: false,
                observed_existing_pr: false,
                last_error: None,
                updated_unix_seconds: 0,
            },
            remote_url: "https://example.invalid/owner/repo.git".to_string(),
            push_effect_request: None,
            pr_effect_request: None,
        };

        for retry in 0..100 {
            transaction.journal.last_error = Some(format!("retry {retry}"));
            transaction.persist().expect("persist retry");
        }

        let records = fs::read_dir(&journal_directory)
            .expect("read journal dir")
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.path().extension().and_then(|ext| ext.to_str()) == Some("json"))
            .collect::<Vec<_>>();
        assert_eq!(records.len(), 32);
        let latest = load_latest_publication_journal(&journal_directory)
            .expect("load latest")
            .expect("journal exists");
        assert_eq!(latest.sequence, 100);
        assert_eq!(latest.last_error.as_deref(), Some("retry 99"));
        let mut previous = latest.clone();
        previous.phase = PublicationTransactionPhase::PushObserved;
        previous.push_observed_oid = Some(previous.expected_oid.clone());
        let mut regressed = previous.clone();
        regressed.sequence += 1;
        regressed.phase = PublicationTransactionPhase::Prepared;
        assert!(
            validate_publication_journal_transition(&previous, &regressed)
                .expect_err("phase regression must fail")
                .to_string()
                .contains("phase regressed")
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for record in records {
                let mode = record
                    .metadata()
                    .expect("record metadata")
                    .permissions()
                    .mode()
                    & 0o777;
                assert_eq!(mode, 0o600);
            }
        }
    }

    #[test]
    fn publication_journal_rejects_every_noncanonical_json_record() {
        let temp = tempfile::tempdir().expect("tempdir");
        let journal_directory = temp.path().join("journal");
        merge::create_private_directory(&journal_directory).expect("private journal directory");
        merge::write_private_file(&journal_directory.join("unexpected.json"), b"{}\n")
            .expect("write private unexpected JSON record");

        assert!(load_latest_publication_journal(&journal_directory)
            .expect_err("noncanonical JSON record must fail")
            .to_string()
            .contains("canonical sequence"));
    }

    #[test]
    fn publication_journal_rejects_oversized_hardlinked_and_excess_records() {
        let temp = tempfile::tempdir().expect("tempdir");

        let oversized_directory = temp.path().join("oversized");
        merge::create_private_directory(&oversized_directory)
            .expect("private oversized journal directory");
        let oversized_path = oversized_directory.join("00000000000000000001.json");
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let oversized = options
            .open(&oversized_path)
            .expect("create oversized journal");
        oversized
            .set_len(PUBLICATION_JOURNAL_MAX_RECORD_BYTES + 1)
            .expect("size oversized journal");
        assert!(load_latest_publication_journal(&oversized_directory)
            .expect_err("oversized journal must fail")
            .to_string()
            .contains("invalid size"));

        let linked_directory = temp.path().join("linked");
        merge::create_private_directory(&linked_directory)
            .expect("private linked journal directory");
        let linked_path = linked_directory.join("00000000000000000001.json");
        merge::write_private_file(&linked_path, b"{}\n").expect("write linked journal source");
        fs::hard_link(&linked_path, temp.path().join("journal-hardlink"))
            .expect("link journal record");
        assert!(load_latest_publication_journal(&linked_directory)
            .expect_err("hardlinked journal must fail")
            .to_string()
            .contains("multiple links"));

        let excess_directory = temp.path().join("excess");
        merge::create_private_directory(&excess_directory)
            .expect("private excess journal directory");
        for sequence in 1..=(PUBLICATION_JOURNAL_MAX_RECORDS as u64 + 1) {
            write_test_journal_record(&excess_directory, &completed_github_journal(sequence));
        }
        assert!(load_latest_publication_journal(&excess_directory)
            .expect_err("excess journal records must fail")
            .to_string()
            .contains("record safety limit"));

        let entry_directory = temp.path().join("entries");
        merge::create_private_directory(&entry_directory)
            .expect("private entry-bound journal directory");
        for entry in 0..=PUBLICATION_JOURNAL_MAX_DIRECTORY_ENTRIES {
            merge::write_private_file(&entry_directory.join(format!("entry-{entry}")), b"x")
                .expect("write bounded journal directory entry");
        }
        assert!(load_latest_publication_journal(&entry_directory)
            .expect_err("excess journal directory entries must fail")
            .to_string()
            .contains("entry safety limit"));
    }

    #[cfg(unix)]
    #[test]
    fn publication_journal_rejects_symlinked_and_exposed_records() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let temp = tempfile::tempdir().expect("tempdir");
        let symlink_directory = temp.path().join("symlink");
        merge::create_private_directory(&symlink_directory)
            .expect("private symlink journal directory");
        let target = temp.path().join("target.json");
        merge::write_private_file(&target, b"{}\n").expect("write journal target");
        symlink(&target, symlink_directory.join("00000000000000000001.json"))
            .expect("symlink journal record");
        assert!(load_latest_publication_journal(&symlink_directory)
            .expect_err("symlinked journal must fail")
            .to_string()
            .contains("real regular file"));

        let exposed_directory = temp.path().join("exposed");
        merge::create_private_directory(&exposed_directory)
            .expect("private exposed journal directory");
        let exposed = exposed_directory.join("00000000000000000001.json");
        merge::write_private_file(&exposed, b"{}\n").expect("write exposed journal");
        fs::set_permissions(&exposed, fs::Permissions::from_mode(0o644))
            .expect("expose journal mode");
        assert!(load_latest_publication_journal(&exposed_directory)
            .expect_err("exposed journal must fail")
            .to_string()
            .contains("unsafe mode"));
    }

    #[test]
    fn publication_journal_rejects_sequence_gaps_and_receipt_changes() {
        let temp = tempfile::tempdir().expect("tempdir");
        let journal_directory = temp.path().join("journal");
        merge::create_private_directory(&journal_directory).expect("private journal directory");
        write_test_journal_record(&journal_directory, &completed_github_journal(1));
        write_test_journal_record(&journal_directory, &completed_github_journal(3));
        assert!(load_latest_publication_journal(&journal_directory)
            .expect_err("retained journal gap must fail")
            .to_string()
            .contains("not contiguous"));

        let previous = completed_github_journal(1);
        let mut changed = completed_github_journal(2);
        changed.pr_url = Some("https://example.invalid/owner/repo/pull/8".to_string());
        changed.pr_number = Some(8);
        validate_publication_journal(&changed).expect("changed receipt is independently valid");
        assert!(validate_publication_journal_transition(&previous, &changed)
            .expect_err("receipt identity change must fail")
            .to_string()
            .contains("immutable PR receipt"));
    }

    #[test]
    fn publication_journal_enforces_completed_github_receipt_contract() {
        let valid = completed_github_journal(1);
        validate_publication_journal(&valid).expect("valid completed receipt");

        let mut wrong_head = valid.clone();
        wrong_head.pr_head_oid = Some("4444444444444444444444444444444444444444".to_string());
        assert!(validate_publication_journal(&wrong_head)
            .expect_err("wrong persisted head must fail")
            .to_string()
            .contains("PR head"));

        let mut wrong_base = valid.clone();
        wrong_base.pr_base = Some("release".to_string());
        assert!(validate_publication_journal(&wrong_base)
            .expect_err("wrong persisted base must fail")
            .to_string()
            .contains("PR base"));

        let mut missing_number = valid.clone();
        missing_number.pr_number = None;
        assert!(validate_publication_journal(&missing_number)
            .expect_err("missing persisted PR number must fail")
            .to_string()
            .contains("number"));

        let mut wrong_draft = valid;
        wrong_draft.pr_is_draft = Some(false);
        assert!(validate_publication_journal(&wrong_draft)
            .expect_err("changed persisted draft state must fail")
            .to_string()
            .contains("draft state"));
    }

    #[test]
    fn github_receipt_requires_matching_base_and_open_state() {
        let remote_display = "https://example.invalid/repo";
        let remote_binding_digest = "2222222222222222222222222222222222222222".to_string();
        let journal = PublicationTransactionJournal {
            version: PUBLICATION_JOURNAL_VERSION,
            transaction_id: "receipt-contract".to_string(),
            sequence: 1,
            agent_id: "agent-a".to_string(),
            forge: ForgeKind::Github,
            expected_oid: "1111111111111111111111111111111111111111".to_string(),
            expected_base_oid: Some("3333333333333333333333333333333333333333".to_string()),
            remote_name: "origin".to_string(),
            remote_binding_digest,
            remote_display: remote_display.to_string(),
            remote_ref: "refs/heads/maco/review/agent-a/test".to_string(),
            remote_branch: "maco/review/agent-a/test".to_string(),
            github_repository: Some(GithubRepositoryIdentity {
                host: "example.invalid".to_string(),
                owner: "owner".to_string(),
                name: "repo".to_string(),
            }),
            pr_marker_nonce: Some(test_publication_pr_marker()),
            expected_pr_title: Some("Agent agent-a changes".to_string()),
            expected_pr_body: Some(test_publication_pr_body()),
            expected_pr_author: Some("publisher".to_string()),
            base: "main".to_string(),
            draft: true,
            phase: PublicationTransactionPhase::Prepared,
            push_observed_oid: None,
            pr_url: None,
            pr_head_oid: None,
            pr_base: None,
            pr_state: None,
            pr_is_draft: None,
            pr_number: None,
            pr_title: None,
            pr_body: None,
            pr_head_ref_name: None,
            pr_head_repository_owner: None,
            pr_head_repository_name: None,
            pr_is_cross_repository: None,
            pr_author: None,
            create_attempted: false,
            created_by_transaction: false,
            observed_existing_pr: false,
            last_error: None,
            updated_unix_seconds: 1,
        };
        let mut receipt = GithubPrResult {
            url: "https://example.invalid/owner/repo/pull/1".to_string(),
            head_oid: journal.expected_oid.clone(),
            base_oid: journal.expected_base_oid.clone().expect("base oid"),
            number: 1,
            base_ref_name: "release".to_string(),
            state: "OPEN".to_string(),
            is_draft: true,
            title: "Agent agent-a changes".to_string(),
            body: test_publication_pr_body(),
            head_ref_name: "maco/review/agent-a/test".to_string(),
            head_repository_owner: "owner".to_string(),
            head_repository_name: "repo".to_string(),
            is_cross_repository: false,
            author: "publisher".to_string(),
            created: false,
        };
        assert!(validate_github_receipt_contract(&receipt, &journal)
            .expect_err("wrong base must fail")
            .to_string()
            .contains("baseRefName"));
        receipt.base_ref_name = "main".to_string();
        receipt.state = "CLOSED".to_string();
        assert!(validate_github_receipt_contract(&receipt, &journal)
            .expect_err("closed PR must fail")
            .to_string()
            .contains("not OPEN"));
    }

    #[test]
    fn github_receipt_requires_exact_marker_head_repository_and_author_provenance() {
        let journal = completed_github_journal(1);
        let exact = exact_github_receipt(&journal);
        validate_github_receipt_contract(&exact, &journal).expect("exact receipt");

        let mut cases = Vec::new();
        let mut changed = exact.clone();
        changed.title.push('!');
        cases.push(("title", changed));
        let mut changed = exact.clone();
        changed.body.push_str("different");
        cases.push(("body", changed));
        let mut changed = exact.clone();
        changed.head_ref_name = "maco/review/agent-a/front-run".to_string();
        cases.push(("head ref", changed));
        let mut changed = exact.clone();
        changed.head_repository_owner = "attacker".to_string();
        cases.push(("head owner", changed));
        let mut changed = exact.clone();
        changed.head_repository_name = "fork".to_string();
        cases.push(("head repository", changed));
        let mut changed = exact.clone();
        changed.is_cross_repository = true;
        cases.push(("cross repository", changed));
        let mut changed = exact;
        changed.author = "unexpected-bot[bot]".to_string();
        cases.push(("author", changed));

        for (label, changed) in cases {
            assert!(
                validate_github_receipt_contract(&changed, &journal).is_err(),
                "changed {label} provenance must fail"
            );
        }
    }

    #[test]
    fn publication_journal_remote_binding_is_keyed_and_does_not_serialize_credentials() {
        let raw = "https://user-one:super-secret@example.invalid/repo.git?token=query-secret#fragment-secret";
        let equivalent =
            "https://user-two:different-secret@example.invalid/repo.git?token=other#different";
        let display = redact_remote_url(raw);
        let equivalent_display = redact_remote_url(equivalent);
        assert_eq!(
            display,
            "https://<redacted>@example.invalid/repo.git?<redacted>#<redacted>"
        );
        assert_eq!(display, equivalent_display);
        let secret = [7_u8; REMOTE_BINDING_SECRET_BYTES];
        let other_secret = [8_u8; REMOTE_BINDING_SECRET_BYTES];
        let digest = publication_remote_binding_digest(&secret, "origin", raw)
            .expect("digest remote binding");
        let equivalent_digest = publication_remote_binding_digest(&secret, "origin", equivalent)
            .expect("digest equivalent remote binding");
        let other_key_digest = publication_remote_binding_digest(&other_secret, "origin", raw)
            .expect("digest remote binding with another key");
        assert_ne!(digest, equivalent_digest);
        assert_ne!(digest, other_key_digest);
        let serialized = serde_json::json!({
            "remote_binding_digest": digest,
            "remote_display": display,
        })
        .to_string();
        assert!(!serialized.contains("user-one"));
        assert!(!serialized.contains("super-secret"));
        assert!(!serialized.contains("query-secret"));
        assert!(!serialized.contains("fragment-secret"));
        assert!(serialized.contains("<redacted>"));

        assert!(publication_remote_transport(raw).is_err());
        assert!(publication_remote_transport(equivalent).is_err());
    }

    #[test]
    fn github_repository_binding_accepts_only_https_without_url_credentials() {
        let https = github_repository_identity("https://github.example/Owner/repo.git")
            .expect("parse HTTPS origin");
        assert_eq!(https.selector(), "github.example/owner/repo");
        assert!(github_repository_identity("/tmp/local-origin.git").is_err());
        assert!(github_repository_identity("ssh://git@github.example/Owner/repo.git").is_err());
        assert!(github_repository_identity("git@github.example:Owner/repo.git").is_err());
        assert!(
            github_repository_identity("https://user:secret@github.example/Owner/repo.git")
                .is_err()
        );
        assert!(github_repository_identity("https://github.example/group/owner/repo.git").is_err());
    }

    #[test]
    fn github_receipt_url_is_bound_to_repository_and_number() {
        let repository = GithubRepositoryIdentity {
            host: "github.example".to_string(),
            owner: "owner".to_string(),
            name: "repo".to_string(),
        };
        validate_github_receipt_url("https://github.example/owner/repo/pull/7", &repository, 7)
            .expect("matching receipt URL");
        assert!(validate_github_receipt_url(
            "https://github.example/other/repo/pull/7",
            &repository,
            7,
        )
        .expect_err("wrong repository must fail")
        .to_string()
        .contains("bound forge repository"));
        assert!(validate_github_receipt_url(
            "https://github.example/owner/repo/pull/8",
            &repository,
            7,
        )
        .is_err());
        assert!(validate_github_receipt_url(
            "https://github.example/owner/repo/pull/7?token=x",
            &repository,
            7,
        )
        .is_err());
        assert!(validate_github_receipt_url(
            "https://github.example/owner/repo/pull/7#fragment",
            &repository,
            7,
        )
        .is_err());
        assert!(validate_github_receipt_url(
            "https://github.example/owner/repo/pull/0",
            &repository,
            0,
        )
        .is_err());
        assert!(validate_github_receipt_url(
            "https://github.example/owner/repo/pull/007",
            &repository,
            7,
        )
        .is_err());
    }

    #[test]
    fn github_issue_receipt_requires_exact_nonzero_bound_url() {
        let repository = GithubRepositoryIdentity {
            host: "github.example".to_string(),
            owner: "owner".to_string(),
            name: "repo".to_string(),
        };
        assert_eq!(
            validate_github_issue_receipt_url(
                "https://github.example/owner/repo/issues/9",
                &repository,
                9,
            )
            .expect("valid issue receipt"),
            "https://github.example/owner/repo/issues/9"
        );
        for invalid in [
            "",
            "https://github.example/owner/repo/issues",
            "https://github.example/owner/repo/issues/0",
            "https://github.example/owner/repo/issues/009",
            "https://github.example/owner/repo/issues/8",
            "https://github.example/other/repo/issues/9",
            "https://github.example/owner/repo/issues/9?token=x",
            "https://github.example/owner/repo/issues/9#fragment",
            "http://github.example/owner/repo/issues/9",
        ] {
            assert!(
                validate_github_issue_receipt_url(invalid, &repository, 9).is_err(),
                "invalid issue receipt passed: {invalid}"
            );
        }
    }

    #[test]
    fn github_pr_receipt_parser_bounds_strings_and_requires_canonical_values() {
        let valid = serde_json::json!({
            "url": "https://github.example/owner/repo/pull/7",
            "headRefOid": "1111111111111111111111111111111111111111",
            "baseRefOid": "2222222222222222222222222222222222222222",
            "number": 7,
            "baseRefName": "main",
            "state": "OPEN",
            "isDraft": true,
            "title": "Agent agent-a changes",
            "body": test_publication_pr_body(),
            "headRefName": "maco/review/agent-a/test",
            "headRepository": {
                "name": "repo",
                "nameWithOwner": "owner/repo"
            },
            "headRepositoryOwner": { "login": "owner" },
            "isCrossRepository": false,
            "author": { "login": "publisher" },
        });
        github_pr_receipt_from_json(&valid).expect("valid PR receipt");

        let mut invalid = valid.clone();
        invalid["url"] = serde_json::json!("https://github.example/owner/repo/pull/7?x=1");
        assert!(github_pr_receipt_from_json(&invalid).is_err());
        let mut invalid = valid.clone();
        invalid["number"] = serde_json::json!(0);
        assert!(github_pr_receipt_from_json(&invalid).is_err());
        let mut invalid = valid.clone();
        invalid["headRefOid"] = serde_json::json!("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        assert!(github_pr_receipt_from_json(&invalid).is_err());
        let mut invalid = valid.clone();
        invalid["baseRefName"] = serde_json::json!("a".repeat(MAX_GITHUB_RECEIPT_STRING_BYTES + 1));
        assert!(github_pr_receipt_from_json(&invalid).is_err());
        let mut invalid = valid.clone();
        invalid["body"] = serde_json::json!("a".repeat(MAX_GITHUB_RECEIPT_BODY_BYTES + 1));
        assert!(github_pr_receipt_from_json(&invalid).is_err());
        let excessive = serde_json::Value::Array(
            std::iter::repeat_n(valid, MAX_GITHUB_PR_LIST_RECEIPTS + 1).collect(),
        );
        assert!(github_pr_list_from_json(&excessive).is_err());
    }

    #[test]
    fn invalid_github_receipt_is_not_persisted_before_contract_checks() {
        let temp = tempfile::tempdir().expect("tempdir");
        let mut transaction = PublicationTransaction {
            directory: temp.path().to_path_buf(),
            journal: PublicationTransactionJournal {
                version: PUBLICATION_JOURNAL_VERSION,
                transaction_id: "invalid-receipt".to_string(),
                sequence: 0,
                agent_id: "agent-a".to_string(),
                forge: ForgeKind::Github,
                expected_oid: "1111111111111111111111111111111111111111".to_string(),
                expected_base_oid: Some("2222222222222222222222222222222222222222".to_string()),
                remote_name: "origin".to_string(),
                remote_binding_digest: "3333333333333333333333333333333333333333".to_string(),
                remote_display: "https://github.example/owner/repo.git".to_string(),
                remote_ref: "refs/heads/maco/review/agent-a/test".to_string(),
                remote_branch: "maco/review/agent-a/test".to_string(),
                github_repository: Some(GithubRepositoryIdentity {
                    host: "github.example".to_string(),
                    owner: "owner".to_string(),
                    name: "repo".to_string(),
                }),
                pr_marker_nonce: Some(test_publication_pr_marker()),
                expected_pr_title: Some("Agent agent-a changes".to_string()),
                expected_pr_body: Some(test_publication_pr_body()),
                expected_pr_author: Some("publisher".to_string()),
                base: "main".to_string(),
                draft: true,
                phase: PublicationTransactionPhase::PushObserved,
                push_observed_oid: Some("1111111111111111111111111111111111111111".to_string()),
                pr_url: None,
                pr_head_oid: None,
                pr_base: None,
                pr_state: None,
                pr_is_draft: None,
                pr_number: None,
                pr_title: None,
                pr_body: None,
                pr_head_ref_name: None,
                pr_head_repository_owner: None,
                pr_head_repository_name: None,
                pr_is_cross_repository: None,
                pr_author: None,
                create_attempted: true,
                created_by_transaction: false,
                observed_existing_pr: false,
                last_error: None,
                updated_unix_seconds: 0,
            },
            remote_url: "https://github.example/owner/repo.git".to_string(),
            push_effect_request: None,
            pr_effect_request: None,
        };
        let receipt = GithubPrResult {
            url: "https://github.example/owner/repo/pull/7".to_string(),
            head_oid: transaction.journal.expected_oid.clone(),
            base_oid: "4444444444444444444444444444444444444444".to_string(),
            number: 7,
            base_ref_name: "main".to_string(),
            state: "OPEN".to_string(),
            is_draft: true,
            title: "Agent agent-a changes".to_string(),
            body: test_publication_pr_body(),
            head_ref_name: "maco/review/agent-a/test".to_string(),
            head_repository_owner: "owner".to_string(),
            head_repository_name: "repo".to_string(),
            is_cross_repository: false,
            author: "publisher".to_string(),
            created: false,
        };

        let error = verify_github_receipt_with_remote_check(
            temp.path(),
            &mut transaction,
            receipt,
            true,
            false,
            |_, _, _| Ok(()),
        )
        .expect_err("wrong base receipt must fail before persistence");

        assert!(error.to_string().contains("baseRefOid"));
        assert_eq!(transaction.journal.sequence, 0);
        assert_eq!(
            transaction.journal.phase,
            PublicationTransactionPhase::PushObserved
        );
        assert!(transaction.journal.pr_url.is_none());
        assert_eq!(
            fs::read_dir(temp.path()).expect("read journal dir").count(),
            0
        );
    }

    #[test]
    fn github_command_environment_is_an_explicit_data_auth_allowlist() {
        let temp = tempfile::tempdir().expect("tempdir");
        let repo_path = temp.path().join("repo");
        Repository::init(&repo_path).expect("init repo");
        let repository = GithubRepositoryIdentity {
            host: "github.example".to_string(),
            owner: "owner".to_string(),
            name: "repo".to_string(),
        };
        let context = GhCommandContext::create_with_token_source(&repo_path, &repository, |key| {
            enterprise_test_value("github.example", key)
        })
        .expect("create gh context");
        for key in [
            "GH_REPO",
            "GH_HOST",
            "GH_DEBUG",
            "GH_FORCE_TTY",
            "GH_PAGER",
            "HOME",
            "HTTPS_PROXY",
            "ALL_PROXY",
            "SSL_CERT_FILE",
            "SSL_CERT_DIR",
            "GIT_SSL_CAINFO",
            "GIT_SSL_CAPATH",
            "GH_TOKEN",
            "GITHUB_TOKEN",
            "GH_ENTERPRISE_TOKEN",
            "GITHUB_ENTERPRISE_TOKEN",
            "GIT_CONFIG_NOSYSTEM",
            "GIT_CONFIG_GLOBAL",
        ] {
            assert!(
                !context.environment.contains_key(key),
                "unexpected inherited routing variable {key}"
            );
        }
        assert_eq!(
            context
                .environment
                .get("GH_PROMPT_DISABLED")
                .map(String::as_str),
            Some("1")
        );
        assert_eq!(
            context.environment.get("GH_CONFIG_DIR").map(String::as_str),
            context.runtime_directory.path().to_str()
        );
    }

    #[test]
    fn publication_git_uses_only_private_path_scoped_basic_auth_config() {
        let temp = tempfile::tempdir().expect("tempdir");
        let repo_path = temp.path().join("repo");
        Repository::init(&repo_path).expect("init repo");
        let raw = "https://example.invalid/owner/repo";
        let context = PublicationGitContext::create_with_token_source(
            &repo_path,
            raw,
            test_observe_operation(),
            |key| enterprise_test_value("example.invalid", key),
        )
        .expect("create publication Git context");
        let args = context.command_args(vec![
            OsString::from("ls-remote"),
            OsString::from("--refs"),
            OsString::from("maco-publication"),
            OsString::from("refs/heads/test"),
        ]);
        let argv = args
            .iter()
            .map(|argument| argument.to_string_lossy())
            .collect::<Vec<_>>()
            .join(" ");
        assert!(!argv.contains(raw));
        assert!(!argv.contains("test-token"));
        assert!(!context
            .environment
            .values()
            .any(|value| value.contains("test-token")));
        let config = git2::Config::open(&context.directory.join("config"))
            .expect("open private publication config");
        let header = config
            .get_string("http.https://example.invalid/owner/repo.git.extraheader")
            .expect("scoped auth header");
        assert_eq!(
            header,
            "Authorization: Basic eC1hY2Nlc3MtdG9rZW46dGVzdC10b2tlbg=="
        );
        assert_eq!(
            config
                .get_string("remote.maco-publication.url")
                .expect("bound remote"),
            "https://example.invalid/owner/repo.git"
        );
        assert_eq!(
            config
                .get_string("http.followredirects")
                .expect("redirect setting"),
            "false"
        );
        assert!(config.get_bool("http.sslverify").expect("TLS setting"));
        assert_eq!(config.get_string("http.proxy").expect("proxy setting"), "");
        assert_eq!(
            config
                .get_string("credential.helper")
                .expect("credential helper setting"),
            ""
        );
    }

    #[test]
    fn publication_profiles_expose_only_required_config_and_git_objects() {
        let temp = tempfile::tempdir().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let repo = Repository::init(&repo_path).expect("init repo");
        let context = PublicationGitContext::create_with_token_source(
            &repo_path,
            "https://github.example/owner/repo.git",
            test_observe_operation(),
            |key| enterprise_test_value("github.example", key),
        )
        .expect("create publication context");
        let PublicationGitBoundary::Https(profile) = &context.boundary;
        assert_eq!(
            profile.visible_read_only_roots(),
            &[context.directory.join("objects")]
        );
        assert_eq!(profile.visible_read_only_files().len(), 2);
        let state = fs::canonicalize(repo.commondir().join("maco/state")).expect("state");
        assert!(profile.hidden_roots().contains(&state));
        assert!(profile
            .hidden_roots()
            .contains(&fs::canonicalize(&repo_path).expect("repo root")));

        let repository = GithubRepositoryIdentity {
            host: "github.example".to_string(),
            owner: "owner".to_string(),
            name: "repo".to_string(),
        };
        let gh = GhCommandContext::create_with_token_source(&repo_path, &repository, |key| {
            enterprise_test_value("github.example", key)
        })
        .expect("create gh context");
        assert!(gh.profile.visible_read_only_roots().is_empty());
        assert_eq!(gh.profile.visible_read_only_files().len(), 1);
        assert!(gh.profile.hidden_roots().contains(&state));
    }

    #[test]
    fn missing_https_token_cleans_private_runtime_without_residue() {
        let temp = tempfile::tempdir().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let repo = Repository::init(&repo_path).expect("init repo");
        merge::ensure_repo_common_state_directory(&repo).expect("state");
        let runtime_root = merge::trusted_runtime_root(&repo_path).expect("runtime root");
        let before = fs::read_dir(&runtime_root)
            .expect("runtime root")
            .map(|entry| entry.expect("runtime entry").file_name())
            .collect::<BTreeSet<_>>();
        assert!(PublicationGitContext::create_with_token_source(
            &repo_path,
            "https://github.example/owner/repo.git",
            test_observe_operation(),
            |key| (key == "GH_HOST").then(|| "github.example".to_string()),
        )
        .is_err());
        let after = fs::read_dir(&runtime_root)
            .expect("runtime root after failure")
            .map(|entry| entry.expect("runtime entry after failure").file_name())
            .collect::<BTreeSet<_>>();
        assert!(
            after.is_subset(&before),
            "failed setup left a new private runtime entry: {:?}",
            after.difference(&before).collect::<Vec<_>>()
        );
    }

    #[test]
    fn private_config_in_place_mutation_and_hardlink_are_detected_before_spawn() {
        let temp = tempfile::tempdir().expect("tempdir");
        let repo_path = temp.path().join("repo");
        Repository::init(&repo_path).expect("init repo");
        let context = PublicationGitContext::create_with_token_source(
            &repo_path,
            "https://github.example/owner/repo.git",
            test_observe_operation(),
            |key| enterprise_test_value("github.example", key),
        )
        .expect("create publication context");
        let config_path = context.directory.join("config");
        let mut original = fs::read(&config_path).expect("read config");
        fs::write(&config_path, b"[core]\n\tbare = true\n").expect("mutate config in place");
        assert!(verify_private_config_files(&context.config_files).is_err());
        merge::write_private_file(&context.directory.join("replacement"), &original)
            .expect("write replacement");
        fs::remove_file(&config_path).expect("remove mutated config");
        fs::rename(context.directory.join("replacement"), &config_path)
            .expect("restore config path with changed inode");
        assert!(verify_private_config_files(&context.config_files).is_err());

        let hardlink = context.directory.join("config-hardlink");
        fs::hard_link(&config_path, &hardlink).expect("hardlink config");
        assert!(capture_private_config_file(&config_path).is_err());
        fs::remove_file(hardlink).expect("remove hardlink before secret cleanup");
        zeroize_bytes(&mut original);
    }

    #[cfg(unix)]
    #[test]
    fn private_network_configs_are_verifiably_erased_before_explicit_runtime_close() {
        let temp = tempfile::tempdir().expect("tempdir");
        let repo_path = temp.path().join("repo");
        Repository::init(&repo_path).expect("init repo");
        let mut git = PublicationGitContext::create_with_token_source(
            &repo_path,
            "https://github.example/owner/repo.git",
            test_observe_operation(),
            |key| enterprise_test_value("github.example", key),
        )
        .expect("create publication context");
        let git_runtime = git.directory.clone();
        let git_config_paths = git
            .config_files
            .iter()
            .map(|identity| (identity.path.clone(), identity.bytes.len()))
            .collect::<Vec<_>>();
        assert!(git_config_paths.iter().any(|(path, _)| {
            fs::read(path).is_ok_and(|bytes| {
                bytes
                    .windows(b"Authorization".len())
                    .any(|part| part == b"Authorization")
            })
        }));
        erase_private_config_files(&mut git.config_files).expect("verified Git config erasure");
        for (path, length) in &git_config_paths {
            let bytes = fs::read(path).expect("read erased Git config");
            assert_eq!(bytes.len(), *length);
            assert!(bytes.iter().all(|byte| *byte == 0));
        }
        git.close().expect("close erased Git runtime");
        assert!(!git_runtime.exists());

        let repository = GithubRepositoryIdentity {
            host: "github.example".to_string(),
            owner: "owner".to_string(),
            name: "repo".to_string(),
        };
        let mut gh = GhCommandContext::create_with_token_source(&repo_path, &repository, |key| {
            enterprise_test_value("github.example", key)
        })
        .expect("create gh context");
        let gh_runtime = gh.runtime_directory.path().to_path_buf();
        let gh_config_paths = gh
            .config_files
            .iter()
            .map(|identity| (identity.path.clone(), identity.bytes.len()))
            .collect::<Vec<_>>();
        erase_private_config_files(&mut gh.config_files).expect("verified gh config erasure");
        for (path, length) in &gh_config_paths {
            let bytes = fs::read(path).expect("read erased gh config");
            assert_eq!(bytes.len(), *length);
            assert!(bytes.iter().all(|byte| *byte == 0));
        }
        gh.close().expect("close erased gh runtime");
        assert!(!gh_runtime.exists());
    }

    #[test]
    fn publication_remote_rejects_ambiguous_encoded_query_and_fragment_credentials() {
        assert!(validate_publication_remote_url(
            "https://user:secret@example.invalid/repo.git?token=secret"
        )
        .is_err());
        assert!(validate_publication_remote_url(
            "https://user:secret@example.invalid/repo.git#secret"
        )
        .is_err());
        assert!(
            validate_publication_remote_url("https://user:abc%64ef@example.invalid/repo.git")
                .is_err()
        );
    }

    #[test]
    fn publication_remote_accepts_only_bounded_canonical_https() {
        assert!(matches!(
            publication_remote_transport("https://github.example/owner/repo")
                .expect("classify HTTPS remote"),
            PublicationRemoteTransport::Https { command_url, .. }
                if command_url == "https://github.example/owner/repo.git"
        ));
        assert!(matches!(
            publication_remote_transport("https://github.com:443/owner/repo")
                .expect("normalize canonical public HTTPS port"),
            PublicationRemoteTransport::Https { host, command_url, .. }
                if host == "github.com" && command_url == "https://github.com/owner/repo.git"
        ));
        for remote in [
            "https://github.com:0443/owner/repo.git",
            "https://github.com:444/owner/repo.git",
        ] {
            assert!(
                publication_remote_transport(remote).is_err(),
                "noncanonical public GitHub authority must fail: {remote}"
            );
        }

        for remote in [
            "ssh://github.example/owner/repo.git",
            "ssh://git@github.example:2222/owner/repo.git",
            "git+ssh://github.example/owner/repo.git",
            "ssh+git://git@github.example/owner/repo.git",
            "github.example:owner/repo.git",
            "git@github.example:owner/repo.git",
            "[2001:db8::1]:owner/repo.git",
            "git@[2001:db8::1]:owner/repo.git",
            "/tmp/repo.git",
            "file:///tmp/repo.git",
            "../repo.git",
            r"C:\\repo.git",
            "http://github.example/owner/repo.git",
            "git://github.example/owner/repo.git",
            "ext://host/repo",
            "SSH://host/repo",
            "host::remote-helper",
            "ssh://user@@host/repo",
            "ssh://[2001:db8::1/repo",
            "host:",
            "https://user@github.example/owner/repo.git",
            "https://github.example/owner/repo.git?token=x",
            "https://github.example/owner/repo.git#fragment",
            "https://github.example/owner/%72epo.git",
        ] {
            assert!(
                publication_remote_transport(remote).is_err(),
                "ambiguous remote must fail: {remote}"
            );
        }
    }

    #[test]
    fn publication_object_store_rejects_alternates_promisor_and_partial_clone_inputs() {
        let temp = tempfile::tempdir().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let repo = Repository::init(&repo_path).expect("init repo");
        let objects = fs::canonicalize(repo.commondir().join("objects")).expect("objects");
        validate_publication_object_store_is_self_contained(&repo, &objects)
            .expect("ordinary object store");

        let alternates = objects.join("info/alternates");
        fs::write(&alternates, b"/tmp/escape\n").expect("write alternates");
        assert!(validate_publication_object_store_is_self_contained(&repo, &objects).is_err());
        fs::remove_file(&alternates).expect("remove alternates");

        let promisor = objects.join("pack/pack-test.promisor");
        fs::write(&promisor, b"").expect("write promisor marker");
        assert!(validate_publication_object_store_is_self_contained(&repo, &objects).is_err());
        fs::remove_file(&promisor).expect("remove promisor marker");

        repo.config()
            .expect("repo config")
            .set_str("extensions.partialClone", "origin")
            .expect("set partial clone extension");
        assert!(validate_publication_object_store_is_self_contained(&repo, &objects).is_err());
    }

    #[test]
    fn private_publication_object_database_contains_only_exact_reachable_closure() {
        let temp = tempfile::tempdir().expect("tempdir");
        let source = Repository::init_bare(temp.path().join("source.git")).expect("source repo");
        let destination =
            Repository::init_bare(temp.path().join("destination.git")).expect("destination repo");
        let blob = source
            .blob(b"reachable publication content\n")
            .expect("blob");
        let gitlink =
            Oid::from_str("7777777777777777777777777777777777777777").expect("gitlink oid");
        let mut tree = source.treebuilder(None).expect("tree builder");
        tree.insert("README.md", blob, 0o100644)
            .expect("insert reachable blob");
        tree.insert("vendor", gitlink, 0o160000)
            .expect("insert non-traversed gitlink");
        let tree_oid = tree.write().expect("write tree");
        let tree = source.find_tree(tree_oid).expect("find tree");
        let signature =
            git2::Signature::now("maco test", "maco-test@example.invalid").expect("signature");
        let commit = source
            .commit(None, &signature, &signature, "candidate", &tree, &[])
            .expect("commit candidate");
        let unreachable = source
            .blob(b"unreachable local secret\n")
            .expect("extra blob");

        let seal =
            materialize_publication_object_closure(&source, &destination, &commit.to_string())
                .expect("materialize exact publication closure");

        assert_eq!(seal.expected_oid, commit);
        assert_eq!(seal.object_ids, BTreeSet::from([commit, tree_oid, blob]));
        assert!(destination.find_object(commit, None).is_ok());
        assert!(destination.find_object(tree_oid, None).is_ok());
        assert!(destination.find_object(blob, None).is_ok());
        assert!(destination.find_object(gitlink, None).is_err());
        assert!(destination.find_object(unreachable, None).is_err());
        verify_private_publication_object_closure(&destination, &seal)
            .expect("private closure remains exact");

        destination
            .blob(b"object outside sealed closure")
            .expect("inject extra private object");
        assert!(
            verify_private_publication_object_closure(&destination, &seal)
                .expect_err("extra private object must break the seal")
                .to_string()
                .contains("outside the exact closure")
        );
    }

    #[test]
    fn publication_closure_rejects_duplicate_parents_cycles_and_excessive_tree_depth() {
        let temp = tempfile::tempdir().expect("tempdir");
        let source = Repository::init_bare(temp.path().join("source.git")).expect("source repo");
        let destination =
            Repository::init_bare(temp.path().join("destination.git")).expect("destination repo");
        let signature =
            git2::Signature::now("maco test", "maco-test@example.invalid").expect("signature");
        let empty_tree_oid = source
            .treebuilder(None)
            .expect("empty tree")
            .write()
            .expect("write empty tree");
        let empty_tree = source.find_tree(empty_tree_oid).expect("find empty tree");
        let root_oid = source
            .commit(None, &signature, &signature, "root", &empty_tree, &[])
            .expect("root commit");
        let root = source.find_commit(root_oid).expect("find root commit");
        let duplicate_parent = source
            .commit(
                None,
                &signature,
                &signature,
                "duplicate parent",
                &empty_tree,
                &[&root, &root],
            )
            .expect("write duplicate-parent commit");
        let duplicate_error = match materialize_publication_object_closure(
            &source,
            &destination,
            &duplicate_parent.to_string(),
        ) {
            Ok(_) => panic!("duplicate commit parent must fail"),
            Err(error) => error,
        };
        assert!(duplicate_error
            .to_string()
            .contains("self or duplicate parent"));

        let first = Oid::from_str("1111111111111111111111111111111111111111").expect("first oid");
        let second = Oid::from_str("2222222222222222222222222222222222222222").expect("second oid");
        let cycle = BTreeMap::from([(first, vec![second]), (second, vec![first])]);
        assert!(validate_publication_commit_graph(&cycle, first)
            .expect_err("cycle must fail")
            .to_string()
            .contains("cycle"));

        let leaf = source.blob(b"leaf").expect("leaf blob");
        let mut nested_oid = leaf;
        for depth in 0..=MAX_PUBLICATION_TREE_DEPTH + 1 {
            let mut nested = source.treebuilder(None).expect("nested tree");
            let mode = if depth == 0 { 0o100644 } else { 0o040000 };
            nested
                .insert("entry", nested_oid, mode)
                .expect("insert nested object");
            nested_oid = nested.write().expect("write nested tree");
        }
        let deep_tree = source.find_tree(nested_oid).expect("find deep tree");
        let deep_commit = source
            .commit(None, &signature, &signature, "deep", &deep_tree, &[])
            .expect("deep commit");
        let deep_destination = Repository::init_bare(temp.path().join("deep-destination.git"))
            .expect("deep destination");
        let depth_error = match materialize_publication_object_closure(
            &source,
            &deep_destination,
            &deep_commit.to_string(),
        ) {
            Ok(_) => panic!("excessive tree depth must fail"),
            Err(error) => error,
        };
        assert!(
            depth_error.to_string().contains("depth safety bound"),
            "unexpected deep-tree error: {depth_error:#}"
        );
    }

    #[test]
    fn token_selection_is_host_specific_unambiguous_and_basic_encoded() {
        let public = select_network_token_with("github.com", |key| {
            (key == "GH_TOKEN").then(|| "test-token".to_string())
        })
        .expect("public token");
        assert_eq!(
            public.basic_str().expect("basic token"),
            "eC1hY2Nlc3MtdG9rZW46dGVzdC10b2tlbg=="
        );
        assert!(select_network_token_with("github.com", |_| None).is_err());
        assert!(
            select_network_token_with("github.example", |key| match key {
                "GH_HOST" => Some("github.example".to_string()),
                "GH_ENTERPRISE_TOKEN" => Some("first-token".to_string()),
                "GITHUB_ENTERPRISE_TOKEN" => Some("second-token".to_string()),
                _ => None,
            })
            .is_err()
        );
        assert!(select_network_token_with("github.com", |key| {
            (key == "GH_TOKEN").then(|| "unsafe'token".to_string())
        })
        .is_err());
    }

    #[test]
    fn enterprise_host_authorization_precedes_and_exactly_scopes_token_selection() {
        use std::cell::Cell;

        let token_was_requested = Cell::new(false);
        let missing_host = select_network_token_with("github.example", |key| {
            if key.contains("TOKEN") {
                token_was_requested.set(true);
                Some("test-token".to_string())
            } else {
                None
            }
        });
        assert!(missing_host.is_err());
        assert!(!token_was_requested.get());

        let mismatch = select_network_token_with("github.example:8443", |key| match key {
            "GH_HOST" => Some("github.example".to_string()),
            "GH_ENTERPRISE_TOKEN" => Some("test-token".to_string()),
            _ => None,
        });
        assert!(mismatch.is_err());

        select_network_token_with("github.example:8443", |key| match key {
            "GH_HOST" => Some("github.example:8443".to_string()),
            "GH_ENTERPRISE_TOKEN" => Some("test-token".to_string()),
            _ => None,
        })
        .expect("exact enterprise authority is explicitly approved");

        let private_token_was_requested = Cell::new(false);
        let private_unapproved = select_network_token_with("127.0.0.1", |key| {
            if key.contains("TOKEN") {
                private_token_was_requested.set(true);
                Some("test-token".to_string())
            } else {
                None
            }
        });
        assert!(private_unapproved.is_err());
        assert!(!private_token_was_requested.get());
        select_network_token_with("127.0.0.1", |key| match key {
            "GH_HOST" => Some("127.0.0.1".to_string()),
            "GH_ENTERPRISE_TOKEN" => Some("test-token".to_string()),
            _ => None,
        })
        .expect("owner may explicitly approve an exact private enterprise endpoint");
    }

    #[test]
    fn github_expected_author_is_explicit_exact_and_bot_compatible() {
        assert!(select_github_expected_author_with(|_| None).is_err());
        assert!(select_github_expected_author_with(|key| match key {
            "GH_EXPECTED_AUTHOR" => Some("publisher".to_string()),
            "GITHUB_EXPECTED_AUTHOR" => Some("other".to_string()),
            _ => None,
        })
        .is_err());
        assert_eq!(
            select_github_expected_author_with(|key| {
                (key == "GH_EXPECTED_AUTHOR").then(|| "Release-Bot[bot]".to_string())
            })
            .expect("explicit bot provenance"),
            "release-bot[bot]"
        );
    }

    #[test]
    fn publication_pr_markers_are_canonical_unpredictable_and_exactly_embedded() {
        let first = generate_publication_pr_marker_nonce().expect("first marker");
        let second = generate_publication_pr_marker_nonce().expect("second marker");
        validate_publication_pr_marker_nonce(&first).expect("canonical first marker");
        validate_publication_pr_marker_nonce(&second).expect("canonical second marker");
        assert_ne!(first, second);
        let body = pr_body_with_publication_marker("body", &first).expect("marker body");
        assert_eq!(
            body.matches(&format!("<!-- maco-publication-marker:{first} -->"))
                .count(),
            1
        );
        assert!(!body.contains(&second));
    }

    #[test]
    fn token_redaction_covers_raw_and_basic_forms() {
        let token = select_network_token_with("github.com", |key| {
            (key == "GH_TOKEN").then(|| "test-token".to_string())
        })
        .expect("token");
        let mut output = format!(
            "raw={} basic={}",
            token.as_str().expect("raw"),
            token.basic_str().expect("basic")
        )
        .into_bytes();
        redact_private_bytes(&mut output, &token.bytes);
        redact_private_bytes(&mut output, &token.basic);
        let output = String::from_utf8(output).expect("UTF-8 redaction");
        assert!(!output.contains("test-token"));
        assert!(!output.contains("eC1hY2Nlc3MtdG9rZW46dGVzdC10b2tlbg=="));
        assert_eq!(output.matches("<redacted:network-token>").count(), 2);
    }

    #[test]
    fn publication_network_capability_callsites_are_exactly_audited() {
        let source_directory = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut constructors = Vec::new();
        let mut runners = Vec::new();
        let constructor_needle = ["TrustedFixedNetworkProfile", "::read_write("].concat();
        let runner_needle = ["merge::run_required_", "network_direct("].concat();
        for entry in fs::read_dir(&source_directory).expect("read source directory") {
            let entry = entry.expect("read source entry");
            let path = entry.path();
            if path.extension().and_then(|extension| extension.to_str()) != Some("rs") {
                continue;
            }
            let source = fs::read_to_string(&path).expect("read Rust source");
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .expect("UTF-8 source name");
            let production_source = if name == "process_runner.rs" {
                source
                    .split_once("#[cfg(test)]\nmod tests")
                    .map_or(source.as_str(), |(production, _)| production)
            } else {
                source.as_str()
            };
            for _ in production_source.match_indices(&constructor_needle) {
                constructors.push(name.to_string());
            }
            for _ in production_source.match_indices(&runner_needle) {
                runners.push(name.to_string());
            }
        }
        constructors.sort();
        runners.sort();
        assert_eq!(
            constructors,
            ["process_runner.rs", "publication.rs", "publication.rs"]
        );
        assert_eq!(runners, ["publication.rs", "publication.rs"]);
    }

    #[test]
    fn publication_url_slug_ref_and_oid_bounds_fail_closed() {
        assert!(publication_remote_transport(&format!(
            "https://example.invalid/owner/{}",
            "a".repeat(MAX_PUBLICATION_PATH_BYTES)
        ))
        .is_err());
        assert!(publication_remote_transport(&format!(
            "https://{}.example/owner/repo",
            "a".repeat(64)
        ))
        .is_err());
        assert!(github_repository_identity(&format!(
            "https://example.invalid/{}/repo",
            "a".repeat(MAX_GITHUB_SLUG_BYTES + 1)
        ))
        .is_err());
        assert!(validate_publication_ref(&format!(
            "refs/heads/{}",
            "a".repeat(MAX_PUBLICATION_REF_BYTES)
        ))
        .is_err());
        assert!(validate_publication_git_operation(&[
            OsString::from("push"),
            OsString::from("--no-verify"),
            OsString::from("--force-with-lease=refs/heads/review:"),
            OsString::from("maco-publication"),
            OsString::from(format!("{}:refs/heads/review", "A".repeat(40))),
        ])
        .is_err());

        let repository = GithubRepositoryIdentity {
            host: "github.example".to_string(),
            owner: "owner".to_string(),
            name: "repo".to_string(),
        };
        for malicious in ["--web", "--help"] {
            let view = [
                "pr",
                "view",
                malicious,
                "--repo",
                "github.example/owner/repo",
                "--json",
                "url,headRefOid,baseRefOid,number,baseRefName,state,isDraft",
            ]
            .into_iter()
            .map(OsString::from)
            .collect::<Vec<_>>();
            assert!(validate_gh_operation(&view, &StdinMode::Null, &repository).is_err());

            let create = [
                "pr",
                "create",
                "--repo",
                "github.example/owner/repo",
                "--base",
                malicious,
                "--head",
                "branch",
                "--title",
                "title",
                "--body-file",
                "-",
            ]
            .into_iter()
            .map(OsString::from)
            .collect::<Vec<_>>();
            assert!(
                validate_gh_operation(&create, &StdinMode::Bytes(Vec::new()), &repository).is_err()
            );

            for args in [
                vec![
                    "pr",
                    "list",
                    "--repo",
                    "github.example/owner/repo",
                    "--head",
                    malicious,
                    "--state",
                    "all",
                    "--json",
                    "url,headRefOid,baseRefOid,number,baseRefName,state,isDraft",
                ],
                vec![
                    "pr",
                    "create",
                    "--repo",
                    "github.example/owner/repo",
                    "--base",
                    "main",
                    "--head",
                    malicious,
                    "--title",
                    "title",
                    "--body-file",
                    "-",
                ],
                vec![
                    "pr",
                    "create",
                    "--repo",
                    "github.example/owner/repo",
                    "--base",
                    "main",
                    "--head",
                    "branch",
                    "--title",
                    malicious,
                    "--body-file",
                    "-",
                ],
                vec![
                    "issue",
                    "create",
                    "--repo",
                    "github.example/owner/repo",
                    "--title",
                    "title",
                    "--body-file",
                    "-",
                    "--label",
                    malicious,
                ],
            ] {
                let stdin = if args.get(1) == Some(&"list") {
                    StdinMode::Null
                } else {
                    StdinMode::Bytes(Vec::new())
                };
                let args = args.into_iter().map(OsString::from).collect::<Vec<_>>();
                assert!(validate_gh_operation(&args, &stdin, &repository).is_err());
            }
        }
    }

    #[test]
    fn github_source_list_argv_is_host_bound_exact_and_bounded() {
        let repository = GithubRepositoryIdentity {
            host: "github.example".to_string(),
            owner: "owner".to_string(),
            name: "repo".to_string(),
        };
        let args = github_source_list_args(
            &repository,
            ExternalSourceObjectKind::PullRequest,
            17,
            &["security".to_string(), "ready".to_string()],
        )
        .expect("trusted source list argv");
        let text = args
            .iter()
            .map(|argument| argument.to_str().expect("UTF-8 argv"))
            .collect::<Vec<_>>();
        assert_eq!(
            text,
            [
                "pr",
                "list",
                "--repo",
                "github.example/owner/repo",
                "--state",
                "open",
                "--json",
                GITHUB_PR_SOURCE_FIELDS,
                "--limit",
                "17",
                "--label",
                "security",
                "--label",
                "ready",
            ]
        );
        validate_gh_operation(&args, &StdinMode::Null, &repository)
            .expect("exact allowlisted source list");
        let issue_args = github_source_list_args(
            &repository,
            ExternalSourceObjectKind::Issue,
            MAX_GITHUB_SOURCE_LIST_ITEMS,
            &[],
        )
        .expect("trusted issue source list argv");
        validate_gh_operation(&issue_args, &StdinMode::Null, &repository)
            .expect("exact allowlisted issue source list");
        assert_eq!(issue_args[0], "issue");
        assert_eq!(issue_args[3], "github.example/owner/repo");

        let other_host = GithubRepositoryIdentity {
            host: "other.example".to_string(),
            owner: "owner".to_string(),
            name: "repo".to_string(),
        };
        assert!(validate_gh_operation(&args, &StdinMode::Null, &other_host).is_err());
        assert!(
            github_source_list_args(&repository, ExternalSourceObjectKind::Issue, 0, &[]).is_err()
        );
        assert!(github_source_list_args(
            &repository,
            ExternalSourceObjectKind::Issue,
            MAX_GITHUB_SOURCE_LIST_ITEMS + 1,
            &[]
        )
        .is_err());
        assert!(github_source_list_args(
            &repository,
            ExternalSourceObjectKind::Issue,
            1,
            &vec!["label".to_string(); MAX_GITHUB_SOURCE_LIST_LABELS + 1]
        )
        .is_err());
        assert!(github_source_list_args(
            &repository,
            ExternalSourceObjectKind::Issue,
            1,
            &["--web".to_string()]
        )
        .is_err());
    }

    #[test]
    fn zeroizing_string_debug_is_redacted_and_explicit_clear_empties_it() {
        let mut secret = ZeroizingString("test-token".to_string());
        assert_eq!(format!("{secret:?}"), "<redacted:zeroizing-string>");
        secret.zeroize();
        assert!(secret.as_str().is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn gh_command_refuses_changed_private_runtime_before_spawn() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().expect("tempdir");
        let repo_path = temp.path().join("repo");
        Repository::init(&repo_path).expect("init repo");
        let repository = GithubRepositoryIdentity {
            host: "github.example".to_string(),
            owner: "owner".to_string(),
            name: "repo".to_string(),
        };
        let mut context =
            GhCommandContext::create_with_token_source(&repo_path, &repository, |key| {
                enterprise_test_value("github.example", key)
            })
            .expect("create gh context");
        assert_ne!(context.runtime_directory.path(), repo_path);
        fs::set_permissions(
            context.runtime_directory.path(),
            fs::Permissions::from_mode(0o755),
        )
        .expect("weaken gh runtime mode");
        let result = context.run_inner(
            "gh identity test",
            vec![OsString::from("--version")],
            StdinMode::Null,
        );
        fs::set_permissions(
            context.runtime_directory.path(),
            fs::Permissions::from_mode(0o700),
        )
        .expect("restore gh runtime mode for cleanup");
        let error = match result {
            Ok(_) => panic!("changed gh runtime must fail before command execution"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("private gh runtime changed"));
        context.close().expect("explicit gh context cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn publication_remote_binding_key_is_private_stable_and_fixed_length() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let state = tempfile::tempdir().expect("state dir");
        let first = load_or_create_remote_binding_secret(state.path()).expect("create key");
        let second = load_or_create_remote_binding_secret(state.path()).expect("reload key");
        assert_eq!(first, second);
        assert_eq!(first.len(), REMOTE_BINDING_SECRET_BYTES);
        let metadata =
            fs::metadata(state.path().join(REMOTE_BINDING_SECRET_FILE)).expect("key metadata");
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        assert_eq!(metadata.nlink(), 1);
    }

    #[test]
    fn publication_remote_binding_key_missing_with_prior_transaction_fails_closed() {
        let state = tempfile::tempdir().expect("state dir");
        fs::create_dir_all(state.path().join("publication-transactions/prior"))
            .expect("prior transaction");

        let error = load_or_create_remote_binding_secret(state.path())
            .expect_err("missing key with prior transaction must fail");

        assert!(error
            .to_string()
            .contains("prior transaction entries exist"));
        assert!(!state.path().join(REMOTE_BINDING_SECRET_FILE).exists());
    }

    #[cfg(unix)]
    #[test]
    fn publication_remote_binding_key_rejects_corruption_permissions_and_symlink() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let corrupt = tempfile::tempdir().expect("corrupt state");
        let corrupt_path = corrupt.path().join(REMOTE_BINDING_SECRET_FILE);
        fs::write(&corrupt_path, b"short").expect("write corrupt key");
        fs::set_permissions(&corrupt_path, fs::Permissions::from_mode(0o600))
            .expect("chmod corrupt key");
        assert!(read_remote_binding_secret(&corrupt_path)
            .expect_err("corrupt key must fail")
            .to_string()
            .contains("invalid length"));

        let exposed = tempfile::tempdir().expect("exposed state");
        let exposed_path = exposed.path().join(REMOTE_BINDING_SECRET_FILE);
        fs::write(&exposed_path, [1_u8; REMOTE_BINDING_SECRET_BYTES]).expect("write exposed key");
        fs::set_permissions(&exposed_path, fs::Permissions::from_mode(0o644))
            .expect("chmod exposed key");
        assert!(read_remote_binding_secret(&exposed_path)
            .expect_err("exposed key must fail")
            .to_string()
            .contains("mode 0600"));

        let replaced = tempfile::tempdir().expect("replaced state");
        let target = replaced.path().join("target");
        fs::write(&target, [2_u8; REMOTE_BINDING_SECRET_BYTES]).expect("write key target");
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).expect("chmod key target");
        let replaced_path = replaced.path().join(REMOTE_BINDING_SECRET_FILE);
        symlink(&target, &replaced_path).expect("replace key with symlink");
        assert!(read_remote_binding_secret(&replaced_path)
            .expect_err("symlink key must fail")
            .to_string()
            .contains("non-reparse"));
    }

    #[cfg(unix)]
    #[test]
    fn publication_remote_binding_key_recovers_only_known_crash_temp_link() {
        use std::os::unix::fs::MetadataExt;

        let state = tempfile::tempdir().expect("state dir");
        let secret = load_or_create_remote_binding_secret(state.path()).expect("create key");
        let key = state.path().join(REMOTE_BINDING_SECRET_FILE);
        let crash_temp = state
            .path()
            .join(format!(".{REMOTE_BINDING_SECRET_FILE}-123-456.tmp"));
        fs::hard_link(&key, &crash_temp).expect("simulate crash temp hard link");
        assert_eq!(fs::metadata(&key).expect("linked key metadata").nlink(), 2);

        let recovered = read_remote_binding_secret(&key).expect("recover known temp link");

        assert_eq!(recovered, secret);
        assert!(!crash_temp.exists());
        assert_eq!(
            fs::metadata(&key).expect("recovered key metadata").nlink(),
            1
        );

        let unknown = state.path().join("unknown-key-link");
        fs::hard_link(&key, &unknown).expect("create unknown key hard link");
        assert!(read_remote_binding_secret(&key)
            .expect_err("unknown hard link must fail")
            .to_string()
            .contains("multiple hard links"));
    }
}
