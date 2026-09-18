//! Finite authenticated GitHub transport for CAS coordination journal (#410).
//!
//! Does not enable remote coordination by itself; production I/O stays behind
//! explicit adapter construction after branch-protection proof.

use super::coordination_journal::{
    preflight_proposed_journal_transition, AuthenticatedCommentEvidence, AuthoritySnapshot,
    CoordinationIntent, CoordinationIntentAction, CoordinationJournalConfig,
    EffectReconciliationVerifier, IntentAdmissionTiming, JournalPointer, ProposedIntentAdmission,
    TrustedFiniteJournalHistory, TrustedJournalReductionInput, VerifiedJournalEntry,
    MAX_JOURNAL_ENTRIES, MAX_POINTER_FILE_BYTES,
};
use super::forge_transport::{
    ForgeActor, ForgeComment, ForgeItem, ForgeItemKind, ForgeRepository, ForgeTimestamp,
    ProviderObjectKind, ReportedActorKind,
};
use super::{
    encode_base64, github_node_object_id, github_repository_identity_from_selector,
    parse_authenticated_github_json, required_command_stdout, stable_json_digest,
    validate_authenticated_github_number, validate_authenticated_github_oid,
    validate_authenticated_github_page, validate_external_digest, GhCommandContext, GithubApiActor,
    GithubRepositoryIdentity, AUTHENTICATED_GITHUB_MAX_PAGES, AUTHENTICATED_GITHUB_PAGE_SIZE,
    GH_CAPTURE_LIMIT_BYTES, MAX_GITHUB_COMMENT_CANDIDATES, MAX_GITHUB_RECEIPT_BODY_BYTES,
    MAX_GITHUB_RECEIPT_URL_BYTES,
};
use crate::{
    artifacts::{repository_auth_writer, state_auth::sha256_hex},
    effect_wal::{DefaultEffectWal, EffectPhase, EffectWal},
    process_runner::StdinMode,
    sync_store::ClaimTiming,
};
use anyhow::{bail, Context, Result};
use git2::{ObjectType, Oid};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    ffi::OsString,
    path::{Path, PathBuf},
};

const DEFAULT_POINTER_PATH: &str = "maco-coordination.json";
const COORDINATION_MUTATION_VERSION: u32 = 1;
const COORDINATION_MUTATION_PLAN: &str = "maco_coordination_journal_mutation_v1";
const COMMENT_EFFECT_PREFIX: &str = "coord-comment:";
const CAS_EFFECT_PREFIX: &str = "coord-cas:";
const GITHUB_CREATE_COMMIT_ON_BRANCH: &str =
    "mutation($input:CreateCommitOnBranchInput!){createCommitOnBranch(input:$input){commit{oid}}}";
const CAS_COMMIT_HEADLINE: &str = "maco coordination journal CAS";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CoordinationGithubAdapterConfig {
    journal: CoordinationJournalConfig,
    pointer_path: String,
    repository: GithubRepositoryIdentity,
    worktree: PathBuf,
    branch_name: String,
    anchor_issue_api_url: String,
    anchor_issue_html_url: String,
    approved_actor: ForgeActor,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CoordinationGithubAdapterOpenInput {
    pub worktree: PathBuf,
    pub repository_selector: String,
    pub anchor_item: ForgeItem,
    pub journal_ref: String,
    pub anchor_commit_oid: String,
    pub pointer_path: Option<String>,
    pub trusted_actors: Vec<ForgeActor>,
    pub timing: ClaimTiming,
}

impl CoordinationGithubAdapterConfig {
    pub(crate) fn journal(&self) -> &CoordinationJournalConfig {
        &self.journal
    }

    pub(crate) fn pointer_path(&self) -> &str {
        &self.pointer_path
    }

    pub(crate) fn repository(&self) -> &GithubRepositoryIdentity {
        &self.repository
    }

    pub(crate) fn worktree(&self) -> &Path {
        &self.worktree
    }

    pub(crate) fn approved_actor(&self) -> &ForgeActor {
        &self.approved_actor
    }

    pub(crate) fn try_new(
        input: CoordinationGithubAdapterOpenInput,
        runner: &impl CoordinationGithubRunner,
    ) -> Result<Self> {
        let journal_ref = input.journal_ref;
        let pointer_path = input
            .pointer_path
            .unwrap_or_else(|| DEFAULT_POINTER_PATH.to_string());
        validate_pointer_path(&pointer_path)?;
        let repository = github_repository_identity_from_selector(&input.repository_selector)?;
        if input.anchor_item.repository().canonical_locator() != repository.selector() {
            bail!("coordination anchor item locator does not match the configured repository selector");
        }
        let journal = CoordinationJournalConfig::new(
            input.anchor_item.clone(),
            journal_ref.clone(),
            input.anchor_commit_oid,
            input.trusted_actors.clone(),
            input.timing,
        )?;
        let branch_name = journal_branch_name(&journal_ref)?;
        let mut config = Self {
            journal,
            pointer_path,
            repository,
            worktree: input.worktree,
            branch_name,
            anchor_issue_api_url: String::new(),
            anchor_issue_html_url: String::new(),
            approved_actor: input
                .trusted_actors
                .first()
                .cloned()
                .context("trusted actor allowlist unexpectedly empty")?,
        };
        config.bind_authenticated_identities(runner, &input.anchor_item)?;
        config.verify_journal_branch_protection(runner)?;
        Ok(config)
    }

    fn bind_authenticated_identities(
        &mut self,
        runner: &impl CoordinationGithubRunner,
        anchor_item: &ForgeItem,
    ) -> Result<()> {
        let repo_json = runner.run(
            self,
            "gh coordination repository identity",
            CoordinationGithubOperation::RepositoryMetadata,
        )?;
        let repo: GithubRepositoryMetadataWire =
            parse_authenticated_github_json(&repo_json, "GitHub coordination repository identity")?;
        let observed_repo = ForgeRepository::new(
            "github",
            self.repository.selector(),
            github_node_object_id(ProviderObjectKind::Repository, &repo.node_id)?,
        )?;
        if observed_repo.provider_repository_id()
            != anchor_item.repository().provider_repository_id()
        {
            bail!("authenticated repository identity does not match the configured anchor item");
        }
        let expected_name = format!("{}/{}", self.repository.owner, self.repository.name);
        if repo.full_name.to_ascii_lowercase() != expected_name {
            bail!("authenticated repository full name does not match the configured selector");
        }
        let issue_json = runner.run(
            self,
            "gh coordination anchor issue identity",
            CoordinationGithubOperation::AnchorIssue {
                number: anchor_item.number(),
            },
        )?;
        let issue: GithubIssueMetadataWire =
            parse_authenticated_github_json(&issue_json, "GitHub coordination anchor issue")?;
        if issue.number != anchor_item.number() || issue.pull_request.is_some() {
            bail!("authenticated anchor endpoint returned the wrong item kind or number");
        }
        let observed_item = ForgeItem::new(
            observed_repo.clone(),
            ForgeItemKind::Issue,
            issue.number,
            github_node_object_id(ProviderObjectKind::Item, &issue.node_id)?,
            format!(
                "github-issue-{}-{}",
                issue.number,
                sha256_hex(issue.updated_at.as_bytes())
            ),
            None,
            None,
        )?;
        if observed_item.provider_item_id() != anchor_item.provider_item_id() {
            bail!("authenticated issue identity does not match the configured anchor item");
        }
        self.anchor_issue_html_url =
            validate_bound_github_issue_html_url(&issue.html_url, &self.repository, issue.number)?;
        self.anchor_issue_api_url =
            validate_bound_github_issue_api_url(&issue.url, &self.repository, issue.number)?;
        let actor_json = runner.run(
            self,
            "gh coordination approved actor",
            CoordinationGithubOperation::AuthenticatedActor,
        )?;
        let actor: GithubApiActor =
            parse_authenticated_github_json(&actor_json, "GitHub coordination approved actor")?;
        let approved = github_wire_actor(&actor)?;
        if !self.journal.is_trusted_actor(&approved) {
            bail!("approved authenticated actor is not in the configured trusted allowlist");
        }
        self.approved_actor = approved;
        Ok(())
    }

    fn verify_journal_branch_protection(
        &self,
        runner: &impl CoordinationGithubRunner,
    ) -> Result<()> {
        let json = runner.run(
            self,
            "gh coordination journal branch protection",
            CoordinationGithubOperation::JournalBranchProtection {
                branch_name: self.branch_name.clone(),
            },
        )?;
        let protection: GithubBranchProtectionWire =
            parse_authenticated_github_json(&json, "GitHub journal branch protection")?;
        if !protection.enforce_admins.enabled {
            bail!(
                "coordination journal branch protection does not enforce admins; remote mode is refused"
            );
        }
        if protection.allow_force_pushes.enabled {
            bail!("coordination journal branch allows force pushes; remote mode is refused");
        }
        if protection.allow_deletions.enabled {
            bail!("coordination journal branch allows deletions; remote mode is refused");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CoordinationGithubOperation {
    AuthenticatedActor,
    RepositoryMetadata,
    AnchorIssue {
        number: u64,
    },
    JournalBranchProtection {
        branch_name: String,
    },
    JournalRefHead {
        branch_name: String,
    },
    JournalRefHeadWithProviderTime {
        branch_name: String,
    },
    Commit {
        oid: String,
    },
    Tree {
        tree_oid: String,
    },
    Blob {
        blob_oid: String,
    },
    AnchorItemComments {
        number: u64,
        page: usize,
    },
    IssueComment {
        comment_id: u64,
    },
    PostIssueComment {
        number: u64,
        body: String,
        payload_digest: String,
    },
    CreateCommitOnBranch {
        branch_name: String,
        expected_head_oid: String,
        pointer_path: String,
        pointer_contents: String,
        event_nonce: String,
        payload_digest: String,
    },
}

impl CoordinationGithubOperation {
    fn approved_mutation(&self) -> bool {
        matches!(
            self,
            Self::PostIssueComment { .. } | Self::CreateCommitOnBranch { .. }
        )
    }

    fn command(&self, repository: &GithubRepositoryIdentity) -> Result<(Vec<OsString>, StdinMode)> {
        let base = format!("repos/{}/{}", repository.owner, repository.name);
        let get = |endpoint: String| {
            (
                ["api", "--method", "GET", endpoint.as_str()]
                    .into_iter()
                    .map(OsString::from)
                    .collect(),
                StdinMode::Null,
            )
        };
        Ok(match self {
            Self::AuthenticatedActor => get("user".to_string()),
            Self::RepositoryMetadata => get(base),
            Self::AnchorIssue { number } => {
                validate_authenticated_github_number(*number)?;
                get(format!("{base}/issues/{number}"))
            }
            Self::JournalBranchProtection { branch_name } => {
                validate_branch_name(branch_name)?;
                get(format!(
                    "{base}/branches/{}/protection",
                    encode_github_path_segment(branch_name)
                ))
            }
            Self::JournalRefHead { branch_name } => {
                validate_branch_name(branch_name)?;
                get(format!(
                    "{base}/git/ref/heads/{}",
                    encode_github_path_segment(branch_name)
                ))
            }
            Self::JournalRefHeadWithProviderTime { branch_name } => {
                validate_branch_name(branch_name)?;
                let endpoint = format!(
                    "{base}/git/ref/heads/{}",
                    encode_github_path_segment(branch_name)
                );
                (
                    ["api", "--include", "--method", "GET", endpoint.as_str()]
                        .into_iter()
                        .map(OsString::from)
                        .collect(),
                    StdinMode::Null,
                )
            }
            Self::Commit { oid } => {
                validate_authenticated_github_oid(oid)?;
                get(format!("{base}/commits/{oid}"))
            }
            Self::Tree { tree_oid } => {
                validate_authenticated_github_oid(tree_oid)?;
                get(format!("{base}/git/trees/{tree_oid}"))
            }
            Self::Blob { blob_oid } => {
                validate_authenticated_github_oid(blob_oid)?;
                get(format!("{base}/git/blobs/{blob_oid}"))
            }
            Self::AnchorItemComments { number, page } => {
                validate_authenticated_github_number(*number)?;
                validate_authenticated_github_page(*page)?;
                get(format!(
                    "{base}/issues/{number}/comments?per_page={AUTHENTICATED_GITHUB_PAGE_SIZE}&page={page}"
                ))
            }
            Self::IssueComment { comment_id } => {
                if *comment_id == 0 {
                    bail!("GitHub issue comment id must be positive");
                }
                get(format!("{base}/issues/comments/{comment_id}"))
            }
            Self::PostIssueComment {
                number,
                body,
                payload_digest,
            } => {
                validate_authenticated_github_number(*number)?;
                validate_external_digest(payload_digest, "coordination intent payload digest")?;
                if body.len() > MAX_GITHUB_RECEIPT_BODY_BYTES {
                    bail!("coordination intent comment body exceeds its bound");
                }
                let payload = serde_json::to_vec(&serde_json::json!({ "body": body }))
                    .context("serialize coordination intent comment")?;
                (
                    vec![
                        OsString::from("api"),
                        OsString::from("--method"),
                        OsString::from("POST"),
                        OsString::from(format!("{base}/issues/{number}/comments")),
                        OsString::from("--input"),
                        OsString::from("-"),
                    ],
                    StdinMode::Bytes(payload),
                )
            }
            Self::CreateCommitOnBranch {
                branch_name,
                expected_head_oid,
                pointer_path,
                pointer_contents,
                event_nonce,
                payload_digest,
            } => {
                validate_branch_name(branch_name)?;
                validate_authenticated_github_oid(expected_head_oid)?;
                validate_pointer_path(pointer_path)?;
                validate_external_digest(payload_digest, "coordination CAS payload digest")?;
                if event_nonce.is_empty() || event_nonce.len() > 96 {
                    bail!("coordination CAS event nonce is malformed");
                }
                let body = format!("nonce={event_nonce}\ndigest={payload_digest}");
                if body.len() > 4096 {
                    bail!("coordination CAS commit message exceeds its bound");
                }
                let contents = encode_base64(pointer_contents.as_bytes());
                let variables = serde_json::json!({
                    "input": {
                        "branch": {
                            "repositoryNameWithOwner": repository_name_with_owner(repository),
                            "branchName": branch_name,
                        },
                        "expectedHeadOid": expected_head_oid,
                        "message": {
                            "headline": CAS_COMMIT_HEADLINE,
                            "body": body,
                        },
                        "fileChanges": {
                            "additions": [{
                                "path": pointer_path,
                                "contents": contents,
                            }]
                        }
                    }
                });
                let body = serde_json::json!({
                    "query": GITHUB_CREATE_COMMIT_ON_BRANCH,
                    "variables": variables,
                });
                (
                    vec![
                        OsString::from("api"),
                        OsString::from("graphql"),
                        OsString::from("--input"),
                        OsString::from("-"),
                    ],
                    StdinMode::Bytes(
                        serde_json::to_vec(&body).context("serialize coordination CAS GraphQL")?,
                    ),
                )
            }
        })
    }
}

/// Bound `GET …/git/ref/heads/…` with a single authenticated `Date` response header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct JournalRefHeadWithProviderTime {
    pub(crate) head_oid: String,
    pub(crate) provider_time: ForgeTimestamp,
}

fn split_github_include_response(raw: &str) -> Result<(&str, &str)> {
    if raw.len() > GH_CAPTURE_LIMIT_BYTES {
        bail!("coordination GitHub include response exceeds capture bound");
    }
    let (headers, body) = raw
        .split_once("\r\n\r\n")
        .or_else(|| raw.split_once("\n\n"))
        .context("coordination GitHub include response missing header/body separator")?;
    if body.is_empty() {
        bail!("coordination GitHub include response body is empty");
    }
    if body.len() > GH_CAPTURE_LIMIT_BYTES {
        bail!("coordination GitHub include response body exceeds capture bound");
    }
    Ok((headers, body))
}

fn parse_github_include_date_header(headers: &str) -> Result<String> {
    let mut lines = headers.lines();
    let status = lines
        .next()
        .context("coordination GitHub include response omitted status line")?;
    if !status.starts_with("HTTP/") {
        bail!("coordination GitHub include response status line was malformed");
    }
    let status_code = status
        .split_whitespace()
        .nth(1)
        .context("coordination GitHub include status line omitted status code")?;
    if status_code != "200" {
        bail!("coordination GitHub include response status was not HTTP 200");
    }
    let mut dates = Vec::new();
    for line in lines {
        if line.starts_with("HTTP/") {
            bail!("coordination GitHub include response contained multiple HTTP status blocks");
        }
        if line.is_empty() {
            continue;
        }
        let (name, value) = line
            .split_once(':')
            .context("coordination GitHub include header line was malformed")?;
        if name.eq_ignore_ascii_case("date") {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                bail!("coordination GitHub Date header was empty");
            }
            dates.push(trimmed.to_string());
        }
    }
    if dates.is_empty() {
        bail!("coordination GitHub include response omitted Date header");
    }
    if dates.len() != 1 {
        bail!("coordination GitHub include response contained duplicate Date headers");
    }
    Ok(dates[0].clone())
}

fn validate_imf_fixdate_weekday(token: &str) -> Result<()> {
    if token.len() != 4 || !token.ends_with(',') {
        bail!("coordination GitHub Date weekday token was malformed");
    }
    match &token.as_bytes()[..3] {
        b"Mon" | b"Tue" | b"Wed" | b"Thu" | b"Fri" | b"Sat" | b"Sun" => Ok(()),
        _ => bail!("coordination GitHub Date weekday was invalid"),
    }
}

fn imf_fixdate_to_forge_timestamp(value: &str) -> Result<ForgeTimestamp> {
    if value.len() > 128 || !value.is_ascii() {
        bail!("coordination GitHub Date header is malformed");
    }
    let parts = value.split_whitespace().collect::<Vec<_>>();
    if parts.len() != 6 || parts[5] != "GMT" {
        bail!("coordination GitHub Date header is not IMF-fixdate GMT");
    }
    validate_imf_fixdate_weekday(parts[0])?;
    if parts[1].len() != 2 || !parts[1].bytes().all(|byte| byte.is_ascii_digit()) {
        bail!("coordination GitHub Date day was invalid");
    }
    if parts[2].len() != 3 {
        bail!("coordination GitHub Date month was invalid");
    }
    if parts[3].len() != 4 || !parts[3].bytes().all(|byte| byte.is_ascii_digit()) {
        bail!("coordination GitHub Date year was invalid");
    }
    let clock = parts[4].as_bytes();
    if clock.len() != 8
        || clock[2] != b':'
        || clock[5] != b':'
        || !clock[..2].iter().all(|byte| byte.is_ascii_digit())
        || !clock[3..5].iter().all(|byte| byte.is_ascii_digit())
        || !clock[6..8].iter().all(|byte| byte.is_ascii_digit())
    {
        bail!("coordination GitHub Date time was malformed");
    }
    let day = parts[1]
        .parse::<u32>()
        .context("coordination GitHub Date day was invalid")?;
    let year = parts[3]
        .parse::<u32>()
        .context("coordination GitHub Date year was invalid")?;
    let month = match parts[2].to_ascii_lowercase().as_str() {
        "jan" => 1,
        "feb" => 2,
        "mar" => 3,
        "apr" => 4,
        "may" => 5,
        "jun" => 6,
        "jul" => 7,
        "aug" => 8,
        "sep" => 9,
        "oct" => 10,
        "nov" => 11,
        "dec" => 12,
        _ => bail!("coordination GitHub Date month was invalid"),
    };
    let hour = std::str::from_utf8(&clock[..2])?
        .parse::<u32>()
        .context("coordination GitHub Date hour was invalid")?;
    let minute = std::str::from_utf8(&clock[3..5])?
        .parse::<u32>()
        .context("coordination GitHub Date minute was invalid")?;
    let second = std::str::from_utf8(&clock[6..8])?
        .parse::<u32>()
        .context("coordination GitHub Date second was invalid")?;
    ForgeTimestamp::new(format!(
        "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z"
    ))
    .context("coordination GitHub Date header failed forge timestamp validation")
}

#[derive(Debug, Deserialize)]
struct GithubJournalRefHeadIncludeWire {
    #[serde(rename = "ref")]
    ref_name: String,
    object: GithubJournalRefHeadIncludeObjectWire,
}

#[derive(Debug, Deserialize)]
struct GithubJournalRefHeadIncludeObjectWire {
    sha: String,
    #[serde(rename = "type")]
    type_field: String,
}

fn validate_bound_journal_ref_head_include_body(body: &str, expected_ref: &str) -> Result<String> {
    let wire: GithubJournalRefHeadIncludeWire = parse_authenticated_github_json(
        body,
        "GitHub coordination journal ref head with provider time",
    )?;
    if wire.ref_name != expected_ref {
        bail!("bound journal ref does not match configured journal branch ref");
    }
    if wire.object.type_field != "commit" {
        bail!("bound journal ref object type is not commit");
    }
    validate_observed_git_oid(&wire.object.sha)?;
    Ok(wire.object.sha)
}

pub(crate) fn parse_journal_ref_head_with_provider_time_response(
    raw: &str,
    expected_ref: &str,
) -> Result<JournalRefHeadWithProviderTime> {
    let (headers, body) = split_github_include_response(raw)?;
    let date = parse_github_include_date_header(headers)?;
    let provider_time = imf_fixdate_to_forge_timestamp(&date)?;
    let head_oid = validate_bound_journal_ref_head_include_body(body, expected_ref)?;
    Ok(JournalRefHeadWithProviderTime {
        head_oid,
        provider_time,
    })
}

#[derive(Debug)]
enum TakeoverProviderTimePreflightFailure {
    JournalHeadRace,
    Refused(anyhow::Error),
}

pub(crate) trait CoordinationGithubRunner: Send + Sync {
    fn run(
        &self,
        config: &CoordinationGithubAdapterConfig,
        label: &str,
        operation: CoordinationGithubOperation,
    ) -> Result<String>;
}

pub(crate) struct ProductionCoordinationGithubRunner;

impl Clone for ProductionCoordinationGithubRunner {
    fn clone(&self) -> Self {
        *self
    }
}

impl Copy for ProductionCoordinationGithubRunner {}

impl CoordinationGithubRunner for ProductionCoordinationGithubRunner {
    fn run(
        &self,
        config: &CoordinationGithubAdapterConfig,
        label: &str,
        operation: CoordinationGithubOperation,
    ) -> Result<String> {
        let (args, stdin) = operation.command(config.repository())?;
        let output = GhCommandContext::create(config.worktree(), config.repository())?
            .run_coordination_github(label, args, stdin, operation.approved_mutation())?;
        required_command_stdout(output, label)
    }
}

pub(crate) struct CoordinationGithubTransport<R: CoordinationGithubRunner> {
    config: CoordinationGithubAdapterConfig,
    runner: R,
}

impl<R: CoordinationGithubRunner> CoordinationGithubTransport<R> {
    pub(crate) fn new(config: CoordinationGithubAdapterConfig, runner: R) -> Self {
        Self { config, runner }
    }

    pub(crate) fn config(&self) -> &CoordinationGithubAdapterConfig {
        &self.config
    }

    pub(crate) fn load_trusted_history(&self) -> Result<TrustedFiniteJournalHistory> {
        let tip = self.journal_ref_head()?;
        let commits = self.complete_ancestry_to_anchor(&tip)?;
        let comments = self.complete_anchor_comment_index()?;
        let mut entries = Vec::with_capacity(commits.len());
        for commit in commits {
            entries.push(self.verified_entry_from_commit(&commit, &comments)?);
        }
        TrustedFiniteJournalHistory::from_transport_verified_entries(self.config.journal(), entries)
    }

    pub(crate) fn reduce_loaded_history(
        &self,
        history: &TrustedFiniteJournalHistory,
        effect_reconciliation: Option<&dyn EffectReconciliationVerifier>,
    ) -> Result<AuthoritySnapshot> {
        let input = TrustedJournalReductionInput {
            config: self.config.journal().clone(),
            history,
            effect_reconciliation,
        };
        match input.reduce() {
            super::coordination_journal::JournalAuthorityResult::Authoritative(snapshot) => {
                Ok(snapshot)
            }
            super::coordination_journal::JournalAuthorityResult::Refused(reason) => {
                bail!("coordination journal reduction refused: {reason:?}")
            }
        }
    }

    pub(crate) fn apply_authorized_intent(
        &self,
        intent: CoordinationIntent,
        comment_author: ForgeActor,
        effect_reconciliation: Option<&dyn EffectReconciliationVerifier>,
    ) -> Result<CoordinationMutationOutcome> {
        self.require_exact_comment_actor(&comment_author)?;
        intent.require_target(self.config.journal().anchor_item())?;
        let body = intent.render()?;
        let payload_digest = sha256_hex(body.as_bytes());
        let plan_digest = stable_json_digest(&(
            COORDINATION_MUTATION_PLAN,
            intent.event_nonce(),
            intent.expected_parent_oid(),
            &payload_digest,
            comment_author.provider_actor_id(),
        ))?;
        validate_external_digest(&plan_digest, "coordination journal mutation plan digest")?;
        let comment_effect_id = format!("{COMMENT_EFFECT_PREFIX}{plan_digest}");
        let cas_effect_id = format!("{CAS_EFFECT_PREFIX}{plan_digest}");
        let logical_id = format!("coord-journal-{plan_digest}");
        let planned = CoordinationJournalMutationRecord {
            version: COORDINATION_MUTATION_VERSION,
            plan_digest: plan_digest.clone(),
            event_nonce: intent.event_nonce().to_string(),
            expected_parent_oid: intent.expected_parent_oid().to_string(),
            payload_digest: payload_digest.clone(),
            intent_body: body.clone(),
            comment: None,
            cas: None,
        };
        let mut wal: DefaultEffectWal = EffectWal::open_or_create_planned(
            || {
                repository_auth_writer(self.config.worktree())?
                    .into_authenticator()
                    .context("failed to bind coordination journal mutation ledger")
            },
            &logical_id,
            &comment_effect_id,
            &planned,
        )?;
        if wal.phase(&cas_effect_id).is_none() {
            wal.planned(&cas_effect_id, &planned)?;
        }
        self.apply_with_wal(
            &mut wal,
            CoordinationGithubIntentApplyPlan {
                comment_effect_id,
                cas_effect_id,
                plan_digest,
                intent,
                comment_author,
                body,
                payload_digest,
            },
            effect_reconciliation,
        )
    }

    fn require_exact_comment_actor(&self, author: &ForgeActor) -> Result<()> {
        if author != self.config.approved_actor() {
            bail!(
                "coordination intent actor does not match the bound approved authenticated actor"
            );
        }
        if !self.config.journal().is_trusted_actor(author) {
            bail!("coordination intent actor is not in the configured trusted actor allowlist");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CoordinationMutationOutcome {
    Applied {
        entry: Box<VerifiedJournalEntry>,
        snapshot: AuthoritySnapshot,
    },
    NotApplied {
        reason: String,
    },
    Unknown {
        evidence: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CoordinationJournalMutationRecord {
    version: u32,
    plan_digest: String,
    event_nonce: String,
    expected_parent_oid: String,
    payload_digest: String,
    intent_body: String,
    comment: Option<CoordinationCommentReceipt>,
    cas: Option<CoordinationCasReceipt>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CoordinationCommentReceipt {
    provider_comment_id: u64,
    url: String,
    author_login: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CoordinationCasReceipt {
    commit_oid: String,
    parent_oid: String,
}

fn preflight_refusal_outcome(
    wal: &EffectWal,
    plan: &CoordinationGithubIntentApplyPlan,
    error: impl std::fmt::Display,
    unknown_prefix: &str,
) -> CoordinationMutationOutcome {
    if wal.phase(&plan.comment_effect_id) == Some(EffectPhase::Planned)
        && wal.phase(&plan.cas_effect_id) == Some(EffectPhase::Planned)
    {
        CoordinationMutationOutcome::NotApplied {
            reason: format!("{error}"),
        }
    } else {
        CoordinationMutationOutcome::Unknown {
            evidence: format!("{unknown_prefix}: {error}"),
        }
    }
}

struct CoordinationGithubIntentApplyPlan {
    comment_effect_id: String,
    cas_effect_id: String,
    plan_digest: String,
    intent: CoordinationIntent,
    comment_author: ForgeActor,
    body: String,
    payload_digest: String,
}

struct CoordinationGithubCommittedReplay {
    plan: CoordinationGithubIntentApplyPlan,
    entry: VerifiedJournalEntry,
    history: TrustedFiniteJournalHistory,
}

struct CoordinationGithubWalReceiptBinding {
    comment_effect_id: String,
    cas_effect_id: String,
    plan_digest: String,
    comment_receipt: CoordinationCommentReceipt,
    cas_receipt: CoordinationCasReceipt,
    pointer: JournalPointer,
}

impl<R: CoordinationGithubRunner> CoordinationGithubTransport<R> {
    fn apply_with_wal(
        &self,
        wal: &mut EffectWal,
        plan: CoordinationGithubIntentApplyPlan,
        effect_reconciliation: Option<&dyn EffectReconciliationVerifier>,
    ) -> Result<CoordinationMutationOutcome> {
        if let Some(history) = self.history_for_committed_nonce(plan.intent.event_nonce())? {
            let entry = history
                .verified_entries()
                .iter()
                .find(|entry| entry.pointer().event_nonce() == plan.intent.event_nonce())
                .cloned()
                .expect("history_for_committed_nonce promised a matching entry");
            return self.reconcile_and_finish_committed_apply(
                wal,
                CoordinationGithubCommittedReplay {
                    plan,
                    entry,
                    history,
                },
                effect_reconciliation,
            );
        }
        if let Some(outcome) =
            self.preflight_before_first_mutation(wal, &plan, effect_reconciliation)?
        {
            return Ok(outcome);
        }
        let comment_record = match self.run_comment_phase(
            wal,
            &plan.comment_effect_id,
            &plan.plan_digest,
            &plan.body,
            &plan.comment_author,
        ) {
            Ok(receipt) => receipt,
            Err(error) => {
                let message = format!("{error:#}");
                if message.contains("unknown coordination") {
                    return Ok(CoordinationMutationOutcome::Unknown { evidence: message });
                }
                return Err(error);
            }
        };
        let readback = self.fetch_comment_exact(comment_record.provider_comment_id)?;
        self.validate_comment_wire(&readback, &plan.body, &plan.comment_author)?;
        if let Some(outcome) =
            self.preflight_after_comment_observed(&plan, &readback, effect_reconciliation)?
        {
            return Ok(outcome);
        }
        let evidence = AuthenticatedCommentEvidence::from_verified_transport(
            &forge_comment_from_wire(self.config.journal().anchor_item(), &readback)?,
            self.config.journal().anchor_item(),
        )?;
        let pointer = journal_pointer_from_comment(
            &plan.intent,
            &readback,
            &plan.payload_digest,
            comment_record.provider_comment_id,
        )?;
        let cas_receipt = match self.run_cas_phase(
            wal,
            &plan.cas_effect_id,
            &plan.plan_digest,
            &plan.intent,
            &pointer,
            &plan.payload_digest,
        ) {
            Ok(receipt) => receipt,
            Err(error) => {
                let message = format!("{error:#}");
                if message.contains("unknown coordination") {
                    return Ok(CoordinationMutationOutcome::Unknown { evidence: message });
                }
                return Err(error);
            }
        };
        let merged = CoordinationJournalMutationRecord {
            comment: Some(comment_record),
            cas: Some(cas_receipt.clone()),
            ..latest_coordination_mutation_record(wal, &plan.comment_effect_id)?.1
        };
        Self::finalize_mutation_wal_if_nonterminal(
            wal,
            &plan.comment_effect_id,
            &plan.cas_effect_id,
            &merged,
        )?;
        let entry = VerifiedJournalEntry::new(
            pointer,
            cas_receipt.commit_oid,
            cas_receipt.parent_oid,
            evidence,
        )?;
        let history = TrustedFiniteJournalHistory::from_transport_verified_entries(
            self.config.journal(),
            self.history_prefix_plus(entry.clone())?,
        )?;
        let snapshot = match self.reduce_loaded_history(&history, effect_reconciliation) {
            Ok(snapshot) => snapshot,
            Err(error) => {
                return Ok(CoordinationMutationOutcome::Unknown {
                    evidence: format!("{error:#}"),
                });
            }
        };
        Ok(CoordinationMutationOutcome::Applied {
            entry: Box::new(entry),
            snapshot,
        })
    }

    fn preflight_before_first_mutation(
        &self,
        wal: &EffectWal,
        plan: &CoordinationGithubIntentApplyPlan,
        effect_reconciliation: Option<&dyn EffectReconciliationVerifier>,
    ) -> Result<Option<CoordinationMutationOutcome>> {
        let history = self.load_trusted_history()?;
        let snapshot = self.reduce_loaded_history(&history, effect_reconciliation)?;
        if plan.intent.expected_parent_oid() != snapshot.journal_head_oid() {
            return Ok(Some(CoordinationMutationOutcome::Unknown {
                evidence: "in-flight intent parent does not match current journal tip".to_string(),
            }));
        }
        match preflight_proposed_journal_transition(
            self.config.journal(),
            &snapshot,
            &plan.intent,
            &ProposedIntentAdmission {
                bound_actor: plan.comment_author.clone(),
                timing: IntentAdmissionTiming::PreflightDeferred,
            },
            effect_reconciliation,
        ) {
            Ok(()) => {}
            Err(error) => {
                return Ok(Some(preflight_refusal_outcome(
                    wal,
                    plan,
                    error,
                    "coordination transition refused after a prior effect may have started",
                )));
            }
        }
        if matches!(
            plan.intent.action(),
            CoordinationIntentAction::Takeover { .. }
        ) {
            match self.preflight_takeover_provider_time_refusal(
                &snapshot,
                plan,
                effect_reconciliation,
            ) {
                Ok(()) => {}
                Err(TakeoverProviderTimePreflightFailure::JournalHeadRace) => {
                    return Ok(Some(CoordinationMutationOutcome::Unknown {
                        evidence: "in-flight intent parent does not match current journal tip"
                            .to_string(),
                    }));
                }
                Err(TakeoverProviderTimePreflightFailure::Refused(error)) => {
                    return Ok(Some(preflight_refusal_outcome(
                        wal,
                        plan,
                        error,
                        "coordination takeover provider-time refusal after a prior effect may have started",
                    )));
                }
            }
        }
        Ok(None)
    }

    fn preflight_takeover_provider_time_refusal(
        &self,
        snapshot: &AuthoritySnapshot,
        plan: &CoordinationGithubIntentApplyPlan,
        effect_reconciliation: Option<&dyn EffectReconciliationVerifier>,
    ) -> Result<(), TakeoverProviderTimePreflightFailure> {
        let observed = self
            .journal_ref_head_with_provider_time()
            .map_err(TakeoverProviderTimePreflightFailure::Refused)?;
        if observed.head_oid != snapshot.journal_head_oid() {
            return Err(TakeoverProviderTimePreflightFailure::JournalHeadRace);
        }
        preflight_proposed_journal_transition(
            self.config.journal(),
            snapshot,
            &plan.intent,
            &ProposedIntentAdmission {
                bound_actor: plan.comment_author.clone(),
                timing: IntentAdmissionTiming::Observed(observed.provider_time),
            },
            effect_reconciliation,
        )
        .map_err(TakeoverProviderTimePreflightFailure::Refused)?;
        Ok(())
    }

    fn preflight_after_comment_observed(
        &self,
        plan: &CoordinationGithubIntentApplyPlan,
        readback: &GithubCommentWire,
        effect_reconciliation: Option<&dyn EffectReconciliationVerifier>,
    ) -> Result<Option<CoordinationMutationOutcome>> {
        let history = self.load_trusted_history()?;
        let snapshot = self.reduce_loaded_history(&history, effect_reconciliation)?;
        if plan.intent.expected_parent_oid() != snapshot.journal_head_oid() {
            return Ok(Some(CoordinationMutationOutcome::Unknown {
                evidence: "coordination comment was posted but journal tip moved before CAS"
                    .to_string(),
            }));
        }
        let observed_at = ForgeTimestamp::new(&readback.created_at)
            .context("authenticated coordination comment timestamp")?;
        match preflight_proposed_journal_transition(
            self.config.journal(),
            &snapshot,
            &plan.intent,
            &ProposedIntentAdmission {
                bound_actor: plan.comment_author.clone(),
                timing: IntentAdmissionTiming::Observed(observed_at),
            },
            effect_reconciliation,
        ) {
            Ok(()) => Ok(None),
            Err(error) => Ok(Some(CoordinationMutationOutcome::Unknown {
                evidence: format!(
                    "coordination comment was posted but semantic transition was refused: {error:#}"
                ),
            })),
        }
    }

    fn history_for_committed_nonce(
        &self,
        event_nonce: &str,
    ) -> Result<Option<TrustedFiniteJournalHistory>> {
        let history = self.load_trusted_history()?;
        Ok(history
            .verified_entries()
            .iter()
            .any(|entry| entry.pointer().event_nonce() == event_nonce)
            .then_some(history))
    }

    fn reconcile_and_finish_committed_apply(
        &self,
        wal: &mut EffectWal,
        replay: CoordinationGithubCommittedReplay,
        effect_reconciliation: Option<&dyn EffectReconciliationVerifier>,
    ) -> Result<CoordinationMutationOutcome> {
        let CoordinationGithubCommittedReplay {
            plan,
            entry,
            history,
        } = replay;
        if let Err(error) = self.validate_committed_entry_against_authorized_intent(
            &entry,
            &plan.intent,
            &plan.body,
            &plan.payload_digest,
            &plan.comment_author,
        ) {
            return Ok(CoordinationMutationOutcome::NotApplied {
                reason: format!("{error:#}"),
            });
        }
        let pointer = entry.pointer().clone();
        let (comment_receipt, comment_database_id) =
            match self.committed_comment_receipt_from_branch_readback(&entry) {
                Ok(value) => value,
                Err(error) => {
                    let message = format!("{error:#}");
                    if message.contains("unknown coordination") {
                        return Ok(CoordinationMutationOutcome::Unknown { evidence: message });
                    }
                    return Ok(CoordinationMutationOutcome::NotApplied { reason: message });
                }
            };
        let readback = self.fetch_comment_exact(comment_database_id)?;
        self.validate_comment_wire(&readback, &plan.body, &plan.comment_author)?;
        let readback_pointer = journal_pointer_from_comment(
            &plan.intent,
            &readback,
            &plan.payload_digest,
            comment_database_id,
        )?;
        if readback_pointer != pointer {
            return Ok(CoordinationMutationOutcome::NotApplied {
                reason: "committed journal pointer contradicts authenticated comment readback"
                    .to_string(),
            });
        }
        let cas_receipt = CoordinationCasReceipt {
            commit_oid: entry.commit_oid().to_string(),
            parent_oid: entry.parent_oid().to_string(),
        };
        if let Err(error) = self.verify_cas_receipt_from_observed(
            &cas_receipt.commit_oid,
            &cas_receipt.parent_oid,
            &pointer,
        ) {
            let message = format!("{error:#}");
            if message.contains("unknown coordination") {
                return Ok(CoordinationMutationOutcome::Unknown { evidence: message });
            }
            return Ok(CoordinationMutationOutcome::NotApplied { reason: message });
        }
        let merged_comment = comment_receipt.clone();
        let merged_cas = cas_receipt.clone();
        if let Err(error) = self.reconcile_committed_mutation_wal_write_free(
            wal,
            CoordinationGithubWalReceiptBinding {
                comment_effect_id: plan.comment_effect_id.clone(),
                cas_effect_id: plan.cas_effect_id.clone(),
                plan_digest: plan.plan_digest.clone(),
                comment_receipt,
                cas_receipt,
                pointer,
            },
        ) {
            let message = format!("{error:#}");
            if message.contains("unknown coordination") {
                return Ok(CoordinationMutationOutcome::Unknown { evidence: message });
            }
            return Ok(CoordinationMutationOutcome::NotApplied { reason: message });
        }
        let merged = CoordinationJournalMutationRecord {
            comment: Some(merged_comment),
            cas: Some(merged_cas),
            ..latest_coordination_mutation_record(wal, &plan.comment_effect_id)?.1
        };
        Self::finalize_mutation_wal_if_nonterminal(
            wal,
            &plan.comment_effect_id,
            &plan.cas_effect_id,
            &merged,
        )?;
        let snapshot = self.reduce_loaded_history(&history, effect_reconciliation)?;
        Ok(CoordinationMutationOutcome::Applied {
            entry: Box::new(entry),
            snapshot,
        })
    }

    fn committed_comment_receipt_from_branch_readback(
        &self,
        entry: &VerifiedJournalEntry,
    ) -> Result<(CoordinationCommentReceipt, u64)> {
        let comments = self.complete_anchor_comment_index()?;
        for comment in comments.values() {
            let provider_id = github_node_object_id(ProviderObjectKind::Comment, &comment.node_id)?;
            if provider_id != *entry.comment().provider_comment_id() {
                continue;
            }
            self.validate_comment_membership(comment)?;
            if comment.body != entry.comment().body() {
                bail!("committed journal comment body contradicts authenticated thread readback");
            }
            let author = github_wire_actor(&comment.user)?;
            if author != *entry.comment().author() {
                bail!("committed journal comment author contradicts authenticated thread readback");
            }
            return Ok((
                CoordinationCommentReceipt {
                    provider_comment_id: comment.id,
                    url: comment.html_url.clone(),
                    author_login: comment.user.login.clone(),
                },
                comment.id,
            ));
        }
        bail!("unknown coordination: committed journal comment is absent from authenticated thread readback");
    }

    fn reconcile_committed_mutation_wal_write_free(
        &self,
        wal: &mut EffectWal,
        binding: CoordinationGithubWalReceiptBinding,
    ) -> Result<()> {
        let CoordinationGithubWalReceiptBinding {
            comment_effect_id,
            cas_effect_id,
            plan_digest,
            comment_receipt,
            cas_receipt,
            pointer,
        } = binding;
        let (comment_phase, comment_current) =
            latest_coordination_mutation_record(wal, &comment_effect_id)?;
        let (cas_phase, cas_current) = latest_coordination_mutation_record(wal, &cas_effect_id)?;
        if comment_current.plan_digest != plan_digest || cas_current.plan_digest != plan_digest {
            bail!("committed recovery ledger belongs to a different exact plan");
        }
        if let Some(stored) = &comment_current.comment {
            if stored != &comment_receipt {
                bail!(
                    "committed recovery comment ledger contradicts authenticated branch evidence"
                );
            }
        }
        if let Some(stored) = &cas_current.cas {
            if stored != &cas_receipt {
                bail!("committed recovery CAS ledger contradicts authenticated branch evidence");
            }
        }
        Self::advance_committed_comment_wal_write_free(
            wal,
            &comment_effect_id,
            comment_phase,
            &comment_current,
            &comment_receipt,
        )?;
        self.advance_committed_cas_wal_write_free(
            wal,
            &cas_effect_id,
            cas_phase,
            &cas_current,
            &cas_receipt,
            &pointer,
        )?;
        Ok(())
    }

    fn advance_committed_comment_wal_write_free(
        wal: &mut EffectWal,
        effect_id: &str,
        phase: EffectPhase,
        current: &CoordinationJournalMutationRecord,
        receipt: &CoordinationCommentReceipt,
    ) -> Result<()> {
        let observed_record = CoordinationJournalMutationRecord {
            comment: Some(receipt.clone()),
            ..current.clone()
        };
        match phase {
            EffectPhase::Completed => Ok(()),
            EffectPhase::Observed => {
                if current.comment.as_ref() != Some(receipt) {
                    bail!("committed recovery comment ledger omitted its observed prior-effect receipt");
                }
                Ok(())
            }
            EffectPhase::Started => {
                wal.observed(effect_id, &observed_record)?;
                Ok(())
            }
            EffectPhase::Planned => {
                wal.started(effect_id, current)?;
                wal.observed(effect_id, &observed_record)?;
                Ok(())
            }
        }
    }

    fn advance_committed_cas_wal_write_free(
        &self,
        wal: &mut EffectWal,
        effect_id: &str,
        phase: EffectPhase,
        current: &CoordinationJournalMutationRecord,
        receipt: &CoordinationCasReceipt,
        pointer: &JournalPointer,
    ) -> Result<()> {
        self.verify_cas_receipt(receipt, pointer)?;
        let observed_record = CoordinationJournalMutationRecord {
            cas: Some(receipt.clone()),
            ..current.clone()
        };
        match phase {
            EffectPhase::Completed => Ok(()),
            EffectPhase::Observed => {
                if current.cas.as_ref() != Some(receipt) {
                    bail!(
                        "committed recovery CAS ledger omitted its observed prior-effect receipt"
                    );
                }
                Ok(())
            }
            EffectPhase::Started => {
                wal.observed(effect_id, &observed_record)?;
                Ok(())
            }
            EffectPhase::Planned => {
                wal.started(effect_id, current)?;
                wal.observed(effect_id, &observed_record)?;
                Ok(())
            }
        }
    }

    fn validate_committed_entry_against_authorized_intent(
        &self,
        entry: &VerifiedJournalEntry,
        intent: &CoordinationIntent,
        body: &str,
        payload_digest: &str,
        comment_author: &ForgeActor,
    ) -> Result<()> {
        let pointer = entry.pointer();
        if pointer.event_nonce() != intent.event_nonce() {
            bail!("committed journal entry event nonce contradicts the authorized intent");
        }
        if pointer.body_sha256() != payload_digest {
            bail!("committed journal entry body digest contradicts the authorized intent");
        }
        if pointer.expected_parent_oid() != intent.expected_parent_oid() {
            bail!("committed journal entry expected parent contradicts the authorized intent");
        }
        if entry.parent_oid() != pointer.expected_parent_oid() {
            bail!("committed journal entry parent contradicts its pointer expected head");
        }
        if entry.comment().body() != body {
            bail!("committed journal comment body contradicts the authorized intent");
        }
        if entry.comment().author() != comment_author {
            bail!("committed journal comment author contradicts the authorized actor");
        }
        if entry.comment().item() != self.config.journal().anchor_item() {
            bail!("committed journal comment anchor contradicts the configured journal item");
        }
        Ok(())
    }

    fn finalize_mutation_wal_if_nonterminal(
        wal: &mut EffectWal,
        comment_effect_id: &str,
        cas_effect_id: &str,
        merged: &CoordinationJournalMutationRecord,
    ) -> Result<()> {
        if wal.phase(cas_effect_id) != Some(EffectPhase::Completed) {
            wal.completed(cas_effect_id, merged)?;
        }
        if wal.phase(comment_effect_id) != Some(EffectPhase::Completed) {
            wal.completed(comment_effect_id, merged)?;
        }
        Ok(())
    }

    fn run_comment_phase(
        &self,
        wal: &mut EffectWal,
        comment_effect_id: &str,
        plan_digest: &str,
        body: &str,
        comment_author: &ForgeActor,
    ) -> Result<CoordinationCommentReceipt> {
        let (phase, current) = latest_coordination_mutation_record(wal, comment_effect_id)?;
        if current.plan_digest != plan_digest {
            bail!("coordination comment ledger belongs to a different exact plan");
        }
        match phase {
            EffectPhase::Completed | EffectPhase::Observed => {
                let receipt = current
                    .comment
                    .clone()
                    .context("comment ledger omitted its durable receipt")?;
                Ok(receipt)
            }
            EffectPhase::Started => match self.reconcile_comment_once(body, comment_author)? {
                ReconcileComment::Exact(receipt) => {
                    wal.observed(
                        comment_effect_id,
                        &CoordinationJournalMutationRecord {
                            comment: Some(receipt.clone()),
                            ..current
                        },
                    )?;
                    Ok(receipt)
                }
                ReconcileComment::Absent | ReconcileComment::Ambiguous => {
                    bail!("unknown coordination: comment POST outcome is uncertain after durable start");
                }
            },
            EffectPhase::Planned => match self.reconcile_comment_once(body, comment_author)? {
                ReconcileComment::Exact(receipt) => {
                    wal.observed(
                        comment_effect_id,
                        &CoordinationJournalMutationRecord {
                            comment: Some(receipt.clone()),
                            ..current
                        },
                    )?;
                    Ok(receipt)
                }
                ReconcileComment::Absent => {
                    wal.started(comment_effect_id, &current)?;
                    let posted = self.post_intent_comment(body, &current.payload_digest)?;
                    let readback = self.fetch_comment_exact(posted.provider_comment_id)?;
                    self.validate_comment_wire(&readback, body, comment_author)?;
                    wal.observed(
                        comment_effect_id,
                        &CoordinationJournalMutationRecord {
                            comment: Some(posted.clone()),
                            ..current
                        },
                    )?;
                    Ok(posted)
                }
                ReconcileComment::Ambiguous => {
                    bail!("coordination anchor comment thread is ambiguous during reconciliation");
                }
            },
        }
    }

    fn run_cas_phase(
        &self,
        wal: &mut EffectWal,
        cas_effect_id: &str,
        plan_digest: &str,
        intent: &CoordinationIntent,
        pointer: &JournalPointer,
        payload_digest: &str,
    ) -> Result<CoordinationCasReceipt> {
        let (phase, current) = latest_coordination_mutation_record(wal, cas_effect_id)?;
        if current.plan_digest != plan_digest {
            bail!("coordination CAS ledger belongs to a different exact plan");
        }
        match phase {
            EffectPhase::Completed | EffectPhase::Observed => {
                let receipt = current
                    .cas
                    .clone()
                    .context("CAS ledger omitted its durable receipt")?;
                self.verify_cas_receipt(&receipt, pointer)?;
                Ok(receipt)
            }
            EffectPhase::Started => match self.reconcile_cas(intent.event_nonce(), pointer)? {
                ReconcileCas::Exact(receipt) => {
                    self.verify_cas_receipt(&receipt, pointer)?;
                    wal.observed(
                        cas_effect_id,
                        &CoordinationJournalMutationRecord {
                            cas: Some(receipt.clone()),
                            ..current
                        },
                    )?;
                    Ok(receipt)
                }
                ReconcileCas::Absent | ReconcileCas::Ambiguous => {
                    bail!("unknown coordination: CAS mutation outcome is uncertain after durable start");
                }
            },
            EffectPhase::Planned => match self.reconcile_cas(intent.event_nonce(), pointer)? {
                ReconcileCas::Exact(receipt) => {
                    self.verify_cas_receipt(&receipt, pointer)?;
                    wal.observed(
                        cas_effect_id,
                        &CoordinationJournalMutationRecord {
                            cas: Some(receipt.clone()),
                            ..current
                        },
                    )?;
                    Ok(receipt)
                }
                ReconcileCas::Absent => {
                    wal.started(cas_effect_id, &current)?;
                    let receipt = self.create_and_verify_cas_commit(
                        intent.expected_parent_oid(),
                        pointer,
                        intent.event_nonce(),
                        payload_digest,
                    )?;
                    wal.observed(
                        cas_effect_id,
                        &CoordinationJournalMutationRecord {
                            cas: Some(receipt.clone()),
                            ..current
                        },
                    )?;
                    Ok(receipt)
                }
                ReconcileCas::Ambiguous => {
                    bail!("coordination CAS mutation is ambiguous before durable start");
                }
            },
        }
    }

    fn history_prefix_plus(
        &self,
        entry: VerifiedJournalEntry,
    ) -> Result<Vec<VerifiedJournalEntry>> {
        let prior = self.load_trusted_history()?.verified_entries().to_vec();
        if prior
            .iter()
            .any(|existing| existing.pointer().event_nonce() == entry.pointer().event_nonce())
        {
            return Ok(prior);
        }
        if prior.last().map(|tip| tip.commit_oid()) == Some(entry.commit_oid()) {
            return Ok(prior);
        }
        let mut extended = prior;
        extended.push(entry);
        Ok(extended)
    }

    fn journal_ref_head(&self) -> Result<String> {
        let json = self.runner.run(
            &self.config,
            "gh coordination journal ref head",
            CoordinationGithubOperation::JournalRefHead {
                branch_name: self.config.branch_name.clone(),
            },
        )?;
        let wire: GithubRefWire =
            parse_authenticated_github_json(&json, "GitHub coordination journal ref")?;
        validate_observed_git_oid(&wire.object.sha)?;
        Ok(wire.object.sha)
    }

    fn journal_ref_head_with_provider_time(&self) -> Result<JournalRefHeadWithProviderTime> {
        let raw = self.runner.run(
            &self.config,
            "gh coordination journal ref head with provider time",
            CoordinationGithubOperation::JournalRefHeadWithProviderTime {
                branch_name: self.config.branch_name.clone(),
            },
        )?;
        let expected_ref = format!("refs/heads/{}", self.config.branch_name);
        parse_journal_ref_head_with_provider_time_response(&raw, &expected_ref)
    }

    fn complete_ancestry_to_anchor(&self, tip: &str) -> Result<Vec<VerifiedCommit>> {
        let anchor = self.config.journal().anchor_commit_oid();
        if tip == anchor {
            return Ok(Vec::new());
        }
        let mut chain = Vec::new();
        let mut current = tip.to_string();
        for _ in 0..=MAX_JOURNAL_ENTRIES {
            if current == anchor {
                return Ok(chain.into_iter().rev().collect());
            }
            let commit = self.fetch_commit(&current)?;
            if commit.parents.len() != 1 {
                bail!("coordination journal commit history is not a complete linear chain");
            }
            chain.push(commit.clone());
            current = commit.parents[0].sha.clone();
        }
        bail!("coordination journal ancestry exceeded its finite bound before reaching the anchor");
    }

    fn fetch_commit(&self, oid: &str) -> Result<VerifiedCommit> {
        validate_observed_git_oid(oid)?;
        let json = self.runner.run(
            &self.config,
            "gh coordination journal commit",
            CoordinationGithubOperation::Commit {
                oid: oid.to_string(),
            },
        )?;
        let wire: GithubCommitWire =
            parse_authenticated_github_json(&json, "GitHub coordination journal commit")?;
        if wire.sha != oid {
            bail!("GitHub returned a different commit OID than requested");
        }
        validate_observed_git_oid(&wire.commit.tree.sha)?;
        if wire.parents.len() > 1 {
            bail!("coordination journal commit has merge parents");
        }
        for parent in &wire.parents {
            validate_observed_git_oid(&parent.sha)?;
        }
        Ok(VerifiedCommit {
            sha: wire.sha,
            tree_sha: wire.commit.tree.sha,
            parents: wire.parents,
        })
    }

    fn verified_entry_from_commit(
        &self,
        commit: &VerifiedCommit,
        comments: &BTreeMap<u64, GithubCommentWire>,
    ) -> Result<VerifiedJournalEntry> {
        let parent_sha = commit
            .parents
            .first()
            .map(|parent| parent.sha.as_str())
            .context("coordination journal commit omitted its parent")?;
        let parent_commit = self.fetch_commit(parent_sha)?;
        let child_tree = self.fetch_tree(&commit.tree_sha)?;
        let parent_tree = self.fetch_tree(&parent_commit.tree_sha)?;
        let (pointer, _blob_sha) = self.pointer_from_tree(&child_tree, &parent_tree)?;
        let comment = comments
            .values()
            .find(|comment| {
                matches!(
                    github_node_object_id(ProviderObjectKind::Comment, &comment.node_id),
                    Ok(id) if &id == pointer.provider_comment_id()
                )
            })
            .context("coordination journal pointer references a missing anchor comment")?;
        let item = self.config.journal().anchor_item();
        self.validate_comment_membership(comment)?;
        let author = github_wire_actor(&comment.user)?;
        if !self.config.journal().is_trusted_actor(&author) {
            bail!("coordination journal comment author is not trusted");
        }
        let evidence = AuthenticatedCommentEvidence::from_verified_transport(
            &forge_comment_from_wire(item, comment)?,
            item,
        )?;
        VerifiedJournalEntry::new(
            pointer,
            commit.sha.clone(),
            parent_sha.to_string(),
            evidence,
        )
    }

    fn fetch_tree(&self, tree_oid: &str) -> Result<GithubTreeWire> {
        validate_observed_git_oid(tree_oid)?;
        let json = self.runner.run(
            &self.config,
            "gh coordination journal tree",
            CoordinationGithubOperation::Tree {
                tree_oid: tree_oid.to_string(),
            },
        )?;
        let tree: GithubTreeWire =
            parse_authenticated_github_json(&json, "GitHub coordination journal tree")?;
        if tree.sha != tree_oid {
            bail!("GitHub returned a different tree OID than requested");
        }
        if tree.truncated {
            bail!("coordination journal tree observation was truncated");
        }
        for entry in &tree.tree {
            validate_observed_git_oid(&entry.sha)?;
        }
        Ok(tree)
    }

    fn pointer_from_tree(
        &self,
        child_tree: &GithubTreeWire,
        parent_tree: &GithubTreeWire,
    ) -> Result<(JournalPointer, String)> {
        verify_strict_tree_delta(parent_tree, child_tree, self.config.pointer_path())?;
        let entry = child_tree
            .tree
            .iter()
            .find(|entry| entry.path == self.config.pointer_path())
            .context("coordination journal commit tree omitted the pointer path")?;
        if entry.type_field != "blob" || entry.mode != "100644" {
            bail!("coordination journal pointer path is not a regular non-executable blob");
        }
        let blob = self.fetch_blob(&entry.sha)?;
        let decoded = decode_base64(&blob.content)?;
        if decoded.len() > MAX_POINTER_FILE_BYTES {
            bail!("coordination journal pointer blob exceeds its byte bound");
        }
        verify_git_blob_oid(&decoded, &entry.sha)?;
        let pointer = JournalPointer::parse_pointer_file(
            &String::from_utf8(decoded)
                .context("coordination journal pointer blob was not UTF-8")?,
        )?;
        Ok((pointer, entry.sha.clone()))
    }

    fn fetch_blob(&self, blob_oid: &str) -> Result<GithubBlobWire> {
        validate_observed_git_oid(blob_oid)?;
        let blob_json = self.runner.run(
            &self.config,
            "gh coordination journal pointer blob",
            CoordinationGithubOperation::Blob {
                blob_oid: blob_oid.to_string(),
            },
        )?;
        let blob: GithubBlobWire = parse_authenticated_github_json(
            &blob_json,
            "GitHub coordination journal pointer blob",
        )?;
        if blob.sha != blob_oid {
            bail!("GitHub returned a different blob OID than requested");
        }
        if blob.encoding != "base64" {
            bail!("coordination journal pointer blob used an unsupported encoding");
        }
        let decoded = decode_base64(&blob.content)?;
        if blob.size != decoded.len() as u64 {
            bail!("coordination journal pointer blob declared size did not match decoded bytes");
        }
        verify_git_blob_oid(&decoded, blob_oid)?;
        Ok(blob)
    }

    fn complete_anchor_comment_index(&self) -> Result<BTreeMap<u64, GithubCommentWire>> {
        let number = self.config.journal().anchor_item().number();
        let mut comments = BTreeMap::new();
        for page in 1..=AUTHENTICATED_GITHUB_MAX_PAGES {
            let json = self.runner.run(
                &self.config,
                "gh coordination anchor comments",
                CoordinationGithubOperation::AnchorItemComments { number, page },
            )?;
            let page_comments: Vec<GithubCommentWire> =
                parse_authenticated_github_json(&json, "GitHub coordination anchor comments")?;
            let page_len = page_comments.len();
            if page_len == 0 {
                return Ok(comments);
            }
            if comments.len().saturating_add(page_len) > MAX_GITHUB_COMMENT_CANDIDATES {
                bail!("coordination anchor comment thread exceeded its candidate bound");
            }
            for comment in page_comments {
                if comment.id == 0 {
                    bail!("GitHub comment omitted a positive database id");
                }
                if comments.insert(comment.id, comment).is_some() {
                    bail!("coordination anchor comment thread reused a comment id");
                }
            }
            if page_len < AUTHENTICATED_GITHUB_PAGE_SIZE {
                return Ok(comments);
            }
            if page == AUTHENTICATED_GITHUB_MAX_PAGES {
                bail!("coordination anchor comment thread pagination did not terminate within its finite bound");
            }
        }
        Ok(comments)
    }

    fn post_intent_comment(
        &self,
        body: &str,
        payload_digest: &str,
    ) -> Result<CoordinationCommentReceipt> {
        let json = self.runner.run(
            &self.config,
            "gh coordination intent comment",
            CoordinationGithubOperation::PostIssueComment {
                number: self.config.journal().anchor_item().number(),
                body: body.to_string(),
                payload_digest: payload_digest.to_string(),
            },
        )?;
        let comment: GithubCommentWire =
            parse_authenticated_github_json(&json, "GitHub coordination intent comment")?;
        self.validate_comment_membership(&comment)?;
        Ok(CoordinationCommentReceipt {
            provider_comment_id: comment.id,
            url: comment.html_url,
            author_login: comment.user.login.clone(),
        })
    }

    fn fetch_comment_exact(&self, comment_id: u64) -> Result<GithubCommentWire> {
        let json = self.runner.run(
            &self.config,
            "gh coordination comment exact",
            CoordinationGithubOperation::IssueComment { comment_id },
        )?;
        let comment: GithubCommentWire =
            parse_authenticated_github_json(&json, "GitHub coordination comment exact")?;
        if comment.id != comment_id {
            bail!("GitHub returned a different comment id than requested");
        }
        self.validate_comment_membership(&comment)?;
        Ok(comment)
    }

    fn validate_comment_wire(
        &self,
        comment: &GithubCommentWire,
        expected_body: &str,
        expected_author: &ForgeActor,
    ) -> Result<()> {
        self.validate_comment_membership(comment)?;
        if comment.body != expected_body {
            bail!("coordination intent comment body changed after posting");
        }
        let author = github_wire_actor(&comment.user)?;
        if author != *expected_author {
            bail!("coordination intent comment author does not match the authorized actor");
        }
        Ok(())
    }

    fn validate_comment_membership(&self, comment: &GithubCommentWire) -> Result<()> {
        if comment.issue_url != self.config.anchor_issue_api_url {
            bail!("coordination comment is not bound to the configured anchor issue API URL");
        }
        if comment.created_at != comment.updated_at {
            bail!("coordination comment shows post-create edit evidence");
        }
        validate_bound_github_comment_html_url(
            &comment.html_url,
            &self.config.repository,
            self.config.journal().anchor_item().number(),
            comment.id,
        )?;
        Ok(())
    }

    fn create_and_verify_cas_commit(
        &self,
        expected_parent: &str,
        pointer: &JournalPointer,
        event_nonce: &str,
        payload_digest: &str,
    ) -> Result<CoordinationCasReceipt> {
        validate_observed_git_oid(expected_parent)?;
        let pointer_contents = pointer.render_pointer_file()?;
        let json = self.runner.run(
            &self.config,
            "gh coordination journal CAS",
            CoordinationGithubOperation::CreateCommitOnBranch {
                branch_name: self.config.branch_name.clone(),
                expected_head_oid: expected_parent.to_string(),
                pointer_path: self.config.pointer_path.clone(),
                pointer_contents,
                event_nonce: event_nonce.to_string(),
                payload_digest: payload_digest.to_string(),
            },
        )?;
        let wire: GithubCreateCommitWire =
            parse_authenticated_github_json(&json, "GitHub coordination journal CAS")?;
        let commit_oid = wire.data.create_commit_on_branch.commit.oid;
        validate_observed_git_oid(&commit_oid)?;
        let receipt =
            self.verify_cas_receipt_from_observed(&commit_oid, expected_parent, pointer)?;
        Ok(receipt)
    }

    fn verify_cas_receipt(
        &self,
        receipt: &CoordinationCasReceipt,
        pointer: &JournalPointer,
    ) -> Result<()> {
        self.verify_cas_receipt_from_observed(&receipt.commit_oid, &receipt.parent_oid, pointer)
            .map(|_| ())
    }

    fn verify_cas_receipt_from_observed(
        &self,
        commit_oid: &str,
        expected_parent: &str,
        pointer: &JournalPointer,
    ) -> Result<CoordinationCasReceipt> {
        let commit = self.fetch_commit(commit_oid)?;
        if commit.parents.len() != 1 || commit.parents[0].sha != expected_parent {
            bail!("observed CAS commit parent does not match the authorized expected head");
        }
        let parent_commit = self.fetch_commit(expected_parent)?;
        let child_tree = self.fetch_tree(&commit.tree_sha)?;
        let parent_tree = self.fetch_tree(&parent_commit.tree_sha)?;
        let (observed_pointer, _) = self.pointer_from_tree(&child_tree, &parent_tree)?;
        if observed_pointer != *pointer {
            bail!("observed CAS commit pointer does not match the authorized journal pointer");
        }
        self.ensure_commit_reachable_from_journal_ref(commit_oid)?;
        Ok(CoordinationCasReceipt {
            commit_oid: commit_oid.to_string(),
            parent_oid: expected_parent.to_string(),
        })
    }

    fn ensure_commit_reachable_from_journal_ref(&self, commit_oid: &str) -> Result<()> {
        validate_observed_git_oid(commit_oid)?;
        let tip = self.journal_ref_head()?;
        let anchor = self.config.journal().anchor_commit_oid();
        if commit_oid == anchor {
            bail!("CAS receipt commit must extend the journal beyond the configured anchor");
        }
        let mut current = tip;
        for _ in 0..=MAX_JOURNAL_ENTRIES {
            if current == commit_oid {
                return Ok(());
            }
            if current == anchor {
                break;
            }
            let commit = self.fetch_commit(&current)?;
            if commit.parents.len() != 1 {
                bail!("protected journal ref ancestry is not a complete linear chain");
            }
            current = commit.parents[0].sha.clone();
        }
        bail!("CAS receipt commit is not reachable from the protected journal ref");
    }

    fn reconcile_comment_once(&self, body: &str, author: &ForgeActor) -> Result<ReconcileComment> {
        let comments = self.complete_anchor_comment_index()?;
        let mut matched = None;
        for comment in comments.values() {
            if comment.body != body {
                continue;
            }
            if github_wire_actor(&comment.user)? != *author {
                continue;
            }
            self.validate_comment_membership(comment)?;
            if matched.is_some() {
                return Ok(ReconcileComment::Ambiguous);
            }
            matched = Some(CoordinationCommentReceipt {
                provider_comment_id: comment.id,
                url: comment.html_url.clone(),
                author_login: comment.user.login.clone(),
            });
        }
        Ok(match matched {
            Some(receipt) => ReconcileComment::Exact(receipt),
            None => ReconcileComment::Absent,
        })
    }

    fn reconcile_cas(&self, event_nonce: &str, pointer: &JournalPointer) -> Result<ReconcileCas> {
        let tip = self.journal_ref_head()?;
        let mut matches = 0_u8;
        let mut matched = None;
        let mut current = tip;
        for _ in 0..=MAX_JOURNAL_ENTRIES {
            if current == self.config.journal().anchor_commit_oid() {
                break;
            }
            let commit = self.fetch_commit(&current)?;
            if commit.parents.len() != 1 {
                return Ok(ReconcileCas::Ambiguous);
            }
            let parent_sha = &commit.parents[0].sha;
            let parent_commit = self.fetch_commit(parent_sha)?;
            let child_tree = self.fetch_tree(&commit.tree_sha)?;
            let parent_tree = self.fetch_tree(&parent_commit.tree_sha)?;
            let parsed = self
                .pointer_from_tree(&child_tree, &parent_tree)
                .map(|(pointer, _)| pointer);
            if let Ok(parsed) = parsed {
                if parsed.event_nonce() == event_nonce && parsed == *pointer {
                    matches = matches.saturating_add(1);
                    matched = Some(CoordinationCasReceipt {
                        commit_oid: commit.sha.clone(),
                        parent_oid: parent_sha.clone(),
                    });
                }
            }
            current = parent_sha.clone();
        }
        match matches {
            0 => Ok(ReconcileCas::Absent),
            1 => Ok(ReconcileCas::Exact(matched.expect("matched CAS"))),
            _ => Ok(ReconcileCas::Ambiguous),
        }
    }
}

enum ReconcileComment {
    Exact(CoordinationCommentReceipt),
    Absent,
    Ambiguous,
}

enum ReconcileCas {
    Exact(CoordinationCasReceipt),
    Absent,
    Ambiguous,
}

fn journal_pointer_from_comment(
    intent: &CoordinationIntent,
    comment: &GithubCommentWire,
    payload_digest: &str,
    comment_database_id: u64,
) -> Result<JournalPointer> {
    if comment.id != comment_database_id {
        bail!("coordination comment id does not match its receipt");
    }
    JournalPointer::new(
        intent.event_nonce(),
        github_node_object_id(ProviderObjectKind::Comment, &comment.node_id)?,
        payload_digest,
        intent.expected_parent_oid(),
    )
}

fn latest_coordination_mutation_record(
    wal: &EffectWal,
    effect_id: &str,
) -> Result<(EffectPhase, CoordinationJournalMutationRecord)> {
    let phase = wal
        .phase(effect_id)
        .context("coordination journal mutation ledger omitted its effect")?;
    let event = wal
        .events()
        .iter()
        .rev()
        .find(|event| event.effect_id == effect_id)
        .context("coordination journal mutation ledger omitted its latest event")?;
    let record: CoordinationJournalMutationRecord = serde_json::from_value(event.data.clone())
        .context("coordination journal mutation record is malformed")?;
    if event.phase != phase || record.version != COORDINATION_MUTATION_VERSION {
        bail!("coordination journal mutation phase or version is inconsistent");
    }
    validate_external_digest(
        &record.plan_digest,
        "coordination journal mutation plan digest",
    )?;
    Ok((phase, record))
}

fn forge_comment_from_wire(_item: &ForgeItem, comment: &GithubCommentWire) -> Result<ForgeComment> {
    ForgeComment::new(
        github_node_object_id(ProviderObjectKind::Comment, &comment.node_id)?,
        github_wire_actor(&comment.user)?,
        comment.body.clone(),
        comment.html_url.clone(),
        ForgeTimestamp::new(comment.created_at.clone())?,
    )
    .context("forge comment construction failed")
}

fn github_wire_actor(actor: &GithubApiActor) -> Result<ForgeActor> {
    let reported = match actor.kind.to_ascii_lowercase().as_str() {
        "user" => ReportedActorKind::Human,
        "bot" => ReportedActorKind::Bot,
        "organization" => ReportedActorKind::Organization,
        _ => ReportedActorKind::Unknown,
    };
    ForgeActor::new(
        "github",
        github_node_object_id(ProviderObjectKind::Actor, &actor.node_id)?,
        actor.login.to_ascii_lowercase(),
        reported,
    )
}

fn journal_branch_name(journal_ref: &str) -> Result<String> {
    journal_ref
        .strip_prefix("refs/heads/")
        .context("journal ref must use refs/heads")
        .map(str::to_string)
}

fn validate_branch_name(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 256
        || value.starts_with('/')
        || value.ends_with('/')
        || value.contains("//")
        || value.contains('\\')
        || value.contains("..")
    {
        bail!("journal branch name is not canonical");
    }
    Ok(())
}

fn validate_pointer_path(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 256
        || value.contains('/')
        || value.starts_with('.')
        || value.ends_with('/')
        || value.contains("//")
        || value.contains('\\')
        || value.contains("..")
        || value.starts_with(".agents/")
        || value.starts_with(".maco/")
    {
        bail!("coordination pointer path must be one top-level repository-relative filename");
    }
    Ok(())
}

fn repository_name_with_owner(repository: &GithubRepositoryIdentity) -> String {
    format!("{}/{}", repository.owner, repository.name)
}

fn encode_github_path_segment(segment: &str) -> String {
    segment
        .bytes()
        .map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                char::from(byte).to_string()
            }
            _ => format!("%{byte:02X}"),
        })
        .collect()
}

fn validate_observed_git_oid(oid: &str) -> Result<()> {
    validate_authenticated_github_oid(oid)?;
    if oid.len() != 40 {
        bail!("coordination GitHub object id must be a 40-character commit/tree/blob OID");
    }
    Ok(())
}

fn verify_strict_tree_delta(
    parent_tree: &GithubTreeWire,
    child_tree: &GithubTreeWire,
    pointer_path: &str,
) -> Result<()> {
    let parent_map = tree_entry_map(parent_tree)?;
    let child_map = tree_entry_map(child_tree)?;
    for (path, entry) in &parent_map {
        if path == pointer_path {
            continue;
        }
        if child_map.get(path) != Some(entry) {
            bail!("coordination journal commit modified a non-pointer tree path");
        }
    }
    for (path, entry) in &child_map {
        if path == pointer_path {
            if entry.type_field != "blob" || entry.mode != "100644" {
                bail!("coordination journal pointer path is not a regular non-executable blob");
            }
            continue;
        }
        if parent_map.get(path) != Some(entry) {
            bail!("coordination journal commit introduced an unexpected tree path");
        }
    }
    child_map
        .get(pointer_path)
        .context("coordination journal commit tree omitted the pointer path")?;
    Ok(())
}

fn tree_entry_map(tree: &GithubTreeWire) -> Result<BTreeMap<String, GithubTreeEntryWire>> {
    let mut map = BTreeMap::new();
    for entry in &tree.tree {
        if map.insert(entry.path.clone(), entry.clone()).is_some() {
            bail!("coordination journal tree observation reused a path");
        }
    }
    Ok(map)
}

fn verify_git_blob_oid(decoded: &[u8], expected_oid: &str) -> Result<()> {
    validate_observed_git_oid(expected_oid)?;
    let hashed = Oid::hash_object(ObjectType::Blob, decoded)
        .context("failed to hash coordination journal pointer blob")?;
    if hashed.to_string() != expected_oid {
        bail!("coordination journal pointer blob content did not match its Git object id");
    }
    Ok(())
}

fn validate_bound_github_issue_html_url(
    url: &str,
    expected: &GithubRepositoryIdentity,
    expected_number: u64,
) -> Result<String> {
    if expected_number == 0 {
        bail!("GitHub issue receipt number was zero");
    }
    if url.is_empty()
        || url.len() > MAX_GITHUB_RECEIPT_URL_BYTES
        || url
            .as_bytes()
            .iter()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
        || url.contains(['?', '#', '%', '\\', '@'])
    {
        bail!("GitHub issue receipt URL was empty, noncanonical, or oversized");
    }
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
    let host = super::normalize_github_host(authority)?;
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

fn validate_bound_github_issue_api_url(
    url: &str,
    expected: &GithubRepositoryIdentity,
    expected_number: u64,
) -> Result<String> {
    if expected_number == 0 {
        bail!("GitHub issue API URL number was zero");
    }
    const PREFIX: &str = "https://api.github.com/repos/";
    if url.len() > MAX_GITHUB_RECEIPT_URL_BYTES
        || url
            .as_bytes()
            .iter()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
        || url.contains(['?', '#', '%', '\\', '@'])
        || !url.starts_with(PREFIX)
    {
        bail!("GitHub issue API URL was malformed or oversized");
    }
    let remainder = &url[PREFIX.len()..];
    let components = remainder.split('/').collect::<Vec<_>>();
    let issue_number = components
        .get(3)
        .and_then(|component| component.parse::<u64>().ok())
        .filter(|number| *number > 0);
    if components.len() != 4
        || components[2] != "issues"
        || issue_number != Some(expected_number)
        || !components[0].eq_ignore_ascii_case(&expected.owner)
        || !components[1].eq_ignore_ascii_case(&expected.name)
    {
        bail!("GitHub issue API URL did not match the bound repository and issue");
    }
    Ok(url.to_string())
}

fn validate_bound_github_comment_html_url(
    url: &str,
    expected: &GithubRepositoryIdentity,
    issue_number: u64,
    comment_id: u64,
) -> Result<()> {
    if comment_id == 0 || issue_number == 0 {
        bail!("GitHub comment URL identifiers must be positive");
    }
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
    if super::normalize_github_host(authority)? != authority || authority != expected.host {
        bail!("GitHub comment URL host did not match the repository");
    }
    let components = path[slash + 1..].split('/').collect::<Vec<_>>();
    if components.len() != 4
        || !components[0].eq_ignore_ascii_case(&expected.owner)
        || !components[1].eq_ignore_ascii_case(&expected.name)
        || components[2] != "issues"
        || components[3] != issue_number.to_string()
    {
        bail!("GitHub comment URL did not match its exact repository and issue");
    }
    let id = fragment
        .strip_prefix("issuecomment-")
        .and_then(|id| id.parse::<u64>().ok())
        .filter(|id| *id > 0)
        .context("GitHub comment URL fragment did not contain a canonical comment id")?;
    if id != comment_id || fragment != format!("issuecomment-{comment_id}") {
        bail!("GitHub comment URL comment id was not canonical");
    }
    Ok(())
}

fn decode_base64(input: &str) -> Result<Vec<u8>> {
    let filtered: Vec<u8> = input
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect();
    if filtered.len() > GH_CAPTURE_LIMIT_BYTES {
        bail!("coordination pointer blob exceeded its capture bound");
    }
    let mut output = Vec::with_capacity(filtered.len() / 4 * 3);
    let mut chunk = [0_u8; 4];
    let mut filled = 0_usize;
    for byte in filtered {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' => {
                chunk[filled] = 0;
                filled += 1;
                if filled == 4 {
                    output.push((chunk[0] << 2) | (chunk[1] >> 4));
                    if chunk[2] != 0 {
                        output.push(((chunk[1] & 0x0f) << 4) | (chunk[2] >> 2));
                    }
                    if chunk[3] != 0 {
                        output.push(((chunk[2] & 0x03) << 6) | chunk[3]);
                    }
                    break;
                }
                continue;
            }
            _ => bail!("coordination pointer blob was not canonical base64"),
        };
        chunk[filled] = value;
        filled += 1;
        if filled == 4 {
            output.push((chunk[0] << 2) | (chunk[1] >> 4));
            output.push(((chunk[1] & 0x0f) << 4) | (chunk[2] >> 2));
            output.push(((chunk[2] & 0x03) << 6) | chunk[3]);
            filled = 0;
        }
    }
    Ok(output)
}

#[derive(Debug, Clone)]
struct VerifiedCommit {
    sha: String,
    tree_sha: String,
    parents: Vec<GithubParentWire>,
}

#[derive(Debug, Deserialize)]
struct GithubBranchProtectionWire {
    enforce_admins: GithubProtectionToggle,
    #[serde(rename = "allow_force_pushes")]
    allow_force_pushes: GithubProtectionToggle,
    #[serde(rename = "allow_deletions")]
    allow_deletions: GithubProtectionToggle,
}

#[derive(Debug, Deserialize)]
struct GithubRepositoryMetadataWire {
    node_id: String,
    full_name: String,
}

#[derive(Debug, Deserialize)]
struct GithubIssueMetadataWire {
    node_id: String,
    number: u64,
    url: String,
    html_url: String,
    updated_at: String,
    pull_request: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct GithubProtectionToggle {
    enabled: bool,
}

#[derive(Debug, Deserialize)]
struct GithubRefWire {
    object: GithubRefObjectWire,
}

#[derive(Debug, Deserialize)]
struct GithubRefObjectWire {
    sha: String,
}

#[derive(Debug, Deserialize)]
struct GithubCommitWire {
    sha: String,
    commit: GithubCommitBodyWire,
    parents: Vec<GithubParentWire>,
}

#[derive(Debug, Deserialize)]
struct GithubCommitBodyWire {
    tree: GithubTreeShaWire,
}

#[derive(Debug, Deserialize)]
struct GithubTreeShaWire {
    sha: String,
}

#[derive(Debug, Clone, Deserialize)]
struct GithubParentWire {
    sha: String,
}

#[derive(Debug, Deserialize)]
struct GithubTreeWire {
    sha: String,
    truncated: bool,
    tree: Vec<GithubTreeEntryWire>,
}

#[derive(Debug, Deserialize, Clone, PartialEq, Eq)]
struct GithubTreeEntryWire {
    path: String,
    #[serde(rename = "type")]
    type_field: String,
    mode: String,
    sha: String,
}

#[derive(Debug, Deserialize)]
struct GithubBlobWire {
    sha: String,
    size: u64,
    encoding: String,
    content: String,
}

#[derive(Debug, Deserialize, Clone)]
struct GithubCommentWire {
    id: u64,
    node_id: String,
    html_url: String,
    issue_url: String,
    body: String,
    created_at: String,
    updated_at: String,
    user: GithubApiActor,
}

#[derive(Debug, Deserialize)]
struct GithubCreateCommitWire {
    data: GithubCreateCommitDataWire,
}

#[derive(Debug, Deserialize)]
struct GithubCreateCommitDataWire {
    #[serde(rename = "createCommitOnBranch")]
    create_commit_on_branch: GithubCreateCommitResultWire,
}

#[derive(Debug, Deserialize)]
struct GithubCreateCommitResultWire {
    commit: GithubCreateCommitOidWire,
}

#[derive(Debug, Deserialize)]
struct GithubCreateCommitOidWire {
    oid: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::effect_wal::{DefaultEffectWal, DefaultEffectWalSpec};
    use crate::publication::coordination_journal::CoordinationOwnerIdentity;
    use crate::sync_store::ClaimTiming;
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    const ANCHOR_OID: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const CHILD_OID: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const GRANDCHILD_OID: &str = "1111111111111111111111111111111111111111";
    const ANCHOR_TREE: &str = "cccccccccccccccccccccccccccccccccccccccc";
    const CHILD_TREE: &str = "dddddddddddddddddddddddddddddddddddddddd";
    const GRANDCHILD_TREE: &str = "2222222222222222222222222222222222222222";
    const POINTER_BLOB: &str = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
    const ISSUE_HTML_URL: &str = "https://github.com/meta-develop/maco/issues/89";
    const ISSUE_API_URL: &str = "https://api.github.com/repos/meta-develop/maco/issues/89";

    struct ScriptedCoordinationRunner {
        responses: Mutex<VecDeque<String>>,
        requests: Mutex<VecDeque<CoordinationGithubOperation>>,
    }

    impl ScriptedCoordinationRunner {
        fn new(responses: impl IntoIterator<Item = String>) -> Self {
            Self {
                responses: Mutex::new(responses.into_iter().collect()),
                requests: Mutex::new(VecDeque::new()),
            }
        }

        fn post_issue_comment_calls(&self) -> usize {
            self.requests
                .lock()
                .expect("requests")
                .iter()
                .filter(|operation| {
                    matches!(
                        operation,
                        CoordinationGithubOperation::PostIssueComment { .. }
                    )
                })
                .count()
        }

        fn create_commit_on_branch_calls(&self) -> usize {
            self.requests
                .lock()
                .expect("requests")
                .iter()
                .filter(|operation| {
                    matches!(
                        operation,
                        CoordinationGithubOperation::CreateCommitOnBranch { .. }
                    )
                })
                .count()
        }
    }

    impl CoordinationGithubRunner for ScriptedCoordinationRunner {
        fn run(
            &self,
            _config: &CoordinationGithubAdapterConfig,
            _label: &str,
            operation: CoordinationGithubOperation,
        ) -> Result<String> {
            self.requests.lock().expect("requests").push_back(operation);
            self.responses
                .lock()
                .expect("responses")
                .pop_front()
                .context("scripted coordination GitHub response missing")
        }
    }

    impl CoordinationGithubRunner for Arc<ScriptedCoordinationRunner> {
        fn run(
            &self,
            config: &CoordinationGithubAdapterConfig,
            label: &str,
            operation: CoordinationGithubOperation,
        ) -> Result<String> {
            self.as_ref().run(config, label, operation)
        }
    }

    fn actor(name: &str) -> ForgeActor {
        ForgeActor::new(
            "github",
            github_node_object_id(ProviderObjectKind::Actor, &format!("A_{name}"))
                .expect("actor id"),
            name,
            ReportedActorKind::Human,
        )
        .expect("actor")
    }

    fn item() -> ForgeItem {
        let repository = super::super::forge_transport::ForgeRepository::new(
            "github",
            "github.com/meta-develop/maco",
            github_node_object_id(ProviderObjectKind::Repository, "R_repo").expect("repo id"),
        )
        .expect("repository");
        ForgeItem::new(
            repository,
            ForgeItemKind::Issue,
            89,
            github_node_object_id(ProviderObjectKind::Item, "I_issue").expect("item id"),
            "revision:1",
            None,
            None,
        )
        .expect("item")
    }

    fn sample_adapter_open(worktree: PathBuf) -> CoordinationGithubAdapterOpenInput {
        CoordinationGithubAdapterOpenInput {
            worktree,
            repository_selector: "github.com/meta-develop/maco".to_string(),
            anchor_item: item(),
            journal_ref: "refs/heads/maco/coordination/journal".to_string(),
            anchor_commit_oid: ANCHOR_OID.to_string(),
            pointer_path: None,
            trusted_actors: vec![actor("trusted-a")],
            timing: ClaimTiming::new(10, 30).expect("timing"),
        }
    }

    fn identity_responses() -> [String; 3] {
        [
            serde_json::json!({"node_id":"R_repo","full_name":"meta-develop/maco"}).to_string(),
            serde_json::json!({
                "node_id":"I_issue","number":89,
                "url":ISSUE_API_URL,"html_url":ISSUE_HTML_URL,
                "updated_at":"2026-08-16T00:00:00Z","pull_request":null
            })
            .to_string(),
            serde_json::json!({"node_id":"A_trusted-a","login":"trusted-a","type":"User"})
                .to_string(),
        ]
    }

    fn protected_branch_json(enforce_admins: bool) -> String {
        serde_json::json!({
            "enforce_admins": { "enabled": enforce_admins },
            "allow_force_pushes": { "enabled": false },
            "allow_deletions": { "enabled": false }
        })
        .to_string()
    }

    fn adapter_responses(extra: impl IntoIterator<Item = String>) -> Vec<String> {
        identity_responses()
            .into_iter()
            .chain(std::iter::once(protected_branch_json(true)))
            .chain(extra)
            .collect()
    }

    fn comment_json(body: &str) -> serde_json::Value {
        comment_json_with_node(body, "IC_comment", 101)
    }

    fn comment_json_with_node(body: &str, node_id: &str, database_id: u64) -> serde_json::Value {
        serde_json::json!({
            "id": database_id,
            "node_id": node_id,
            "html_url": format!("https://github.com/meta-develop/maco/issues/89#issuecomment-{database_id}"),
            "issue_url": ISSUE_API_URL,
            "body": body,
            "created_at": "2026-08-16T00:00:00Z",
            "updated_at": "2026-08-16T00:00:00Z",
            "user": { "node_id": "A_trusted-a", "login": "trusted-a", "type": "User" }
        })
    }

    #[test]
    fn create_commit_on_branch_graphql_uses_commit_message_object() {
        let repository = github_repository_identity_from_selector("github.com/meta-develop/maco")
            .expect("repository");
        let (_, stdin) = CoordinationGithubOperation::CreateCommitOnBranch {
            branch_name: "maco/coordination/journal".to_string(),
            expected_head_oid: ANCHOR_OID.to_string(),
            pointer_path: "maco-coordination.json".to_string(),
            pointer_contents: "{}".to_string(),
            event_nonce: "event-1".to_string(),
            payload_digest: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                .to_string(),
        }
        .command(&repository)
        .expect("command");
        let bytes = match stdin {
            StdinMode::Bytes(bytes) => bytes,
            _ => panic!("graphql mutation must use stdin JSON"),
        };
        let payload: serde_json::Value = serde_json::from_slice(&bytes).expect("graphql json");
        let message = &payload["variables"]["input"]["message"];
        assert!(message.is_object());
        assert_eq!(message["headline"], CAS_COMMIT_HEADLINE);
        assert_eq!(
            payload["variables"]["input"]["branch"]["repositoryNameWithOwner"],
            "meta-develop/maco"
        );
    }

    #[test]
    fn branch_path_segments_are_url_encoded_in_protection_request() {
        let repository = github_repository_identity_from_selector("github.com/meta-develop/maco")
            .expect("repository");
        let (args, _) = CoordinationGithubOperation::JournalBranchProtection {
            branch_name: "maco/coord#1".to_string(),
        }
        .command(&repository)
        .expect("command");
        let endpoint = args.last().expect("endpoint").to_str().expect("utf8");
        assert!(endpoint.contains("maco%2Fcoord%231"));
    }

    #[test]
    fn admin_bypass_protection_refuses_adapter_construction() {
        let mut responses = identity_responses().into_iter().collect::<Vec<_>>();
        responses.push(protected_branch_json(false));
        let runner = ScriptedCoordinationRunner::new(responses);
        let error = CoordinationGithubAdapterConfig::try_new(
            sample_adapter_open(std::env::temp_dir()),
            &runner,
        )
        .expect_err("admin bypass");
        assert!(error.to_string().contains("enforce admins"));
    }

    #[test]
    fn edited_comment_refuses_membership_validation() {
        let runner = ScriptedCoordinationRunner::new(
            identity_responses()
                .into_iter()
                .chain(std::iter::once(protected_branch_json(true)))
                .collect::<Vec<_>>(),
        );
        let config = CoordinationGithubAdapterConfig::try_new(
            sample_adapter_open(std::env::temp_dir()),
            &runner,
        )
        .expect("adapter");
        let transport = CoordinationGithubTransport::new(config, runner);
        let comment = GithubCommentWire {
            id: 101,
            node_id: "IC_comment".to_string(),
            html_url: "https://github.com/meta-develop/maco/issues/89#issuecomment-101".to_string(),
            issue_url: ISSUE_API_URL.to_string(),
            body: "body".to_string(),
            created_at: "2026-08-16T00:00:00Z".to_string(),
            updated_at: "2026-08-16T00:00:01Z".to_string(),
            user: GithubApiActor {
                node_id: "A_trusted-a".to_string(),
                login: "trusted-a".to_string(),
                kind: "User".to_string(),
            },
        };
        assert!(transport.validate_comment_membership(&comment).is_err());
    }

    #[test]
    fn extra_tree_edit_refuses_history_assembly() {
        let owner = CoordinationOwnerIdentity::new("run-a", "nonce-a").expect("owner");
        let intent = CoordinationIntent::claim(
            &item(),
            "event-1",
            ANCHOR_OID,
            owner,
            vec!["scope/a".to_string()],
            ClaimTiming::new(10, 30).expect("timing"),
        )
        .expect("intent");
        let body = intent.render().expect("body");
        let pointer = JournalPointer::new(
            "event-1",
            github_node_object_id(ProviderObjectKind::Comment, "IC_comment").expect("comment id"),
            sha256_hex(body.as_bytes()),
            ANCHOR_OID,
        )
        .expect("pointer");
        let pointer_file = pointer.render_pointer_file().expect("pointer file");
        let (pointer_blob_oid, _pointer_blob_json) = blob_wire(&pointer_file);
        let readme_entry = serde_json::json!({
            "path":"README.md","type":"blob","mode":"100644",
            "sha":"1111111111111111111111111111111111111111"
        });
        let runner = ScriptedCoordinationRunner::new(adapter_responses([
            serde_json::json!({"object":{"sha":CHILD_OID}}).to_string(),
            serde_json::json!({"sha":CHILD_OID,"commit":{"tree":{"sha":CHILD_TREE}},"parents":[{"sha":ANCHOR_OID}]}).to_string(),
            serde_json::json!([]).to_string(),
            serde_json::json!({"sha":ANCHOR_OID,"commit":{"tree":{"sha":ANCHOR_TREE}},"parents":[]}).to_string(),
            serde_json::json!({"sha":CHILD_TREE,"truncated":false,"tree":[
                {"path":"maco-coordination.json","type":"blob","mode":"100644","sha":pointer_blob_oid},
                readme_entry.clone(),
                {"path":"notes.txt","type":"blob","mode":"100644","sha":"2222222222222222222222222222222222222222"}
            ]}).to_string(),
            serde_json::json!({"sha":ANCHOR_TREE,"truncated":false,"tree":[readme_entry]}).to_string(),
        ]));
        let mut open = sample_adapter_open(std::env::temp_dir());
        open.pointer_path = Some("maco-coordination.json".to_string());
        let config = CoordinationGithubAdapterConfig::try_new(open, &runner).expect("adapter");
        let transport = CoordinationGithubTransport::new(config, runner);
        let error = transport.load_trusted_history().expect_err("tree edit");
        assert!(
            format!("{error:#}").contains("unexpected tree path"),
            "load error chain: {error:#}"
        );
    }

    fn coordination_git_repo() -> (tempfile::TempDir, PathBuf) {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let path = temp.path().join("repo");
        git2::Repository::init(&path).expect("repository");
        (temp, path)
    }

    fn sample_intent() -> CoordinationIntent {
        let owner = CoordinationOwnerIdentity::new("run-a", "nonce-a").expect("owner");
        CoordinationIntent::claim(
            &item(),
            "event-apply-1",
            ANCHOR_OID,
            owner,
            vec!["scope/a".to_string()],
            ClaimTiming::new(10, 30).expect("timing"),
        )
        .expect("intent")
    }

    fn mutation_plan(
        intent: &CoordinationIntent,
        author: &ForgeActor,
    ) -> (String, String, String, CoordinationJournalMutationRecord) {
        let body = intent.render().expect("intent body");
        let payload_digest = sha256_hex(body.as_bytes());
        let plan_digest = stable_json_digest(&(
            COORDINATION_MUTATION_PLAN,
            intent.event_nonce(),
            intent.expected_parent_oid(),
            &payload_digest,
            author.provider_actor_id(),
        ))
        .expect("plan digest");
        let comment_effect_id = format!("{COMMENT_EFFECT_PREFIX}{plan_digest}");
        let cas_effect_id = format!("{CAS_EFFECT_PREFIX}{plan_digest}");
        let logical_id = format!("coord-journal-{plan_digest}");
        let planned = CoordinationJournalMutationRecord {
            version: COORDINATION_MUTATION_VERSION,
            plan_digest,
            event_nonce: intent.event_nonce().to_string(),
            expected_parent_oid: intent.expected_parent_oid().to_string(),
            payload_digest,
            intent_body: body,
            comment: None,
            cas: None,
        };
        (logical_id, comment_effect_id, cas_effect_id, planned)
    }

    fn blob_wire(content: &str) -> (String, String) {
        let bytes = content.as_bytes();
        let oid = git2::Oid::hash_object(git2::ObjectType::Blob, bytes)
            .expect("blob oid")
            .to_string();
        let json = serde_json::json!({
            "sha": oid,
            "size": bytes.len(),
            "encoding": "base64",
            "content": encode_base64(bytes),
        })
        .to_string();
        (oid, json)
    }

    const JOURNAL_BRANCH_REF: &str = "refs/heads/maco/coordination/journal";

    fn json_ref_head(oid: &str) -> String {
        serde_json::json!({ "object": { "sha": oid } }).to_string()
    }

    fn json_ref_head_include_body(oid: &str) -> String {
        serde_json::json!({
            "ref": JOURNAL_BRANCH_REF,
            "object": { "sha": oid, "type": "commit" }
        })
        .to_string()
    }

    fn ref_head_include_response(oid: &str, date: &str) -> String {
        format!(
            "HTTP/2.0 200 OK\r\nDate: {}\r\n\r\n{}",
            date,
            json_ref_head_include_body(oid)
        )
    }

    fn child_claim_journal_fixture() -> (String, String, String) {
        let owner = CoordinationOwnerIdentity::new("run-old", "nonce-old").expect("owner");
        let claim = CoordinationIntent::claim(
            &item(),
            "evt-claim-old",
            ANCHOR_OID,
            owner,
            vec!["scope/a".to_string()],
            ClaimTiming::new(10, 30).expect("timing"),
        )
        .expect("claim");
        let claim_body = claim.render().expect("claim body");
        let pointer = JournalPointer::new(
            claim.event_nonce(),
            github_node_object_id(ProviderObjectKind::Comment, "IC_comment").expect("comment id"),
            sha256_hex(claim_body.as_bytes()),
            ANCHOR_OID,
        )
        .expect("pointer");
        let pointer_file = pointer.render_pointer_file().expect("pointer file");
        let (pointer_blob_oid, pointer_blob_json) = blob_wire(&pointer_file);
        (claim_body, pointer_blob_oid, pointer_blob_json)
    }

    fn takeover_intent_for_predecessor(
        predecessor: CoordinationOwnerIdentity,
    ) -> CoordinationIntent {
        CoordinationIntent::takeover(
            &item(),
            "evt-takeover",
            CHILD_OID,
            CoordinationOwnerIdentity::new("run-new", "nonce-new").expect("successor"),
            predecessor,
            vec!["scope/a".to_string()],
            ClaimTiming::new(10, 30).expect("timing"),
        )
        .expect("takeover")
    }

    fn comment_json_with_node_and_created_at(
        body: &str,
        node_id: &str,
        database_id: u64,
        created_at: &str,
    ) -> String {
        let mut value = comment_json_with_node(body, node_id, database_id);
        value["created_at"] = serde_json::json!(created_at);
        value["updated_at"] = serde_json::json!(created_at);
        value.to_string()
    }

    fn json_empty_comments_page() -> String {
        "[]".to_string()
    }

    fn json_issue_comments_page(body: &str) -> String {
        serde_json::to_string(&vec![comment_json(body)]).expect("issue comments page")
    }

    fn append_empty_anchor_history_read(out: &mut Vec<String>) {
        out.push(json_ref_head(ANCHOR_OID));
        out.push(json_empty_comments_page());
    }

    fn append_active_child_journal_history_read(
        out: &mut Vec<String>,
        body: &str,
        pointer_blob_oid: &str,
        pointer_blob_json: &str,
    ) {
        append_verified_child_journal_history_load(out, body, pointer_blob_oid, pointer_blob_json);
    }

    fn append_cas_receipt_verification_grandchild(
        out: &mut Vec<String>,
        child_pointer_blob_oid: &str,
        grandchild_pointer_blob_oid: &str,
        grandchild_pointer_blob_json: &str,
    ) {
        out.push(json_commit(
            GRANDCHILD_OID,
            GRANDCHILD_TREE,
            Some(CHILD_OID),
        ));
        out.push(json_commit(CHILD_OID, CHILD_TREE, Some(ANCHOR_OID)));
        out.push(json_pointer_child_tree(
            GRANDCHILD_TREE,
            grandchild_pointer_blob_oid,
        ));
        out.push(json_pointer_child_tree(CHILD_TREE, child_pointer_blob_oid));
        out.push(grandchild_pointer_blob_json.to_string());
        out.push(json_ref_head(GRANDCHILD_OID));
    }

    fn append_verified_grandchild_journal_history_load(
        out: &mut Vec<String>,
        body_a: &str,
        child_pointer_blob_oid: &str,
        child_pointer_blob_json: &str,
        comment_b: serde_json::Value,
        grandchild_pointer_blob_oid: &str,
        grandchild_pointer_blob_json: &str,
    ) {
        out.push(json_ref_head(GRANDCHILD_OID));
        out.push(json_commit(
            GRANDCHILD_OID,
            GRANDCHILD_TREE,
            Some(CHILD_OID),
        ));
        out.push(json_commit(CHILD_OID, CHILD_TREE, Some(ANCHOR_OID)));
        out.push(
            serde_json::to_string(&vec![comment_json(body_a), comment_b])
                .expect("issue comments page"),
        );
        out.push(json_commit(ANCHOR_OID, ANCHOR_TREE, None));
        out.push(json_pointer_child_tree(CHILD_TREE, child_pointer_blob_oid));
        out.push(json_empty_tree(ANCHOR_TREE));
        out.push(child_pointer_blob_json.to_string());
        out.push(json_commit(CHILD_OID, CHILD_TREE, Some(ANCHOR_OID)));
        out.push(json_pointer_child_tree(
            GRANDCHILD_TREE,
            grandchild_pointer_blob_oid,
        ));
        out.push(json_pointer_child_tree(CHILD_TREE, child_pointer_blob_oid));
        out.push(grandchild_pointer_blob_json.to_string());
    }

    fn json_commit(sha: &str, tree: &str, parent: Option<&str>) -> String {
        let parents = parent
            .map(|parent_sha| vec![serde_json::json!({ "sha": parent_sha })])
            .unwrap_or_default();
        serde_json::json!({
            "sha": sha,
            "commit": { "tree": { "sha": tree } },
            "parents": parents,
        })
        .to_string()
    }

    fn json_pointer_child_tree(tree_sha: &str, blob_oid: &str) -> String {
        serde_json::json!({
            "sha": tree_sha,
            "truncated": false,
            "tree": [{
                "path": "maco-coordination.json",
                "type": "blob",
                "mode": "100644",
                "sha": blob_oid,
            }],
        })
        .to_string()
    }

    fn json_empty_tree(tree_sha: &str) -> String {
        serde_json::json!({
            "sha": tree_sha,
            "truncated": false,
            "tree": [],
        })
        .to_string()
    }

    fn append_verified_child_journal_history_load(
        out: &mut Vec<String>,
        body: &str,
        pointer_blob_oid: &str,
        pointer_blob_json: &str,
    ) {
        out.push(json_ref_head(CHILD_OID));
        out.push(json_commit(CHILD_OID, CHILD_TREE, Some(ANCHOR_OID)));
        out.push(json_issue_comments_page(body));
        out.push(json_commit(ANCHOR_OID, ANCHOR_TREE, None));
        out.push(json_pointer_child_tree(CHILD_TREE, pointer_blob_oid));
        out.push(json_empty_tree(ANCHOR_TREE));
        out.push(pointer_blob_json.to_string());
    }

    fn append_cas_receipt_verification(
        out: &mut Vec<String>,
        pointer_blob_oid: &str,
        pointer_blob_json: &str,
    ) {
        out.push(json_commit(CHILD_OID, CHILD_TREE, Some(ANCHOR_OID)));
        out.push(json_commit(ANCHOR_OID, ANCHOR_TREE, None));
        out.push(json_pointer_child_tree(CHILD_TREE, pointer_blob_oid));
        out.push(json_empty_tree(ANCHOR_TREE));
        out.push(pointer_blob_json.to_string());
        out.push(json_ref_head(CHILD_OID));
    }

    fn append_committed_write_free_apply_responses(
        out: &mut Vec<String>,
        body: &str,
        pointer_blob_oid: &str,
        pointer_blob_json: &str,
    ) {
        append_verified_child_journal_history_load(out, body, pointer_blob_oid, pointer_blob_json);
        out.push(json_issue_comments_page(body));
        out.push(comment_json(body).to_string());
        append_cas_receipt_verification(out, pointer_blob_oid, pointer_blob_json);
        append_cas_receipt_verification(out, pointer_blob_oid, pointer_blob_json);
    }

    fn adapter_config(
        repo: &Path,
        runner: &ScriptedCoordinationRunner,
    ) -> CoordinationGithubAdapterConfig {
        let mut open = sample_adapter_open(repo.to_path_buf());
        open.pointer_path = Some("maco-coordination.json".to_string());
        CoordinationGithubAdapterConfig::try_new(open, runner).expect("adapter config")
    }

    #[test]
    fn comment_api_url_mismatch_refuses_membership() {
        let runner = ScriptedCoordinationRunner::new(
            identity_responses()
                .into_iter()
                .chain(std::iter::once(protected_branch_json(true)))
                .collect::<Vec<_>>(),
        );
        let config = adapter_config(std::env::temp_dir().as_path(), &runner);
        let transport = CoordinationGithubTransport::new(config, runner);
        let mut comment = comment_json("body");
        comment["issue_url"] = serde_json::json!(ISSUE_HTML_URL);
        let comment: GithubCommentWire = serde_json::from_value(comment).expect("comment");
        assert!(transport.validate_comment_membership(&comment).is_err());
    }

    #[test]
    fn duplicate_tree_path_refuses_strict_delta() {
        let parent = GithubTreeWire {
            sha: ANCHOR_TREE.to_string(),
            truncated: false,
            tree: vec![GithubTreeEntryWire {
                path: "maco-coordination.json".to_string(),
                type_field: "blob".to_string(),
                mode: "100644".to_string(),
                sha: POINTER_BLOB.to_string(),
            }],
        };
        let child = GithubTreeWire {
            sha: CHILD_TREE.to_string(),
            truncated: false,
            tree: vec![
                GithubTreeEntryWire {
                    path: "maco-coordination.json".to_string(),
                    type_field: "blob".to_string(),
                    mode: "100644".to_string(),
                    sha: POINTER_BLOB.to_string(),
                },
                GithubTreeEntryWire {
                    path: "maco-coordination.json".to_string(),
                    type_field: "blob".to_string(),
                    mode: "100644".to_string(),
                    sha: POINTER_BLOB.to_string(),
                },
            ],
        };
        let error =
            verify_strict_tree_delta(&parent, &child, "maco-coordination.json").expect_err("dup");
        assert!(error.to_string().contains("reused a path"));
    }

    #[test]
    fn wal_comment_started_before_post_and_restart_never_reposts() {
        let (_temp, repo) = coordination_git_repo();
        let bind_runner =
            ScriptedCoordinationRunner::new(adapter_responses([]).into_iter().collect::<Vec<_>>());
        let config = adapter_config(&repo, &bind_runner);
        let intent = sample_intent();
        let author = actor("trusted-a");
        let (logical_id, comment_effect_id, cas_effect_id, planned) =
            mutation_plan(&intent, &author);
        let mut wal: DefaultEffectWal = EffectWal::open_or_create_planned(
            || {
                repository_auth_writer(&repo)?
                    .into_authenticator()
                    .context("coordination WAL authenticator")
            },
            &logical_id,
            &comment_effect_id,
            &planned,
        )
        .expect("seed WAL");
        wal.planned(&cas_effect_id, &planned).expect("cas planned");
        wal.started(&comment_effect_id, &planned)
            .expect("comment started");
        drop(wal);

        let mut apply_responses = Vec::new();
        append_empty_anchor_history_read(&mut apply_responses);
        append_empty_anchor_history_read(&mut apply_responses);
        apply_responses.push(json_empty_comments_page());
        let runner = Arc::new(ScriptedCoordinationRunner::new(apply_responses));
        let transport = CoordinationGithubTransport::new(config, Arc::clone(&runner));
        let outcome = transport
            .apply_authorized_intent(intent, author, None)
            .expect("apply after comment start");
        match outcome {
            CoordinationMutationOutcome::Unknown { evidence } => {
                assert!(evidence.contains("unknown coordination"));
            }
            other => panic!("expected unknown comment restart outcome, got {other:?}"),
        }
        assert_eq!(runner.post_issue_comment_calls(), 0);
        let wal: DefaultEffectWal = EffectWal::open_instance(
            repository_auth_writer(&repo)
                .expect("auth")
                .into_authenticator()
                .expect("authenticator"),
            &logical_id,
        )
        .expect("reopen WAL");
        assert_eq!(wal.phase(&comment_effect_id), Some(EffectPhase::Started));
    }

    #[test]
    fn wal_cas_started_restart_never_repeats_graphql_cas() {
        let (_temp, repo) = coordination_git_repo();
        let bind_runner =
            ScriptedCoordinationRunner::new(adapter_responses([]).into_iter().collect::<Vec<_>>());
        let config = adapter_config(&repo, &bind_runner);
        let intent = sample_intent();
        let author = actor("trusted-a");
        let body = intent.render().expect("body");
        let (logical_id, comment_effect_id, cas_effect_id, planned) =
            mutation_plan(&intent, &author);
        let comment_receipt = CoordinationCommentReceipt {
            provider_comment_id: 101,
            url: "https://github.com/meta-develop/maco/issues/89#issuecomment-101".to_string(),
            author_login: "trusted-a".to_string(),
        };
        let mut wal: DefaultEffectWal = EffectWal::open_or_create_planned(
            || {
                repository_auth_writer(&repo)?
                    .into_authenticator()
                    .context("coordination WAL authenticator")
            },
            &logical_id,
            &comment_effect_id,
            &planned,
        )
        .expect("seed WAL");
        wal.planned(&cas_effect_id, &planned).expect("cas planned");
        wal.started(&comment_effect_id, &planned)
            .expect("comment started");
        wal.observed(
            &comment_effect_id,
            &CoordinationJournalMutationRecord {
                comment: Some(comment_receipt),
                ..planned.clone()
            },
        )
        .expect("comment observed");
        wal.started(&cas_effect_id, &planned).expect("cas started");
        drop(wal);

        let mut apply_responses = Vec::new();
        append_empty_anchor_history_read(&mut apply_responses);
        append_empty_anchor_history_read(&mut apply_responses);
        apply_responses.push(comment_json(&body).to_string());
        append_empty_anchor_history_read(&mut apply_responses);
        apply_responses.push(json_ref_head(ANCHOR_OID));
        let runner = Arc::new(ScriptedCoordinationRunner::new(apply_responses));
        let transport = CoordinationGithubTransport::new(config, Arc::clone(&runner));
        let outcome = transport
            .apply_authorized_intent(intent, author, None)
            .expect("apply after cas start");
        match outcome {
            CoordinationMutationOutcome::Unknown { evidence } => {
                assert!(evidence.contains("unknown coordination"));
            }
            other => panic!("expected unknown CAS restart outcome, got {other:?}"),
        }
        assert_eq!(runner.create_commit_on_branch_calls(), 0);
        let wal: DefaultEffectWal = EffectWal::open_instance(
            repository_auth_writer(&repo)
                .expect("auth")
                .into_authenticator()
                .expect("authenticator"),
            &logical_id,
        )
        .expect("reopen WAL");
        assert_eq!(wal.phase(&comment_effect_id), Some(EffectPhase::Observed));
        assert_eq!(wal.phase(&cas_effect_id), Some(EffectPhase::Started));
        let _ = body;
    }

    #[test]
    fn wal_successful_apply_exercises_production_phases_and_effect_wal() {
        let (_temp, repo) = coordination_git_repo();
        let bind_runner =
            ScriptedCoordinationRunner::new(adapter_responses([]).into_iter().collect::<Vec<_>>());
        let config = adapter_config(&repo, &bind_runner);
        let intent = sample_intent();
        let author = actor("trusted-a");
        let body = intent.render().expect("body");
        let pointer = JournalPointer::new(
            intent.event_nonce(),
            github_node_object_id(ProviderObjectKind::Comment, "IC_comment").expect("comment id"),
            sha256_hex(body.as_bytes()),
            ANCHOR_OID,
        )
        .expect("pointer");
        let pointer_file = pointer.render_pointer_file().expect("pointer file");
        let (pointer_blob_oid, pointer_blob_json) = blob_wire(&pointer_file);
        let cas_graphql = serde_json::json!({
            "data": { "createCommitOnBranch": { "commit": { "oid": CHILD_OID } } }
        })
        .to_string();
        let mut apply_responses = Vec::new();
        append_empty_anchor_history_read(&mut apply_responses);
        append_empty_anchor_history_read(&mut apply_responses);
        apply_responses.push(json_empty_comments_page());
        apply_responses.push(comment_json(&body).to_string());
        apply_responses.push(comment_json(&body).to_string());
        apply_responses.push(comment_json(&body).to_string());
        append_empty_anchor_history_read(&mut apply_responses);
        apply_responses.push(json_ref_head(ANCHOR_OID));
        apply_responses.push(cas_graphql);
        append_cas_receipt_verification(
            &mut apply_responses,
            &pointer_blob_oid,
            &pointer_blob_json,
        );
        append_verified_child_journal_history_load(
            &mut apply_responses,
            &body,
            &pointer_blob_oid,
            &pointer_blob_json,
        );
        let runner = Arc::new(ScriptedCoordinationRunner::new(apply_responses));
        let transport = CoordinationGithubTransport::new(config, Arc::clone(&runner));
        let (logical_id, comment_effect_id, cas_effect_id, _) = mutation_plan(&intent, &author);
        let outcome = transport
            .apply_authorized_intent(intent, author, None)
            .expect("successful apply");
        match outcome {
            CoordinationMutationOutcome::Applied { .. } => {}
            other => panic!("expected applied outcome, got {other:?}"),
        }
        assert_eq!(runner.post_issue_comment_calls(), 1);
        assert_eq!(runner.create_commit_on_branch_calls(), 1);
        let wal: DefaultEffectWal = EffectWal::open_instance(
            repository_auth_writer(&repo)
                .expect("auth")
                .into_authenticator()
                .expect("authenticator"),
            &logical_id,
        )
        .expect("reopen WAL");
        assert_eq!(wal.phase(&comment_effect_id), Some(EffectPhase::Completed));
        assert_eq!(wal.phase(&cas_effect_id), Some(EffectPhase::Completed));
        let comment_events = wal
            .events()
            .iter()
            .filter(|event| event.effect_id == comment_effect_id)
            .map(|event| event.phase)
            .collect::<Vec<_>>();
        assert_eq!(
            comment_events,
            vec![
                EffectPhase::Planned,
                EffectPhase::Started,
                EffectPhase::Observed,
                EffectPhase::Completed
            ]
        );
    }

    #[test]
    fn wal_cas_restart_reconciles_observed_ancestor_without_graphql() {
        let (_temp, repo) = coordination_git_repo();
        let bind_runner =
            ScriptedCoordinationRunner::new(adapter_responses([]).into_iter().collect::<Vec<_>>());
        let config = adapter_config(&repo, &bind_runner);
        let intent = sample_intent();
        let author = actor("trusted-a");
        let body = intent.render().expect("body");
        let pointer = JournalPointer::new(
            intent.event_nonce(),
            github_node_object_id(ProviderObjectKind::Comment, "IC_comment").expect("comment id"),
            sha256_hex(body.as_bytes()),
            ANCHOR_OID,
        )
        .expect("pointer");
        let pointer_file = pointer.render_pointer_file().expect("pointer file");
        let (pointer_blob_oid, pointer_blob_json) = blob_wire(&pointer_file);
        let comment_receipt = CoordinationCommentReceipt {
            provider_comment_id: 101,
            url: "https://github.com/meta-develop/maco/issues/89#issuecomment-101".to_string(),
            author_login: "trusted-a".to_string(),
        };
        let (logical_id, comment_effect_id, cas_effect_id, planned) =
            mutation_plan(&intent, &author);
        let mut wal: DefaultEffectWal = EffectWal::open_or_create_planned(
            || {
                repository_auth_writer(&repo)?
                    .into_authenticator()
                    .context("coordination WAL authenticator")
            },
            &logical_id,
            &comment_effect_id,
            &planned,
        )
        .expect("seed WAL");
        wal.planned(&cas_effect_id, &planned).expect("cas planned");
        wal.started(&comment_effect_id, &planned)
            .expect("comment started");
        wal.observed(
            &comment_effect_id,
            &CoordinationJournalMutationRecord {
                comment: Some(comment_receipt),
                ..planned.clone()
            },
        )
        .expect("comment observed");
        wal.started(&cas_effect_id, &planned).expect("cas started");
        drop(wal);

        let mut apply_responses = Vec::new();
        append_committed_write_free_apply_responses(
            &mut apply_responses,
            &body,
            &pointer_blob_oid,
            &pointer_blob_json,
        );
        let runner = Arc::new(ScriptedCoordinationRunner::new(apply_responses));
        let transport = CoordinationGithubTransport::new(config, Arc::clone(&runner));
        let outcome = transport
            .apply_authorized_intent(intent, author, None)
            .expect("reconcile CAS after start");
        match outcome {
            CoordinationMutationOutcome::Applied { .. } => {}
            other => panic!("expected applied CAS reconciliation, got {other:?}"),
        }
        assert_eq!(runner.post_issue_comment_calls(), 0);
        assert_eq!(runner.create_commit_on_branch_calls(), 0);
        let wal: DefaultEffectWal = EffectWal::open_instance(
            repository_auth_writer(&repo)
                .expect("auth")
                .into_authenticator()
                .expect("authenticator"),
            &logical_id,
        )
        .expect("reopen WAL");
        assert_eq!(wal.phase(&comment_effect_id), Some(EffectPhase::Completed));
        assert_eq!(wal.phase(&cas_effect_id), Some(EffectPhase::Completed));
    }

    #[test]
    fn committed_apply_with_fresh_planned_wal_completes_without_provider_writes() {
        let (_temp, repo) = coordination_git_repo();
        let bind_runner =
            ScriptedCoordinationRunner::new(adapter_responses([]).into_iter().collect::<Vec<_>>());
        let config = adapter_config(&repo, &bind_runner);
        let intent = sample_intent();
        let author = actor("trusted-a");
        let body = intent.render().expect("body");
        let pointer_file = JournalPointer::new(
            intent.event_nonce(),
            github_node_object_id(ProviderObjectKind::Comment, "IC_comment").expect("comment id"),
            sha256_hex(body.as_bytes()),
            ANCHOR_OID,
        )
        .expect("pointer")
        .render_pointer_file()
        .expect("pointer file");
        let (pointer_blob_oid, pointer_blob_json) = blob_wire(&pointer_file);
        let (logical_id, comment_effect_id, cas_effect_id, _) = mutation_plan(&intent, &author);
        let mut apply_responses = Vec::new();
        append_committed_write_free_apply_responses(
            &mut apply_responses,
            &body,
            &pointer_blob_oid,
            &pointer_blob_json,
        );
        let runner = Arc::new(ScriptedCoordinationRunner::new(apply_responses));
        let transport = CoordinationGithubTransport::new(config, Arc::clone(&runner));
        let outcome = transport
            .apply_authorized_intent(intent, author, None)
            .expect("committed planned WAL apply");
        assert!(matches!(
            outcome,
            CoordinationMutationOutcome::Applied { .. }
        ));
        assert_eq!(runner.post_issue_comment_calls(), 0);
        assert_eq!(runner.create_commit_on_branch_calls(), 0);
        let wal: DefaultEffectWal = EffectWal::open_instance(
            repository_auth_writer(&repo)
                .expect("auth")
                .into_authenticator()
                .expect("authenticator"),
            &logical_id,
        )
        .expect("reopen WAL");
        assert_eq!(wal.phase(&comment_effect_id), Some(EffectPhase::Completed));
        assert_eq!(wal.phase(&cas_effect_id), Some(EffectPhase::Completed));
    }

    #[test]
    fn committed_apply_with_terminal_wal_stays_terminal_without_provider_writes() {
        let (_temp, repo) = coordination_git_repo();
        let bind_runner =
            ScriptedCoordinationRunner::new(adapter_responses([]).into_iter().collect::<Vec<_>>());
        let config = adapter_config(&repo, &bind_runner);
        let intent = sample_intent();
        let author = actor("trusted-a");
        let body = intent.render().expect("body");
        let pointer_file = JournalPointer::new(
            intent.event_nonce(),
            github_node_object_id(ProviderObjectKind::Comment, "IC_comment").expect("comment id"),
            sha256_hex(body.as_bytes()),
            ANCHOR_OID,
        )
        .expect("pointer")
        .render_pointer_file()
        .expect("pointer file");
        let (pointer_blob_oid, pointer_blob_json) = blob_wire(&pointer_file);
        let (logical_id, comment_effect_id, cas_effect_id, planned) =
            mutation_plan(&intent, &author);
        let comment_receipt = CoordinationCommentReceipt {
            provider_comment_id: 101,
            url: "https://github.com/meta-develop/maco/issues/89#issuecomment-101".to_string(),
            author_login: "trusted-a".to_string(),
        };
        let cas_receipt = CoordinationCasReceipt {
            commit_oid: CHILD_OID.to_string(),
            parent_oid: ANCHOR_OID.to_string(),
        };
        let merged = CoordinationJournalMutationRecord {
            comment: Some(comment_receipt),
            cas: Some(cas_receipt),
            ..planned.clone()
        };
        let mut wal: DefaultEffectWal = EffectWal::open_or_create_planned(
            || {
                repository_auth_writer(&repo)?
                    .into_authenticator()
                    .context("coordination WAL authenticator")
            },
            &logical_id,
            &comment_effect_id,
            &planned,
        )
        .expect("seed WAL");
        wal.planned(&cas_effect_id, &planned).expect("cas planned");
        wal.started(&comment_effect_id, &planned)
            .expect("comment started");
        wal.observed(&comment_effect_id, &merged)
            .expect("comment observed");
        wal.completed(&comment_effect_id, &merged)
            .expect("comment completed");
        wal.started(&cas_effect_id, &planned).expect("cas started");
        wal.observed(&cas_effect_id, &merged).expect("cas observed");
        wal.completed(&cas_effect_id, &merged)
            .expect("cas completed");
        drop(wal);
        let event_count_before = EffectWal::<DefaultEffectWalSpec>::open_instance(
            repository_auth_writer(&repo)
                .expect("auth")
                .into_authenticator()
                .expect("authenticator"),
            &logical_id,
        )
        .expect("count WAL")
        .events()
        .len();
        let mut apply_responses = Vec::new();
        append_committed_write_free_apply_responses(
            &mut apply_responses,
            &body,
            &pointer_blob_oid,
            &pointer_blob_json,
        );
        let runner = Arc::new(ScriptedCoordinationRunner::new(apply_responses));
        let transport = CoordinationGithubTransport::new(config, Arc::clone(&runner));
        let outcome = transport
            .apply_authorized_intent(intent, author, None)
            .expect("committed terminal WAL apply");
        assert!(matches!(
            outcome,
            CoordinationMutationOutcome::Applied { .. }
        ));
        assert_eq!(runner.post_issue_comment_calls(), 0);
        assert_eq!(runner.create_commit_on_branch_calls(), 0);
        let wal: DefaultEffectWal = EffectWal::open_instance(
            repository_auth_writer(&repo)
                .expect("auth")
                .into_authenticator()
                .expect("authenticator"),
            &logical_id,
        )
        .expect("reopen WAL");
        assert_eq!(wal.phase(&comment_effect_id), Some(EffectPhase::Completed));
        assert_eq!(wal.phase(&cas_effect_id), Some(EffectPhase::Completed));
        assert_eq!(wal.events().len(), event_count_before);
    }

    #[test]
    fn overlapping_claim_refused_before_github_transport_mutation() {
        assert_overlapping_claim_refusal(false);
    }

    #[test]
    fn overlapping_claim_with_started_wal_remains_unknown_without_more_mutation() {
        assert_overlapping_claim_refusal(true);
    }

    fn assert_overlapping_claim_refusal(comment_started: bool) {
        let (_temp, repo) = coordination_git_repo();
        let bind_runner =
            ScriptedCoordinationRunner::new(adapter_responses([]).into_iter().collect::<Vec<_>>());
        let config = adapter_config(&repo, &bind_runner);
        let author = actor("trusted-a");
        let owner_a = CoordinationOwnerIdentity::new("run-a", "nonce-a").expect("owner a");
        let intent_a = CoordinationIntent::claim(
            &item(),
            "event-host-a",
            ANCHOR_OID,
            owner_a,
            vec!["scope/shared".to_string()],
            ClaimTiming::new(10, 30).expect("timing"),
        )
        .expect("claim a");
        let body_a = intent_a.render().expect("body a");
        let pointer_a = JournalPointer::new(
            intent_a.event_nonce(),
            github_node_object_id(ProviderObjectKind::Comment, "IC_comment").expect("comment id"),
            sha256_hex(body_a.as_bytes()),
            ANCHOR_OID,
        )
        .expect("pointer a");
        let pointer_file_a = pointer_a.render_pointer_file().expect("pointer file a");
        let (pointer_blob_oid_a, pointer_blob_json_a) = blob_wire(&pointer_file_a);
        let owner_b = CoordinationOwnerIdentity::new("run-b", "nonce-b").expect("owner b");
        let intent_b = CoordinationIntent::claim(
            &item(),
            "event-host-b",
            CHILD_OID,
            owner_b,
            vec!["scope/shared".to_string()],
            ClaimTiming::new(10, 30).expect("timing"),
        )
        .expect("claim b");
        let (logical_id, comment_effect_id, cas_effect_id, planned) =
            mutation_plan(&intent_b, &author);
        if comment_started {
            let mut wal: DefaultEffectWal = EffectWal::open_or_create_planned(
                || {
                    repository_auth_writer(&repo)?
                        .into_authenticator()
                        .context("coordination WAL authenticator")
                },
                &logical_id,
                &comment_effect_id,
                &planned,
            )
            .expect("seed WAL");
            wal.planned(&cas_effect_id, &planned).expect("cas planned");
            wal.started(&comment_effect_id, &planned)
                .expect("comment started");
        }
        let mut apply_responses = Vec::new();
        for _ in 0..4 {
            append_active_child_journal_history_read(
                &mut apply_responses,
                &body_a,
                &pointer_blob_oid_a,
                &pointer_blob_json_a,
            );
        }
        let runner = Arc::new(ScriptedCoordinationRunner::new(apply_responses));
        let transport = CoordinationGithubTransport::new(config, Arc::clone(&runner));
        let outcome = transport
            .apply_authorized_intent(intent_b, author, None)
            .expect("overlapping claim apply");
        match outcome {
            CoordinationMutationOutcome::NotApplied { reason } if !comment_started => {
                assert!(reason.contains("scopes overlap"));
            }
            CoordinationMutationOutcome::Unknown { evidence } if comment_started => {
                assert!(evidence.contains("scopes overlap"));
                assert!(evidence.contains("prior effect may have started"));
            }
            other => panic!("expected pre-effect refusal, got {other:?}"),
        }
        assert_eq!(runner.post_issue_comment_calls(), 0);
        assert_eq!(runner.create_commit_on_branch_calls(), 0);
        transport
            .load_trusted_history()
            .expect("journal still loads");
        transport
            .reduce_loaded_history(&transport.load_trusted_history().expect("history"), None)
            .expect("journal still reduces");
        let wal: DefaultEffectWal = EffectWal::open_instance(
            repository_auth_writer(&repo)
                .expect("auth")
                .into_authenticator()
                .expect("authenticator"),
            &logical_id,
        )
        .expect("reopen WAL");
        let expected_comment_phase = if comment_started {
            EffectPhase::Started
        } else {
            EffectPhase::Planned
        };
        assert_eq!(wal.phase(&comment_effect_id), Some(expected_comment_phase));
        assert_eq!(wal.phase(&cas_effect_id), Some(EffectPhase::Planned));
    }

    #[test]
    fn disjoint_claim_applies_on_github_transport_after_active_claim() {
        let (_temp, repo) = coordination_git_repo();
        let bind_runner =
            ScriptedCoordinationRunner::new(adapter_responses([]).into_iter().collect::<Vec<_>>());
        let config = adapter_config(&repo, &bind_runner);
        let author = actor("trusted-a");
        let owner_a = CoordinationOwnerIdentity::new("run-a", "nonce-a").expect("owner a");
        let intent_a = CoordinationIntent::claim(
            &item(),
            "event-host-a",
            ANCHOR_OID,
            owner_a,
            vec!["scope/shared".to_string()],
            ClaimTiming::new(10, 30).expect("timing"),
        )
        .expect("claim a");
        let body_a = intent_a.render().expect("body a");
        let pointer_a = JournalPointer::new(
            intent_a.event_nonce(),
            github_node_object_id(ProviderObjectKind::Comment, "IC_comment").expect("comment id"),
            sha256_hex(body_a.as_bytes()),
            ANCHOR_OID,
        )
        .expect("pointer a");
        let pointer_file_a = pointer_a.render_pointer_file().expect("pointer file a");
        let (pointer_blob_oid_a, pointer_blob_json_a) = blob_wire(&pointer_file_a);
        let owner_b = CoordinationOwnerIdentity::new("run-b", "nonce-b").expect("owner b");
        let intent_b = CoordinationIntent::claim(
            &item(),
            "event-host-b-disjoint",
            CHILD_OID,
            owner_b,
            vec!["scope/disjoint".to_string()],
            ClaimTiming::new(10, 30).expect("timing"),
        )
        .expect("claim b");
        let body_b = intent_b.render().expect("body b");
        let pointer_b = JournalPointer::new(
            intent_b.event_nonce(),
            github_node_object_id(ProviderObjectKind::Comment, "IC_comment_b").expect("comment id"),
            sha256_hex(body_b.as_bytes()),
            CHILD_OID,
        )
        .expect("pointer b");
        let pointer_file_b = pointer_b.render_pointer_file().expect("pointer file b");
        let (pointer_blob_oid_b, pointer_blob_json_b) = blob_wire(&pointer_file_b);
        let cas_graphql = serde_json::json!({
            "data": { "createCommitOnBranch": { "commit": { "oid": GRANDCHILD_OID } } }
        })
        .to_string();
        let comment_b_wire = comment_json_with_node(&body_b, "IC_comment_b", 102).to_string();
        let mut apply_responses = Vec::new();
        append_active_child_journal_history_read(
            &mut apply_responses,
            &body_a,
            &pointer_blob_oid_a,
            &pointer_blob_json_a,
        );
        append_active_child_journal_history_read(
            &mut apply_responses,
            &body_a,
            &pointer_blob_oid_a,
            &pointer_blob_json_a,
        );
        apply_responses.push(json_empty_comments_page());
        apply_responses.push(comment_b_wire.clone());
        apply_responses.push(comment_b_wire.clone());
        apply_responses.push(comment_b_wire);
        append_active_child_journal_history_read(
            &mut apply_responses,
            &body_a,
            &pointer_blob_oid_a,
            &pointer_blob_json_a,
        );
        // CAS reconciliation must inspect A's committed pointer before posting B.
        apply_responses.push(json_ref_head(CHILD_OID));
        apply_responses.push(json_commit(CHILD_OID, CHILD_TREE, Some(ANCHOR_OID)));
        apply_responses.push(json_commit(ANCHOR_OID, ANCHOR_TREE, None));
        apply_responses.push(json_pointer_child_tree(CHILD_TREE, &pointer_blob_oid_a));
        apply_responses.push(json_empty_tree(ANCHOR_TREE));
        apply_responses.push(pointer_blob_json_a.clone());
        apply_responses.push(cas_graphql);
        append_cas_receipt_verification_grandchild(
            &mut apply_responses,
            &pointer_blob_oid_a,
            &pointer_blob_oid_b,
            &pointer_blob_json_b,
        );
        append_verified_grandchild_journal_history_load(
            &mut apply_responses,
            &body_a,
            &pointer_blob_oid_a,
            &pointer_blob_json_a,
            comment_json_with_node(&body_b, "IC_comment_b", 102),
            &pointer_blob_oid_b,
            &pointer_blob_json_b,
        );
        let runner = Arc::new(ScriptedCoordinationRunner::new(apply_responses));
        let transport = CoordinationGithubTransport::new(config, Arc::clone(&runner));
        let outcome = transport
            .apply_authorized_intent(intent_b, author, None)
            .expect("disjoint claim apply");
        assert!(matches!(
            outcome,
            CoordinationMutationOutcome::Applied { .. }
        ));
        assert_eq!(runner.post_issue_comment_calls(), 1);
        assert_eq!(runner.create_commit_on_branch_calls(), 1);
    }

    #[test]
    fn committed_nonce_with_contradicting_intent_body_is_not_applied() {
        let (_temp, repo) = coordination_git_repo();
        let bind_runner =
            ScriptedCoordinationRunner::new(adapter_responses([]).into_iter().collect::<Vec<_>>());
        let config = adapter_config(&repo, &bind_runner);
        let committed_intent = sample_intent();
        let author = actor("trusted-a");
        let committed_body = committed_intent.render().expect("committed body");
        let owner = CoordinationOwnerIdentity::new("run-b", "nonce-b").expect("owner");
        let conflicting_intent = CoordinationIntent::claim(
            &item(),
            committed_intent.event_nonce(),
            ANCHOR_OID,
            owner,
            vec!["scope/conflict".to_string()],
            ClaimTiming::new(10, 30).expect("timing"),
        )
        .expect("conflicting intent");
        let pointer = JournalPointer::new(
            committed_intent.event_nonce(),
            github_node_object_id(ProviderObjectKind::Comment, "IC_comment").expect("comment id"),
            sha256_hex(committed_body.as_bytes()),
            ANCHOR_OID,
        )
        .expect("pointer");
        let pointer_file = pointer.render_pointer_file().expect("pointer file");
        let (pointer_blob_oid, pointer_blob_json) = blob_wire(&pointer_file);
        let (logical_id, comment_effect_id, cas_effect_id, _planned) =
            mutation_plan(&conflicting_intent, &author);
        let mut apply_responses = Vec::new();
        append_verified_child_journal_history_load(
            &mut apply_responses,
            &committed_body,
            &pointer_blob_oid,
            &pointer_blob_json,
        );
        let runner = Arc::new(ScriptedCoordinationRunner::new(apply_responses));
        let transport = CoordinationGithubTransport::new(config, Arc::clone(&runner));
        let outcome = transport
            .apply_authorized_intent(conflicting_intent, author, None)
            .expect("conflicting committed apply");
        match outcome {
            CoordinationMutationOutcome::NotApplied { reason } => {
                assert!(reason.contains("body digest"));
            }
            other => panic!("expected not applied for contradicting intent, got {other:?}"),
        }
        assert_eq!(runner.post_issue_comment_calls(), 0);
        assert_eq!(runner.create_commit_on_branch_calls(), 0);
        let wal: DefaultEffectWal = EffectWal::open_instance(
            repository_auth_writer(&repo)
                .expect("auth")
                .into_authenticator()
                .expect("authenticator"),
            &logical_id,
        )
        .expect("reopen WAL");
        assert_eq!(wal.phase(&comment_effect_id), Some(EffectPhase::Planned));
        assert_eq!(wal.phase(&cas_effect_id), Some(EffectPhase::Planned));
    }

    #[test]
    fn parse_journal_ref_head_with_provider_time_accepts_imf_fixdate() {
        let raw = ref_head_include_response(CHILD_OID, "Sat, 16 Aug 2026 00:00:31 GMT");
        let parsed = parse_journal_ref_head_with_provider_time_response(&raw, JOURNAL_BRANCH_REF)
            .expect("parsed");
        assert_eq!(parsed.head_oid, CHILD_OID);
        assert_eq!(parsed.provider_time.as_str(), "2026-08-16T00:00:31Z");
    }

    #[test]
    fn parse_journal_ref_head_with_provider_time_rejects_wrong_ref_or_object_type() {
        let date = "Sat, 16 Aug 2026 00:00:31 GMT";
        let wrong_ref = format!(
            "HTTP/2.0 200 OK\r\nDate: {}\r\n\r\n{}",
            date,
            serde_json::json!({
                "ref": "refs/heads/other",
                "object": { "sha": CHILD_OID, "type": "commit" }
            })
        );
        assert!(
            parse_journal_ref_head_with_provider_time_response(&wrong_ref, JOURNAL_BRANCH_REF)
                .is_err()
        );
        let wrong_type = format!(
            "HTTP/2.0 200 OK\r\nDate: {}\r\n\r\n{}",
            date,
            serde_json::json!({
                "ref": JOURNAL_BRANCH_REF,
                "object": { "sha": CHILD_OID, "type": "tag" }
            })
        );
        assert!(parse_journal_ref_head_with_provider_time_response(
            &wrong_type,
            JOURNAL_BRANCH_REF
        )
        .is_err());
    }

    #[test]
    fn takeover_live_provider_time_refuses_before_post() {
        let (_temp, repo) = coordination_git_repo();
        let bind_runner =
            ScriptedCoordinationRunner::new(adapter_responses([]).into_iter().collect::<Vec<_>>());
        let config = adapter_config(&repo, &bind_runner);
        let (claim_body, pointer_blob_oid, pointer_blob_json) = child_claim_journal_fixture();
        let predecessor =
            CoordinationOwnerIdentity::new("run-old", "nonce-old").expect("predecessor");
        let intent = takeover_intent_for_predecessor(predecessor);
        let author = actor("trusted-a");
        let mut apply_responses = Vec::new();
        append_verified_child_journal_history_load(
            &mut apply_responses,
            &claim_body,
            &pointer_blob_oid,
            &pointer_blob_json,
        );
        append_verified_child_journal_history_load(
            &mut apply_responses,
            &claim_body,
            &pointer_blob_oid,
            &pointer_blob_json,
        );
        apply_responses.push(ref_head_include_response(
            CHILD_OID,
            "Sat, 16 Aug 2026 00:00:15 GMT",
        ));
        let runner = Arc::new(ScriptedCoordinationRunner::new(apply_responses));
        let transport = CoordinationGithubTransport::new(config, Arc::clone(&runner));
        let outcome = transport
            .apply_authorized_intent(intent, author, None)
            .expect("live takeover refusal");
        assert!(matches!(
            outcome,
            CoordinationMutationOutcome::NotApplied { .. }
        ));
        assert_eq!(runner.post_issue_comment_calls(), 0);
        assert_eq!(runner.create_commit_on_branch_calls(), 0);
    }

    #[test]
    fn takeover_missing_or_duplicate_provider_date_refuses_without_effects() {
        let (_temp, repo) = coordination_git_repo();
        let bind_runner =
            ScriptedCoordinationRunner::new(adapter_responses([]).into_iter().collect::<Vec<_>>());
        let config = adapter_config(&repo, &bind_runner);
        let (claim_body, pointer_blob_oid, pointer_blob_json) = child_claim_journal_fixture();
        let predecessor =
            CoordinationOwnerIdentity::new("run-old", "nonce-old").expect("predecessor");
        let intent = takeover_intent_for_predecessor(predecessor);
        let author = actor("trusted-a");

        let mut missing = Vec::new();
        append_verified_child_journal_history_load(
            &mut missing,
            &claim_body,
            &pointer_blob_oid,
            &pointer_blob_json,
        );
        append_verified_child_journal_history_load(
            &mut missing,
            &claim_body,
            &pointer_blob_oid,
            &pointer_blob_json,
        );
        missing.push(format!(
            "HTTP/2.0 200 OK\r\n\r\n{}",
            json_ref_head_include_body(CHILD_OID)
        ));
        let runner = Arc::new(ScriptedCoordinationRunner::new(missing));
        let transport = CoordinationGithubTransport::new(config, Arc::clone(&runner));
        let outcome = transport
            .apply_authorized_intent(intent.clone(), author.clone(), None)
            .expect("missing date refusal");
        assert!(matches!(
            outcome,
            CoordinationMutationOutcome::NotApplied { .. }
        ));
        assert_eq!(runner.post_issue_comment_calls(), 0);
        assert_eq!(runner.create_commit_on_branch_calls(), 0);

        let bind_runner =
            ScriptedCoordinationRunner::new(adapter_responses([]).into_iter().collect::<Vec<_>>());
        let config = adapter_config(&repo, &bind_runner);
        let mut duplicate = Vec::new();
        append_verified_child_journal_history_load(
            &mut duplicate,
            &claim_body,
            &pointer_blob_oid,
            &pointer_blob_json,
        );
        append_verified_child_journal_history_load(
            &mut duplicate,
            &claim_body,
            &pointer_blob_oid,
            &pointer_blob_json,
        );
        duplicate.push(format!(
            "HTTP/2.0 200 OK\r\nDate: Sat, 16 Aug 2026 00:01:00 GMT\r\nDate: Sat, 16 Aug 2026 00:01:01 GMT\r\n\r\n{}",
            json_ref_head_include_body(CHILD_OID)
        ));
        let runner = Arc::new(ScriptedCoordinationRunner::new(duplicate));
        let transport = CoordinationGithubTransport::new(config, Arc::clone(&runner));
        let outcome = transport
            .apply_authorized_intent(intent, author, None)
            .expect("duplicate date refusal");
        assert!(matches!(
            outcome,
            CoordinationMutationOutcome::NotApplied { .. }
        ));
        assert_eq!(runner.post_issue_comment_calls(), 0);
        assert_eq!(runner.create_commit_on_branch_calls(), 0);
    }

    #[test]
    fn takeover_stale_provider_time_allows_comment_and_cas() {
        let (_temp, repo) = coordination_git_repo();
        let bind_runner =
            ScriptedCoordinationRunner::new(adapter_responses([]).into_iter().collect::<Vec<_>>());
        let config = adapter_config(&repo, &bind_runner);
        let (claim_body, claim_pointer_blob_oid, claim_pointer_blob_json) =
            child_claim_journal_fixture();
        let predecessor =
            CoordinationOwnerIdentity::new("run-old", "nonce-old").expect("predecessor");
        let intent = takeover_intent_for_predecessor(predecessor);
        let author = actor("trusted-a");
        let body = intent.render().expect("takeover body");
        let pointer = JournalPointer::new(
            intent.event_nonce(),
            github_node_object_id(ProviderObjectKind::Comment, "IC_comment_b").expect("comment id"),
            sha256_hex(body.as_bytes()),
            CHILD_OID,
        )
        .expect("pointer");
        let pointer_file = pointer.render_pointer_file().expect("pointer file");
        let (pointer_blob_oid, pointer_blob_json) = blob_wire(&pointer_file);
        let cas_graphql = serde_json::json!({
            "data": { "createCommitOnBranch": { "commit": { "oid": GRANDCHILD_OID } } }
        })
        .to_string();
        let takeover_comment = comment_json_with_node_and_created_at(
            &body,
            "IC_comment_b",
            102,
            "2026-08-16T00:01:00Z",
        );
        let mut apply_responses = Vec::new();
        append_verified_child_journal_history_load(
            &mut apply_responses,
            &claim_body,
            &claim_pointer_blob_oid,
            &claim_pointer_blob_json,
        );
        append_verified_child_journal_history_load(
            &mut apply_responses,
            &claim_body,
            &claim_pointer_blob_oid,
            &claim_pointer_blob_json,
        );
        apply_responses.push(ref_head_include_response(
            CHILD_OID,
            "Sat, 16 Aug 2026 00:01:01 GMT",
        ));
        apply_responses.push(json_empty_comments_page());
        apply_responses.push(takeover_comment.clone());
        apply_responses.push(takeover_comment.clone());
        apply_responses.push(takeover_comment.clone());
        append_verified_child_journal_history_load(
            &mut apply_responses,
            &claim_body,
            &claim_pointer_blob_oid,
            &claim_pointer_blob_json,
        );
        apply_responses.push(json_ref_head(CHILD_OID));
        apply_responses.push(json_commit(CHILD_OID, CHILD_TREE, Some(ANCHOR_OID)));
        apply_responses.push(json_commit(ANCHOR_OID, ANCHOR_TREE, None));
        apply_responses.push(json_pointer_child_tree(CHILD_TREE, &claim_pointer_blob_oid));
        apply_responses.push(json_empty_tree(ANCHOR_TREE));
        apply_responses.push(claim_pointer_blob_json.clone());
        apply_responses.push(cas_graphql);
        append_cas_receipt_verification_grandchild(
            &mut apply_responses,
            &claim_pointer_blob_oid,
            &pointer_blob_oid,
            &pointer_blob_json,
        );
        append_verified_grandchild_journal_history_load(
            &mut apply_responses,
            &claim_body,
            &claim_pointer_blob_oid,
            &claim_pointer_blob_json,
            serde_json::from_str(&takeover_comment).expect("takeover comment JSON"),
            &pointer_blob_oid,
            &pointer_blob_json,
        );
        let runner = Arc::new(ScriptedCoordinationRunner::new(apply_responses));
        let transport = CoordinationGithubTransport::new(config, Arc::clone(&runner));
        let outcome = transport
            .apply_authorized_intent(intent, author, None)
            .expect("stale takeover apply");
        assert!(matches!(
            outcome,
            CoordinationMutationOutcome::Applied { .. }
        ));
        assert_eq!(runner.post_issue_comment_calls(), 1);
        assert_eq!(runner.create_commit_on_branch_calls(), 1);
    }

    #[test]
    fn takeover_future_provider_time_with_live_comment_is_unknown_without_cas() {
        let (_temp, repo) = coordination_git_repo();
        let bind_runner =
            ScriptedCoordinationRunner::new(adapter_responses([]).into_iter().collect::<Vec<_>>());
        let config = adapter_config(&repo, &bind_runner);
        let (claim_body, pointer_blob_oid, pointer_blob_json) = child_claim_journal_fixture();
        let predecessor =
            CoordinationOwnerIdentity::new("run-old", "nonce-old").expect("predecessor");
        let intent = takeover_intent_for_predecessor(predecessor);
        let author = actor("trusted-a");
        let body = intent.render().expect("takeover body");
        let live_comment = comment_json_with_node_and_created_at(
            &body,
            "IC_comment_b",
            102,
            "2026-08-16T00:00:15Z",
        );
        let mut apply_responses = Vec::new();
        append_verified_child_journal_history_load(
            &mut apply_responses,
            &claim_body,
            &pointer_blob_oid,
            &pointer_blob_json,
        );
        append_verified_child_journal_history_load(
            &mut apply_responses,
            &claim_body,
            &pointer_blob_oid,
            &pointer_blob_json,
        );
        apply_responses.push(ref_head_include_response(
            CHILD_OID,
            "Sat, 16 Aug 2026 01:00:00 GMT",
        ));
        apply_responses.push(json_empty_comments_page());
        apply_responses.push(live_comment.clone());
        apply_responses.push(live_comment.clone());
        apply_responses.push(live_comment.clone());
        append_verified_child_journal_history_load(
            &mut apply_responses,
            &claim_body,
            &pointer_blob_oid,
            &pointer_blob_json,
        );
        let runner = Arc::new(ScriptedCoordinationRunner::new(apply_responses));
        let transport = CoordinationGithubTransport::new(config, Arc::clone(&runner));
        let outcome = transport
            .apply_authorized_intent(intent, author, None)
            .expect("future provider time with live comment");
        match outcome {
            CoordinationMutationOutcome::Unknown { evidence } => {
                assert!(evidence.contains("semantic transition was refused"));
            }
            other => panic!("expected unknown after live comment observation, got {other:?}"),
        }
        assert_eq!(runner.post_issue_comment_calls(), 1);
        assert_eq!(runner.create_commit_on_branch_calls(), 0);
    }

    #[test]
    fn takeover_provider_time_journal_head_race_is_unknown_without_post_or_cas() {
        let (_temp, repo) = coordination_git_repo();
        let bind_runner =
            ScriptedCoordinationRunner::new(adapter_responses([]).into_iter().collect::<Vec<_>>());
        let config = adapter_config(&repo, &bind_runner);
        let (claim_body, pointer_blob_oid, pointer_blob_json) = child_claim_journal_fixture();
        let predecessor =
            CoordinationOwnerIdentity::new("run-old", "nonce-old").expect("predecessor");
        let intent = takeover_intent_for_predecessor(predecessor);
        let author = actor("trusted-a");
        let mut apply_responses = Vec::new();
        append_verified_child_journal_history_load(
            &mut apply_responses,
            &claim_body,
            &pointer_blob_oid,
            &pointer_blob_json,
        );
        append_verified_child_journal_history_load(
            &mut apply_responses,
            &claim_body,
            &pointer_blob_oid,
            &pointer_blob_json,
        );
        apply_responses.push(ref_head_include_response(
            ANCHOR_OID,
            "Sat, 16 Aug 2026 00:01:01 GMT",
        ));
        let runner = Arc::new(ScriptedCoordinationRunner::new(apply_responses));
        let transport = CoordinationGithubTransport::new(config, Arc::clone(&runner));
        let outcome = transport
            .apply_authorized_intent(intent, author, None)
            .expect("journal head race");
        match outcome {
            CoordinationMutationOutcome::Unknown { evidence } => {
                assert!(evidence.contains("does not match current journal tip"));
            }
            other => panic!("expected unknown journal head race, got {other:?}"),
        }
        assert_eq!(runner.post_issue_comment_calls(), 0);
        assert_eq!(runner.create_commit_on_branch_calls(), 0);
    }
}
