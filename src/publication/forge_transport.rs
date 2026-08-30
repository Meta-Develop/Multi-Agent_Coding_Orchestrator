//! Provider-neutral, bounded forge observation and comment transport.
//!
//! This boundary deliberately exposes only two complete observations and one
//! idempotent mutation. Provider command construction remains outside the
//! transport trait.

use crate::optimizer::{
    ids::TimestampMillis,
    merge_authority::{
        decide_merge, CheckStatus, CompletionMode, LensDecision, LensVerdict, MergeActor,
        MergeBlocker, MergeDecision, MergeRequest, ProducerFingerprint, VerificationCheck,
    },
};
use anyhow::{bail, Context, Result};
use serde::{de::DeserializeOwned, Deserialize, Deserializer, Serialize};
use std::{
    collections::{btree_map::Entry, BTreeMap, BTreeSet},
    path::PathBuf,
    sync::Mutex,
};

const MAX_PROVIDER_ID_BYTES: usize = 64;
const MAX_STABLE_ID_BYTES: usize = 256;
const MAX_LOCATOR_BYTES: usize = 512;
const MAX_HANDLE_BYTES: usize = 128;
const MAX_REVISION_BYTES: usize = 128;
const MAX_BODY_BYTES: usize = 64 * 1024;
const MAX_NAME_BYTES: usize = 256;
const MAX_URL_BYTES: usize = 2 * 1024;
const MAX_REQUEST_BYTES: usize = 128 * 1024;
const MAX_RESPONSE_BYTES: usize = 512 * 1024;
const MAX_COMMENTS: usize = 1_024;
const MAX_REVIEWS: usize = 512;
const MAX_THREADS: usize = 512;
const MAX_THREAD_COMMENTS: usize = 512;
const MAX_CHECKS: usize = 512;
const MAX_TOTAL_REVIEW_COMMENTS: usize = 4_096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderObjectKind {
    Repository,
    Item,
    Actor,
    Comment,
    Review,
    ReviewThread,
    Check,
    Merge,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct ProviderObjectId {
    provider_id: String,
    kind: ProviderObjectKind,
    stable_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProviderObjectIdWire {
    provider_id: String,
    kind: ProviderObjectKind,
    stable_id: String,
}

impl ProviderObjectId {
    pub fn new(
        provider_id: impl Into<String>,
        kind: ProviderObjectKind,
        stable_id: impl Into<String>,
    ) -> Result<Self> {
        let value = Self {
            provider_id: provider_id.into(),
            kind,
            stable_id: stable_id.into(),
        };
        value.validate()?;
        Ok(value)
    }

    pub fn provider_id(&self) -> &str {
        &self.provider_id
    }

    pub fn kind(&self) -> ProviderObjectKind {
        self.kind
    }

    pub fn stable_id(&self) -> &str {
        &self.stable_id
    }

    fn validate(&self) -> Result<()> {
        validate_provider_id(&self.provider_id)?;
        validate_stable_id(&self.stable_id, "provider object id")
    }
}

impl<'de> Deserialize<'de> for ProviderObjectId {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = ProviderObjectIdWire::deserialize(deserializer)?;
        Self::new(wire.provider_id, wire.kind, wire.stable_id).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ForgeRepository {
    provider_id: String,
    canonical_locator: String,
    provider_repository_id: ProviderObjectId,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ForgeRepositoryWire {
    provider_id: String,
    canonical_locator: String,
    provider_repository_id: ProviderObjectId,
}

impl ForgeRepository {
    pub fn new(
        provider_id: impl Into<String>,
        canonical_locator: impl Into<String>,
        provider_repository_id: ProviderObjectId,
    ) -> Result<Self> {
        let value = Self {
            provider_id: provider_id.into(),
            canonical_locator: canonical_locator.into(),
            provider_repository_id,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn provider_id(&self) -> &str {
        &self.provider_id
    }

    pub fn canonical_locator(&self) -> &str {
        &self.canonical_locator
    }

    pub fn provider_repository_id(&self) -> &ProviderObjectId {
        &self.provider_repository_id
    }

    fn validate(&self) -> Result<()> {
        validate_provider_id(&self.provider_id)?;
        validate_repository_locator(&self.canonical_locator)?;
        require_object_id(
            &self.provider_repository_id,
            &self.provider_id,
            ProviderObjectKind::Repository,
            "repository provider id",
        )
    }
}

impl<'de> Deserialize<'de> for ForgeRepository {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = ForgeRepositoryWire::deserialize(deserializer)?;
        Self::new(
            wire.provider_id,
            wire.canonical_locator,
            wire.provider_repository_id,
        )
        .map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ForgeItemKind {
    Issue,
    PullRequest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportedActorKind {
    Human,
    Bot,
    Organization,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ForgeActor {
    provider_id: String,
    provider_actor_id: ProviderObjectId,
    canonical_handle: String,
    reported_kind: ReportedActorKind,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ForgeActorWire {
    provider_id: String,
    provider_actor_id: ProviderObjectId,
    canonical_handle: String,
    reported_kind: ReportedActorKind,
}

impl ForgeActor {
    pub fn new(
        provider_id: impl Into<String>,
        provider_actor_id: ProviderObjectId,
        canonical_handle: impl Into<String>,
        reported_kind: ReportedActorKind,
    ) -> Result<Self> {
        let value = Self {
            provider_id: provider_id.into(),
            provider_actor_id,
            canonical_handle: canonical_handle.into(),
            reported_kind,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn provider_id(&self) -> &str {
        &self.provider_id
    }

    pub fn provider_actor_id(&self) -> &ProviderObjectId {
        &self.provider_actor_id
    }

    pub fn canonical_handle(&self) -> &str {
        &self.canonical_handle
    }

    pub fn reported_kind(&self) -> ReportedActorKind {
        self.reported_kind
    }

    fn validate(&self) -> Result<()> {
        validate_provider_id(&self.provider_id)?;
        require_object_id(
            &self.provider_actor_id,
            &self.provider_id,
            ProviderObjectKind::Actor,
            "actor provider id",
        )?;
        validate_canonical_handle(&self.canonical_handle)
    }
}

impl<'de> Deserialize<'de> for ForgeActor {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = ForgeActorWire::deserialize(deserializer)?;
        Self::new(
            wire.provider_id,
            wire.provider_actor_id,
            wire.canonical_handle,
            wire.reported_kind,
        )
        .map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(transparent)]
pub struct ForgeTimestamp(String);

impl ForgeTimestamp {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        validate_timestamp(&value)?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for ForgeTimestamp {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ForgeItem {
    repository: ForgeRepository,
    kind: ForgeItemKind,
    number: u64,
    provider_item_id: ProviderObjectId,
    revision: String,
    head_oid: Option<String>,
    base_oid: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ForgeItemWire {
    repository: ForgeRepository,
    kind: ForgeItemKind,
    number: u64,
    provider_item_id: ProviderObjectId,
    revision: String,
    #[serde(deserialize_with = "required_nullable")]
    head_oid: Option<String>,
    #[serde(deserialize_with = "required_nullable")]
    base_oid: Option<String>,
}

impl ForgeItem {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        repository: ForgeRepository,
        kind: ForgeItemKind,
        number: u64,
        provider_item_id: ProviderObjectId,
        revision: impl Into<String>,
        head_oid: Option<String>,
        base_oid: Option<String>,
    ) -> Result<Self> {
        let value = Self {
            repository,
            kind,
            number,
            provider_item_id,
            revision: revision.into(),
            head_oid,
            base_oid,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn repository(&self) -> &ForgeRepository {
        &self.repository
    }

    pub fn kind(&self) -> ForgeItemKind {
        self.kind
    }

    pub fn number(&self) -> u64 {
        self.number
    }

    pub fn provider_item_id(&self) -> &ProviderObjectId {
        &self.provider_item_id
    }

    pub fn revision(&self) -> &str {
        &self.revision
    }

    pub fn head_oid(&self) -> Option<&str> {
        self.head_oid.as_deref()
    }

    pub fn base_oid(&self) -> Option<&str> {
        self.base_oid.as_deref()
    }

    fn validate(&self) -> Result<()> {
        self.repository.validate()?;
        if self.number == 0 {
            bail!("forge item number must be positive");
        }
        require_object_id(
            &self.provider_item_id,
            self.repository.provider_id(),
            ProviderObjectKind::Item,
            "item provider id",
        )?;
        validate_revision(&self.revision)?;
        match self.kind {
            ForgeItemKind::Issue => {
                if self.head_oid.is_some() || self.base_oid.is_some() {
                    bail!("forge issue items must not carry Git OIDs");
                }
            }
            ForgeItemKind::PullRequest => {
                let head = self
                    .head_oid
                    .as_deref()
                    .context("forge pull request omitted its exact head OID")?;
                let base = self
                    .base_oid
                    .as_deref()
                    .context("forge pull request omitted its exact base OID")?;
                validate_git_oid(head, "pull-request head OID")?;
                validate_git_oid(base, "pull-request base OID")?;
                if head.len() != base.len() {
                    bail!("pull-request head and base OIDs use different hash widths");
                }
            }
        }
        Ok(())
    }
}

impl<'de> Deserialize<'de> for ForgeItem {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = ForgeItemWire::deserialize(deserializer)?;
        Self::new(
            wire.repository,
            wire.kind,
            wire.number,
            wire.provider_item_id,
            wire.revision,
            wire.head_oid,
            wire.base_oid,
        )
        .map_err(serde::de::Error::custom)
    }
}

fn required_nullable<'de, D, T>(deserializer: D) -> std::result::Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

fn validate_provider_id(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > MAX_PROVIDER_ID_BYTES
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'.')
        })
    {
        bail!("forge provider id is not canonical and bounded");
    }
    Ok(())
}

fn validate_stable_id(value: &str, label: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > MAX_STABLE_ID_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        bail!("{label} is not a bounded stable provider id");
    }
    Ok(())
}

fn require_object_id(
    id: &ProviderObjectId,
    provider_id: &str,
    kind: ProviderObjectKind,
    label: &str,
) -> Result<()> {
    id.validate()?;
    if id.provider_id() != provider_id || id.kind() != kind {
        bail!("{label} is not bound to the expected provider and object kind");
    }
    Ok(())
}

fn validate_repository_locator(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > MAX_LOCATOR_BYTES
        || value.starts_with('/')
        || value.ends_with('/')
        || value.contains("//")
        || value.bytes().any(|byte| {
            byte.is_ascii_control() || byte.is_ascii_whitespace() || byte.is_ascii_uppercase()
        })
    {
        bail!("forge repository locator is not canonical and bounded");
    }
    let components = value.split('/').collect::<Vec<_>>();
    if components.len() < 3
        || components.iter().any(|component| {
            component.is_empty()
                || component == &"."
                || component == &".."
                || !component.bytes().all(|byte| {
                    byte.is_ascii_lowercase()
                        || byte.is_ascii_digit()
                        || matches!(byte, b'-' | b'_' | b'.')
                })
        })
    {
        bail!("forge repository locator must be a canonical host/path locator");
    }
    Ok(())
}

fn validate_canonical_handle(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > MAX_HANDLE_BYTES
        || value.starts_with('@')
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_' | b'.')
        })
    {
        bail!("forge actor handle is not canonical and bounded");
    }
    Ok(())
}

fn validate_revision(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > MAX_REVISION_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        bail!("forge item revision is not a bounded stable id");
    }
    Ok(())
}

fn validate_git_oid(value: &str, label: &str) -> Result<()> {
    if !matches!(value.len(), 40 | 64)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("{label} must be an exact lowercase 40- or 64-hex OID");
    }
    Ok(())
}

fn validate_timestamp(value: &str) -> Result<()> {
    let bytes = value.as_bytes();
    if bytes.len() != 20
        || bytes.get(4) != Some(&b'-')
        || bytes.get(7) != Some(&b'-')
        || bytes.get(10) != Some(&b'T')
        || bytes.get(13) != Some(&b':')
        || bytes.get(16) != Some(&b':')
        || bytes.get(19) != Some(&b'Z')
        || bytes.iter().enumerate().any(|(index, byte)| {
            !matches!(index, 4 | 7 | 10 | 13 | 16 | 19) && !byte.is_ascii_digit()
        })
    {
        bail!("forge timestamp must be canonical UTC YYYY-MM-DDTHH:MM:SSZ");
    }
    let decimal = |range: std::ops::Range<usize>| -> Result<u32> {
        std::str::from_utf8(&bytes[range])?
            .parse::<u32>()
            .context("forge timestamp component was invalid")
    };
    let year = decimal(0..4)?;
    let month = decimal(5..7)?;
    let day = decimal(8..10)?;
    let hour = decimal(11..13)?;
    let minute = decimal(14..16)?;
    let second = decimal(17..19)?;
    if year == 0 || !(1..=12).contains(&month) || hour > 23 || minute > 59 || second > 59 {
        bail!("forge timestamp contains an out-of-range calendar or time component");
    }
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => 0,
    };
    if day == 0 || day > days {
        bail!("forge timestamp contains an invalid calendar day");
    }
    Ok(())
}

fn validate_bounded_text(value: &str, label: &str, limit: usize, allow_empty: bool) -> Result<()> {
    if (!allow_empty && value.is_empty())
        || value.len() > limit
        || value
            .bytes()
            .any(|byte| byte == 0 || (byte.is_ascii_control() && byte != b'\n' && byte != b'\t'))
    {
        bail!("{label} is empty, malformed, or exceeds its {limit}-byte bound");
    }
    Ok(())
}

fn validate_serialized<T: Serialize>(value: &T, limit: usize, label: &str) -> Result<()> {
    let encoded = serde_json::to_vec(value).with_context(|| format!("failed to size {label}"))?;
    if encoded.len() > limit {
        bail!("{label} exceeds its {limit}-byte serialized limit");
    }
    Ok(())
}

fn parse_bounded_json<T: DeserializeOwned>(json: &str, label: &str) -> Result<T> {
    if json.len() > MAX_RESPONSE_BYTES || json.as_bytes().contains(&0) {
        bail!("{label} is malformed or exceeds its serialized limit");
    }
    serde_json::from_str(json).with_context(|| format!("{label} was not strict valid JSON"))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ForgeComment {
    provider_comment_id: ProviderObjectId,
    author: ForgeActor,
    body: String,
    url: String,
    created_at: ForgeTimestamp,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ForgeCommentWire {
    provider_comment_id: ProviderObjectId,
    author: ForgeActor,
    body: String,
    url: String,
    created_at: ForgeTimestamp,
}

impl ForgeComment {
    pub fn new(
        provider_comment_id: ProviderObjectId,
        author: ForgeActor,
        body: impl Into<String>,
        url: impl Into<String>,
        created_at: ForgeTimestamp,
    ) -> Result<Self> {
        let value = Self {
            provider_comment_id,
            author,
            body: body.into(),
            url: url.into(),
            created_at,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn provider_comment_id(&self) -> &ProviderObjectId {
        &self.provider_comment_id
    }

    pub fn author(&self) -> &ForgeActor {
        &self.author
    }

    pub fn body(&self) -> &str {
        &self.body
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    pub fn created_at(&self) -> &ForgeTimestamp {
        &self.created_at
    }

    fn validate(&self) -> Result<()> {
        self.author.validate()?;
        require_object_id(
            &self.provider_comment_id,
            self.author.provider_id(),
            ProviderObjectKind::Comment,
            "comment provider id",
        )?;
        validate_bounded_text(&self.body, "forge comment body", MAX_BODY_BYTES, true)?;
        validate_https_url(&self.url)
    }
}

impl<'de> Deserialize<'de> for ForgeComment {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = ForgeCommentWire::deserialize(deserializer)?;
        Self::new(
            wire.provider_comment_id,
            wire.author,
            wire.body,
            wire.url,
            wire.created_at,
        )
        .map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ForgeReviewState {
    Approved,
    ChangesRequested,
    Commented,
    Dismissed,
    Pending,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ForgeReview {
    provider_review_id: ProviderObjectId,
    author: ForgeActor,
    state: ForgeReviewState,
    body: String,
    submitted_at: ForgeTimestamp,
    commit_oid: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ForgeReviewWire {
    provider_review_id: ProviderObjectId,
    author: ForgeActor,
    state: ForgeReviewState,
    body: String,
    submitted_at: ForgeTimestamp,
    commit_oid: String,
}

impl ForgeReview {
    pub fn new(
        provider_review_id: ProviderObjectId,
        author: ForgeActor,
        state: ForgeReviewState,
        body: impl Into<String>,
        submitted_at: ForgeTimestamp,
        commit_oid: impl Into<String>,
    ) -> Result<Self> {
        let value = Self {
            provider_review_id,
            author,
            state,
            body: body.into(),
            submitted_at,
            commit_oid: commit_oid.into(),
        };
        value.validate()?;
        Ok(value)
    }

    pub fn provider_review_id(&self) -> &ProviderObjectId {
        &self.provider_review_id
    }

    pub fn author(&self) -> &ForgeActor {
        &self.author
    }

    pub fn state(&self) -> ForgeReviewState {
        self.state
    }

    pub fn body(&self) -> &str {
        &self.body
    }

    pub fn submitted_at(&self) -> &ForgeTimestamp {
        &self.submitted_at
    }

    pub fn commit_oid(&self) -> &str {
        &self.commit_oid
    }

    fn validate(&self) -> Result<()> {
        self.author.validate()?;
        require_object_id(
            &self.provider_review_id,
            self.author.provider_id(),
            ProviderObjectKind::Review,
            "review provider id",
        )?;
        validate_bounded_text(&self.body, "forge review body", MAX_BODY_BYTES, true)?;
        validate_git_oid(&self.commit_oid, "review commit OID")
    }
}

impl<'de> Deserialize<'de> for ForgeReview {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = ForgeReviewWire::deserialize(deserializer)?;
        Self::new(
            wire.provider_review_id,
            wire.author,
            wire.state,
            wire.body,
            wire.submitted_at,
            wire.commit_oid,
        )
        .map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ForgeReviewThread {
    provider_thread_id: ProviderObjectId,
    is_resolved: bool,
    comments: Vec<ForgeComment>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ForgeReviewThreadWire {
    provider_thread_id: ProviderObjectId,
    is_resolved: bool,
    comments: Vec<ForgeComment>,
}

impl ForgeReviewThread {
    pub fn new(
        provider_thread_id: ProviderObjectId,
        is_resolved: bool,
        comments: Vec<ForgeComment>,
    ) -> Result<Self> {
        let value = Self {
            provider_thread_id,
            is_resolved,
            comments,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn provider_thread_id(&self) -> &ProviderObjectId {
        &self.provider_thread_id
    }

    pub fn is_resolved(&self) -> bool {
        self.is_resolved
    }

    pub fn comments(&self) -> &[ForgeComment] {
        &self.comments
    }

    fn validate(&self) -> Result<()> {
        if self.comments.len() > MAX_THREAD_COMMENTS {
            bail!("forge review thread exceeds its comment count limit");
        }
        let provider = self.provider_thread_id.provider_id();
        require_object_id(
            &self.provider_thread_id,
            provider,
            ProviderObjectKind::ReviewThread,
            "review-thread provider id",
        )?;
        let mut ids = BTreeSet::new();
        for comment in &self.comments {
            comment.validate()?;
            if comment.author.provider_id() != provider
                || !ids.insert(comment.provider_comment_id.clone())
            {
                bail!("forge review thread contains a provider mismatch or duplicate comment id");
            }
        }
        validate_actor_identity(self.comments.iter().map(ForgeComment::author))
    }
}

impl<'de> Deserialize<'de> for ForgeReviewThread {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = ForgeReviewThreadWire::deserialize(deserializer)?;
        Self::new(wire.provider_thread_id, wire.is_resolved, wire.comments)
            .map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ForgeCheckStatus {
    Queued,
    InProgress,
    Completed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ForgeCheckConclusion {
    Success,
    Failure,
    Neutral,
    Cancelled,
    Skipped,
    TimedOut,
    ActionRequired,
    StartupFailure,
    Stale,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ForgeCheck {
    provider_check_id: ProviderObjectId,
    actor: ForgeActor,
    name: String,
    status: ForgeCheckStatus,
    conclusion: Option<ForgeCheckConclusion>,
    head_oid: String,
    updated_at: ForgeTimestamp,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ForgeCheckWire {
    provider_check_id: ProviderObjectId,
    actor: ForgeActor,
    name: String,
    status: ForgeCheckStatus,
    #[serde(deserialize_with = "required_nullable")]
    conclusion: Option<ForgeCheckConclusion>,
    head_oid: String,
    updated_at: ForgeTimestamp,
}

impl ForgeCheck {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        provider_check_id: ProviderObjectId,
        actor: ForgeActor,
        name: impl Into<String>,
        status: ForgeCheckStatus,
        conclusion: Option<ForgeCheckConclusion>,
        head_oid: impl Into<String>,
        updated_at: ForgeTimestamp,
    ) -> Result<Self> {
        let value = Self {
            provider_check_id,
            actor,
            name: name.into(),
            status,
            conclusion,
            head_oid: head_oid.into(),
            updated_at,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn provider_check_id(&self) -> &ProviderObjectId {
        &self.provider_check_id
    }

    pub fn actor(&self) -> &ForgeActor {
        &self.actor
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn status(&self) -> ForgeCheckStatus {
        self.status
    }

    pub fn conclusion(&self) -> Option<ForgeCheckConclusion> {
        self.conclusion
    }

    pub fn head_oid(&self) -> &str {
        &self.head_oid
    }

    pub fn updated_at(&self) -> &ForgeTimestamp {
        &self.updated_at
    }

    fn validate(&self) -> Result<()> {
        self.actor.validate()?;
        require_object_id(
            &self.provider_check_id,
            self.actor.provider_id(),
            ProviderObjectKind::Check,
            "check provider id",
        )?;
        validate_bounded_text(&self.name, "forge check name", MAX_NAME_BYTES, false)?;
        validate_git_oid(&self.head_oid, "check head OID")?;
        if matches!(self.status, ForgeCheckStatus::Completed) != self.conclusion.is_some() {
            bail!("forge check completion status and conclusion conflict");
        }
        Ok(())
    }
}

impl<'de> Deserialize<'de> for ForgeCheck {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = ForgeCheckWire::deserialize(deserializer)?;
        Self::new(
            wire.provider_check_id,
            wire.actor,
            wire.name,
            wire.status,
            wire.conclusion,
            wire.head_oid,
            wire.updated_at,
        )
        .map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ItemThreadObservation {
    item: ForgeItem,
    observed_at: ForgeTimestamp,
    comments: Vec<ForgeComment>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ItemThreadObservationWire {
    item: ForgeItem,
    observed_at: ForgeTimestamp,
    comments: Vec<ForgeComment>,
}

impl ItemThreadObservation {
    pub fn new(
        item: ForgeItem,
        observed_at: ForgeTimestamp,
        comments: Vec<ForgeComment>,
    ) -> Result<Self> {
        let value = Self {
            item,
            observed_at,
            comments,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn item(&self) -> &ForgeItem {
        &self.item
    }

    pub fn observed_at(&self) -> &ForgeTimestamp {
        &self.observed_at
    }

    pub fn comments(&self) -> &[ForgeComment] {
        &self.comments
    }

    fn validate(&self) -> Result<()> {
        self.item.validate()?;
        if self.comments.len() > MAX_COMMENTS {
            bail!("forge item thread exceeds its comment count limit");
        }
        let mut ids = BTreeSet::new();
        for comment in &self.comments {
            comment.validate()?;
            if comment.author.provider_id() != self.item.repository.provider_id()
                || comment.created_at > self.observed_at
                || !ids.insert(comment.provider_comment_id.clone())
            {
                bail!("forge item thread contains an invalid, future, or duplicate comment");
            }
        }
        validate_actor_identity(self.comments.iter().map(ForgeComment::author))?;
        validate_serialized(self, MAX_RESPONSE_BYTES, "forge item-thread observation")
    }
}

impl<'de> Deserialize<'de> for ItemThreadObservation {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = ItemThreadObservationWire::deserialize(deserializer)?;
        Self::new(wire.item, wire.observed_at, wire.comments).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PullRequestReviewSnapshot {
    item: ForgeItem,
    observed_at: ForgeTimestamp,
    reviews: Vec<ForgeReview>,
    threads: Vec<ForgeReviewThread>,
    checks: Vec<ForgeCheck>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PullRequestReviewSnapshotWire {
    item: ForgeItem,
    observed_at: ForgeTimestamp,
    reviews: Vec<ForgeReview>,
    threads: Vec<ForgeReviewThread>,
    checks: Vec<ForgeCheck>,
}

impl PullRequestReviewSnapshot {
    pub fn new(
        item: ForgeItem,
        observed_at: ForgeTimestamp,
        reviews: Vec<ForgeReview>,
        threads: Vec<ForgeReviewThread>,
        checks: Vec<ForgeCheck>,
    ) -> Result<Self> {
        let value = Self {
            item,
            observed_at,
            reviews,
            threads,
            checks,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn item(&self) -> &ForgeItem {
        &self.item
    }

    pub fn observed_at(&self) -> &ForgeTimestamp {
        &self.observed_at
    }

    pub fn reviews(&self) -> &[ForgeReview] {
        &self.reviews
    }

    pub fn threads(&self) -> &[ForgeReviewThread] {
        &self.threads
    }

    pub fn checks(&self) -> &[ForgeCheck] {
        &self.checks
    }

    fn validate(&self) -> Result<()> {
        self.item.validate()?;
        if self.item.kind != ForgeItemKind::PullRequest {
            bail!("forge PR review snapshot requires a pull-request item");
        }
        if self.reviews.len() > MAX_REVIEWS
            || self.threads.len() > MAX_THREADS
            || self.checks.len() > MAX_CHECKS
        {
            bail!("forge PR review snapshot exceeds a collection count limit");
        }
        let total_comments = self.threads.iter().try_fold(0_usize, |total, thread| {
            total
                .checked_add(thread.comments.len())
                .context("forge review comment count overflowed")
        })?;
        if total_comments > MAX_TOTAL_REVIEW_COMMENTS {
            bail!("forge PR review snapshot exceeds its aggregate comment count limit");
        }
        let provider = self.item.repository.provider_id();
        let head = self
            .item
            .head_oid()
            .context("forge PR review snapshot item omitted head OID")?;
        let mut review_ids = BTreeSet::new();
        let mut thread_ids = BTreeSet::new();
        let mut comment_ids = BTreeSet::new();
        let mut check_ids = BTreeSet::new();
        let mut actors = Vec::new();
        for review in &self.reviews {
            review.validate()?;
            if review.author.provider_id() != provider
                || review.commit_oid != head
                || review.submitted_at > self.observed_at
                || !review_ids.insert(review.provider_review_id.clone())
            {
                bail!("forge PR snapshot contains an unbound, stale, future, or duplicate review");
            }
            actors.push(&review.author);
        }
        for thread in &self.threads {
            thread.validate()?;
            if thread.provider_thread_id.provider_id() != provider
                || !thread_ids.insert(thread.provider_thread_id.clone())
            {
                bail!("forge PR snapshot contains an unbound or duplicate review thread");
            }
            for comment in &thread.comments {
                if comment.created_at > self.observed_at
                    || !comment_ids.insert(comment.provider_comment_id.clone())
                {
                    bail!("forge PR snapshot contains a future or duplicate review comment");
                }
                actors.push(&comment.author);
            }
        }
        for check in &self.checks {
            check.validate()?;
            if check.actor.provider_id() != provider
                || check.head_oid != head
                || check.updated_at > self.observed_at
                || !check_ids.insert(check.provider_check_id.clone())
            {
                bail!("forge PR snapshot contains an unbound, stale, future, or duplicate check");
            }
            actors.push(&check.actor);
        }
        validate_actor_identity(actors.into_iter())?;
        validate_serialized(self, MAX_RESPONSE_BYTES, "forge PR review snapshot")
    }
}

impl<'de> Deserialize<'de> for PullRequestReviewSnapshot {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = PullRequestReviewSnapshotWire::deserialize(deserializer)?;
        Self::new(
            wire.item,
            wire.observed_at,
            wire.reviews,
            wire.threads,
            wire.checks,
        )
        .map_err(serde::de::Error::custom)
    }
}

/// Provider-observed current PR state used to prove that a review snapshot is
/// still the exact state being authorized.
///
/// This is an evidence input, not a clock heuristic. The adapter requires the
/// complete item and observation timestamp to equal the authenticated
/// snapshot and never guesses freshness from local time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PullRequestFreshnessStatus {
    Fresh,
    Stale,
    Uncertain,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PullRequestFreshnessEvidence {
    pub current_item: ForgeItem,
    pub snapshot_observed_at: ForgeTimestamp,
    pub status: PullRequestFreshnessStatus,
    pub decided_at: TimestampMillis,
}

/// Ground-truth producer identity bound to the exact PR head.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PullRequestProducerEvidence {
    pub head_oid: String,
    pub producer: ProducerFingerprint,
}

/// Ground-truth independent-auditor evidence bound to the reviewed head and
/// snapshot observation. Lens text is never inferred from a PR body, comment,
/// or requesting-agent message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PullRequestAuditorEvidence {
    pub head_oid: String,
    pub snapshot_observed_at: ForgeTimestamp,
    pub auditor: MergeActor,
    pub lenses: Vec<LensVerdict>,
}

/// Result of an actual merge simulation, bound to both sides of the simulated
/// merge and to the snapshot for which it was run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PullRequestMergeSimulationEvidence {
    pub head_oid: String,
    pub base_oid: String,
    pub snapshot_observed_at: ForgeTimestamp,
    pub merges_cleanly: bool,
}

/// Actual changed paths for the candidate head. Binding the path set prevents
/// callers from omitting never-auto-merge paths while supplying evidence for a
/// different revision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PullRequestChangedPathsEvidence {
    pub head_oid: String,
    pub paths: Vec<PathBuf>,
}

/// Accepted auditor evidence that may cross the authenticated merge boundary.
///
/// This capability deliberately has no public constructor and does not
/// implement `Deserialize`. Request bodies, comments, and other
/// requester-authored JSON therefore cannot mint merge authority. Trusted
/// crate code may construct it only after authenticating the accepted auditor
/// record; the effectful executor still rechecks every candidate binding and
/// the provider-observed approval immediately before the merge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct AuthenticatedPullRequestMergeEvidence {
    pub(crate) candidate: ForgeItem,
    /// Exact provider review selected from fresh GitHub ground truth.
    pub(crate) approved_review_id: ProviderObjectId,
    /// Provider-authenticated author of `approved_review_id`. This is distinct
    /// from the terminal critical auditor recorded in `auditor`; both are
    /// independently bound and neither is inferred from requester text.
    pub(crate) approved_reviewer: ForgeActor,
    pub(crate) required_checks: Vec<String>,
    pub(crate) producer: PullRequestProducerEvidence,
    pub(crate) auditor: PullRequestAuditorEvidence,
    pub(crate) merge_simulation: PullRequestMergeSimulationEvidence,
    pub(crate) completion_mode: CompletionMode,
    pub(crate) changed_paths: PullRequestChangedPathsEvidence,
}

impl AuthenticatedPullRequestMergeEvidence {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_authenticated_acceptance(
        candidate: ForgeItem,
        approved_review_id: ProviderObjectId,
        approved_reviewer: ForgeActor,
        required_checks: Vec<String>,
        producer: PullRequestProducerEvidence,
        auditor: PullRequestAuditorEvidence,
        merge_simulation: PullRequestMergeSimulationEvidence,
        completion_mode: CompletionMode,
        changed_paths: PullRequestChangedPathsEvidence,
    ) -> Result<Self> {
        candidate.validate()?;
        if candidate.kind() != ForgeItemKind::PullRequest {
            bail!("authenticated merge evidence requires a pull-request candidate");
        }
        require_object_id(
            &approved_review_id,
            candidate.repository().provider_id(),
            ProviderObjectKind::Review,
            "authenticated auditor approval review id",
        )?;
        approved_reviewer.validate()?;
        if approved_reviewer.provider_id() != candidate.repository().provider_id() {
            bail!("authenticated approval reviewer is not bound to the target provider");
        }
        let evidence = Self {
            candidate,
            approved_review_id,
            approved_reviewer,
            required_checks,
            producer,
            auditor,
            merge_simulation,
            completion_mode,
            changed_paths,
        };
        validate_serialized(
            &evidence,
            MAX_RESPONSE_BYTES,
            "authenticated pull-request merge evidence",
        )?;
        Ok(evidence)
    }
}

/// Complete, explicit inputs to the pure PR merge-authority adapter.
///
/// Optional fields model unavailable ground truth. Absence is returned as a
/// typed blocked decision; it is never filled from requesting-agent text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PullRequestMergeAuthorityInput {
    pub freshness: Option<PullRequestFreshnessEvidence>,
    pub required_checks: Option<Vec<String>>,
    pub producer: Option<PullRequestProducerEvidence>,
    pub auditor: Option<PullRequestAuditorEvidence>,
    pub merge_simulation: Option<PullRequestMergeSimulationEvidence>,
    pub completion_mode: Option<CompletionMode>,
    pub changed_paths: Option<PullRequestChangedPathsEvidence>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "blocker", content = "details", rename_all = "snake_case")]
pub enum PullRequestMergeAuthorityBlocker {
    MissingFreshnessEvidence,
    StaleSnapshotHead {
        snapshot_head_oid: String,
        current_head_oid: String,
    },
    StaleSnapshotObservation,
    UncertainSnapshotFreshness,
    SnapshotItemMismatch,
    MissingRequiredChecks,
    InvalidRequiredCheckName,
    DuplicateRequiredCheck {
        name: String,
    },
    MissingRequiredCheck {
        name: String,
    },
    AmbiguousRequiredCheck {
        name: String,
    },
    StaleRequiredCheck {
        name: String,
    },
    SkippedRequiredCheck {
        name: String,
    },
    FailedRequiredCheck {
        name: String,
        conclusion: ForgeCheckConclusion,
    },
    UncertainRequiredCheck {
        name: String,
    },
    MissingProducerEvidence,
    IncompleteProducerEvidence,
    StaleProducerEvidence,
    MissingAuditorEvidence,
    IncompleteAuditorEvidence,
    StaleAuditorEvidence,
    UncertainAuditorEvidence,
    MissingMergeSimulationEvidence,
    StaleMergeSimulationEvidence,
    MissingCompletionMode,
    MissingChangedPathsEvidence,
    EmptyChangedPathsEvidence,
    StaleChangedPathsEvidence,
    OptimizerBlocked(MergeBlocker),
    OptimizerDecisionFailed,
}

/// Pure authority result. `Allowed` means the optimizer received only exact,
/// complete evidence and returned an unblocked decision. `Blocked` never
/// authorizes a provider mutation, even when a nested diagnostic decision is
/// present.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum PullRequestMergeAuthorityDecision {
    Allowed {
        merge_decision: MergeDecision,
    },
    Blocked {
        blockers: Vec<PullRequestMergeAuthorityBlocker>,
        merge_decision: Option<MergeDecision>,
    },
}

impl PullRequestMergeAuthorityDecision {
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allowed { .. })
    }

    pub fn blockers(&self) -> &[PullRequestMergeAuthorityBlocker] {
        match self {
            Self::Allowed { .. } => &[],
            Self::Blocked { blockers, .. } => blockers,
        }
    }

    pub fn merge_decision(&self) -> Option<&MergeDecision> {
        match self {
            Self::Allowed { merge_decision } => Some(merge_decision),
            Self::Blocked { merge_decision, .. } => merge_decision.as_ref(),
        }
    }
}

/// Adapt an authenticated, constructor-validated PR snapshot and explicit
/// ground-truth evidence to optimizer merge authority.
///
/// The function is side-effect free: it does not call GitHub, merge a branch,
/// or interpret request/comment text as evidence.
pub fn decide_pull_request_merge(
    snapshot: &PullRequestReviewSnapshot,
    input: &PullRequestMergeAuthorityInput,
) -> PullRequestMergeAuthorityDecision {
    let head_oid = snapshot
        .item()
        .head_oid()
        .expect("validated PR snapshots always contain a head OID");
    let base_oid = snapshot
        .item()
        .base_oid()
        .expect("validated PR snapshots always contain a base OID");
    let mut blockers = Vec::new();
    let mut structurally_trusted = true;

    let decided_at = match &input.freshness {
        Some(freshness) => {
            match freshness.status {
                PullRequestFreshnessStatus::Fresh => {}
                PullRequestFreshnessStatus::Stale => {
                    blockers.push(PullRequestMergeAuthorityBlocker::StaleSnapshotObservation);
                    structurally_trusted = false;
                }
                PullRequestFreshnessStatus::Uncertain => {
                    blockers.push(PullRequestMergeAuthorityBlocker::UncertainSnapshotFreshness);
                    structurally_trusted = false;
                }
            }
            if freshness.current_item.head_oid() != Some(head_oid) {
                blockers.push(PullRequestMergeAuthorityBlocker::StaleSnapshotHead {
                    snapshot_head_oid: head_oid.to_string(),
                    current_head_oid: freshness
                        .current_item
                        .head_oid()
                        .unwrap_or_default()
                        .to_string(),
                });
                structurally_trusted = false;
            }
            if freshness.snapshot_observed_at != *snapshot.observed_at() {
                blockers.push(PullRequestMergeAuthorityBlocker::StaleSnapshotObservation);
                structurally_trusted = false;
            }
            if freshness.current_item != *snapshot.item() {
                blockers.push(PullRequestMergeAuthorityBlocker::SnapshotItemMismatch);
                structurally_trusted = false;
            }
            Some(freshness.decided_at)
        }
        None => {
            blockers.push(PullRequestMergeAuthorityBlocker::MissingFreshnessEvidence);
            structurally_trusted = false;
            None
        }
    };

    let verification_checks = map_required_checks(snapshot, &input.required_checks, &mut blockers);

    let producer = match &input.producer {
        Some(evidence) => {
            if !producer_is_complete(&evidence.producer) {
                blockers.push(PullRequestMergeAuthorityBlocker::IncompleteProducerEvidence);
                structurally_trusted = false;
            }
            if evidence.head_oid != head_oid {
                blockers.push(PullRequestMergeAuthorityBlocker::StaleProducerEvidence);
                structurally_trusted = false;
            }
            Some(evidence.producer.clone())
        }
        None => {
            blockers.push(PullRequestMergeAuthorityBlocker::MissingProducerEvidence);
            structurally_trusted = false;
            None
        }
    };

    let (auditor, lenses) = match &input.auditor {
        Some(evidence) => {
            if !actor_is_complete(&evidence.auditor) {
                blockers.push(PullRequestMergeAuthorityBlocker::IncompleteAuditorEvidence);
                structurally_trusted = false;
            }
            if evidence.head_oid != head_oid
                || evidence.snapshot_observed_at != *snapshot.observed_at()
            {
                blockers.push(PullRequestMergeAuthorityBlocker::StaleAuditorEvidence);
                structurally_trusted = false;
            }
            let mut lenses = evidence.lenses.clone();
            if lenses_are_uncertain(&lenses) {
                blockers.push(PullRequestMergeAuthorityBlocker::UncertainAuditorEvidence);
                for lens in &mut lenses {
                    if lens.lens_id.trim().is_empty()
                        || lens.model_label.trim().is_empty()
                        || lens.framing.trim().is_empty()
                        || lens.information_scope.trim().is_empty()
                    {
                        lens.decision = LensDecision::CannotVerify;
                    }
                }
            }
            (Some(evidence.auditor.clone()), Some(lenses))
        }
        None => {
            blockers.push(PullRequestMergeAuthorityBlocker::MissingAuditorEvidence);
            structurally_trusted = false;
            (None, None)
        }
    };

    let branch_merges_cleanly = match &input.merge_simulation {
        Some(evidence) => {
            if evidence.head_oid != head_oid
                || evidence.base_oid != base_oid
                || evidence.snapshot_observed_at != *snapshot.observed_at()
            {
                blockers.push(PullRequestMergeAuthorityBlocker::StaleMergeSimulationEvidence);
                structurally_trusted = false;
            }
            Some(evidence.merges_cleanly)
        }
        None => {
            blockers.push(PullRequestMergeAuthorityBlocker::MissingMergeSimulationEvidence);
            structurally_trusted = false;
            None
        }
    };

    let completion_mode = match input.completion_mode {
        Some(mode) => Some(mode),
        None => {
            blockers.push(PullRequestMergeAuthorityBlocker::MissingCompletionMode);
            structurally_trusted = false;
            None
        }
    };

    let changed_paths = match &input.changed_paths {
        Some(evidence) => {
            if evidence.paths.is_empty() {
                blockers.push(PullRequestMergeAuthorityBlocker::EmptyChangedPathsEvidence);
                structurally_trusted = false;
            }
            if evidence.head_oid != head_oid {
                blockers.push(PullRequestMergeAuthorityBlocker::StaleChangedPathsEvidence);
                structurally_trusted = false;
            }
            Some(evidence.paths.clone())
        }
        None => {
            blockers.push(PullRequestMergeAuthorityBlocker::MissingChangedPathsEvidence);
            structurally_trusted = false;
            None
        }
    };

    if !structurally_trusted {
        return PullRequestMergeAuthorityDecision::Blocked {
            blockers,
            merge_decision: None,
        };
    }

    let request = MergeRequest {
        requested: true,
        producer: producer.expect("trusted producer evidence is present"),
        reviewer: auditor.expect("trusted auditor evidence is present"),
        lenses: lenses.expect("trusted auditor lenses are present"),
        certified: !verification_checks.is_empty()
            && verification_checks
                .iter()
                .all(|check| check.status == CheckStatus::Passed),
        checks: verification_checks,
        branch_merges_cleanly: branch_merges_cleanly
            .expect("trusted merge-simulation evidence is present"),
        completion_mode: completion_mode.expect("trusted completion mode is present"),
        changed_paths: changed_paths.expect("trusted changed-path evidence is present"),
        decided_at: decided_at.expect("trusted freshness evidence is present"),
    };

    let merge_decision = match decide_merge(&request) {
        Ok(decision) => decision,
        Err(_) => {
            blockers.push(PullRequestMergeAuthorityBlocker::OptimizerDecisionFailed);
            return PullRequestMergeAuthorityDecision::Blocked {
                blockers,
                merge_decision: None,
            };
        }
    };
    blockers.extend(
        merge_decision
            .blockers
            .iter()
            .cloned()
            .map(PullRequestMergeAuthorityBlocker::OptimizerBlocked),
    );

    if blockers.is_empty() && merge_decision.auto_merge_performed {
        PullRequestMergeAuthorityDecision::Allowed { merge_decision }
    } else {
        PullRequestMergeAuthorityDecision::Blocked {
            blockers,
            merge_decision: Some(merge_decision),
        }
    }
}

fn map_required_checks(
    snapshot: &PullRequestReviewSnapshot,
    required_checks: &Option<Vec<String>>,
    blockers: &mut Vec<PullRequestMergeAuthorityBlocker>,
) -> Vec<VerificationCheck> {
    let Some(required_checks) = required_checks else {
        blockers.push(PullRequestMergeAuthorityBlocker::MissingRequiredChecks);
        return Vec::new();
    };
    if required_checks.is_empty() {
        blockers.push(PullRequestMergeAuthorityBlocker::MissingRequiredChecks);
        return Vec::new();
    }

    let mut seen = BTreeSet::new();
    required_checks
        .iter()
        .map(|required| {
            if required.trim().is_empty() || required != required.trim() {
                blockers.push(PullRequestMergeAuthorityBlocker::InvalidRequiredCheckName);
                return VerificationCheck {
                    name: required.clone(),
                    status: CheckStatus::Uncertain,
                };
            }
            if !seen.insert(required.as_str()) {
                blockers.push(PullRequestMergeAuthorityBlocker::DuplicateRequiredCheck {
                    name: required.clone(),
                });
                return VerificationCheck {
                    name: required.clone(),
                    status: CheckStatus::Uncertain,
                };
            }

            let matching: Vec<&ForgeCheck> = snapshot
                .checks()
                .iter()
                .filter(|check| check.name() == required)
                .collect();
            let status = match matching.as_slice() {
                [] => {
                    blockers.push(PullRequestMergeAuthorityBlocker::MissingRequiredCheck {
                        name: required.clone(),
                    });
                    CheckStatus::Missing
                }
                [check] => map_required_check_status(check, blockers),
                _ => {
                    blockers.push(PullRequestMergeAuthorityBlocker::AmbiguousRequiredCheck {
                        name: required.clone(),
                    });
                    CheckStatus::Uncertain
                }
            };
            VerificationCheck {
                name: required.clone(),
                status,
            }
        })
        .collect()
}

fn map_required_check_status(
    check: &ForgeCheck,
    blockers: &mut Vec<PullRequestMergeAuthorityBlocker>,
) -> CheckStatus {
    if check.status() != ForgeCheckStatus::Completed {
        blockers.push(PullRequestMergeAuthorityBlocker::UncertainRequiredCheck {
            name: check.name().to_string(),
        });
        return CheckStatus::Uncertain;
    }
    match check
        .conclusion()
        .expect("completed forge checks always contain a conclusion")
    {
        ForgeCheckConclusion::Success => CheckStatus::Passed,
        ForgeCheckConclusion::Skipped => {
            blockers.push(PullRequestMergeAuthorityBlocker::SkippedRequiredCheck {
                name: check.name().to_string(),
            });
            CheckStatus::Skipped
        }
        ForgeCheckConclusion::Stale => {
            blockers.push(PullRequestMergeAuthorityBlocker::StaleRequiredCheck {
                name: check.name().to_string(),
            });
            CheckStatus::Stale
        }
        conclusion => {
            blockers.push(PullRequestMergeAuthorityBlocker::FailedRequiredCheck {
                name: check.name().to_string(),
                conclusion,
            });
            CheckStatus::Failed
        }
    }
}

fn actor_is_complete(actor: &MergeActor) -> bool {
    [
        actor.agent.stable_id.as_str(),
        actor.session.id.as_str(),
        actor.model_label.as_str(),
    ]
    .into_iter()
    .all(|value| !value.trim().is_empty() && value == value.trim())
}

fn producer_is_complete(producer: &ProducerFingerprint) -> bool {
    actor_is_complete(&producer.actor)
        && !producer.commit_authors.is_empty()
        && !producer.commit_committers.is_empty()
        && producer
            .commit_authors
            .iter()
            .chain(&producer.commit_committers)
            .all(|value| !value.trim().is_empty() && value == value.trim())
}

fn lenses_are_uncertain(lenses: &[LensVerdict]) -> bool {
    let mut ids = BTreeSet::new();
    lenses.iter().any(|lens| {
        lens.lens_id.trim().is_empty()
            || lens.model_label.trim().is_empty()
            || lens.framing.trim().is_empty()
            || lens.information_scope.trim().is_empty()
            || !ids.insert(lens.lens_id.as_str())
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "observation", content = "request", rename_all = "snake_case")]
pub enum ForgeObservationRequest {
    ItemThread(ForgeItem),
    PullRequestReviewSnapshot(ForgeItem),
}

#[derive(Deserialize)]
#[serde(
    deny_unknown_fields,
    tag = "observation",
    content = "request",
    rename_all = "snake_case"
)]
enum ForgeObservationRequestWire {
    ItemThread(ForgeItem),
    PullRequestReviewSnapshot(ForgeItem),
}

impl ForgeObservationRequest {
    pub fn item_thread(item: ForgeItem) -> Result<Self> {
        item.validate()?;
        let value = Self::ItemThread(item);
        validate_serialized(&value, MAX_REQUEST_BYTES, "forge observation request")?;
        Ok(value)
    }

    pub fn pull_request_review_snapshot(item: ForgeItem) -> Result<Self> {
        item.validate()?;
        if item.kind != ForgeItemKind::PullRequest {
            bail!("PR review observation request requires a pull-request item");
        }
        let value = Self::PullRequestReviewSnapshot(item);
        validate_serialized(&value, MAX_REQUEST_BYTES, "forge observation request")?;
        Ok(value)
    }

    pub fn item(&self) -> &ForgeItem {
        match self {
            Self::ItemThread(item) | Self::PullRequestReviewSnapshot(item) => item,
        }
    }

    fn validate(&self) -> Result<()> {
        match self {
            Self::ItemThread(item) => Self::item_thread(item.clone()).map(|_| ()),
            Self::PullRequestReviewSnapshot(item) => {
                Self::pull_request_review_snapshot(item.clone()).map(|_| ())
            }
        }
    }
}

impl<'de> Deserialize<'de> for ForgeObservationRequest {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        match ForgeObservationRequestWire::deserialize(deserializer)? {
            ForgeObservationRequestWire::ItemThread(item) => Self::item_thread(item),
            ForgeObservationRequestWire::PullRequestReviewSnapshot(item) => {
                Self::pull_request_review_snapshot(item)
            }
        }
        .map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "observation", content = "snapshot", rename_all = "snake_case")]
pub enum ForgeObservation {
    ItemThread(ItemThreadObservation),
    PullRequestReviewSnapshot(PullRequestReviewSnapshot),
}

#[derive(Deserialize)]
#[serde(
    deny_unknown_fields,
    tag = "observation",
    content = "snapshot",
    rename_all = "snake_case"
)]
enum ForgeObservationWire {
    ItemThread(ItemThreadObservation),
    PullRequestReviewSnapshot(PullRequestReviewSnapshot),
}

impl ForgeObservation {
    pub fn item(&self) -> &ForgeItem {
        match self {
            Self::ItemThread(observation) => observation.item(),
            Self::PullRequestReviewSnapshot(observation) => observation.item(),
        }
    }

    fn validate_for_request(&self, request: &ForgeObservationRequest) -> Result<()> {
        let matches = match (self, request) {
            (Self::ItemThread(observation), ForgeObservationRequest::ItemThread(item)) => {
                observation.validate()?;
                observation.item == *item
            }
            (
                Self::PullRequestReviewSnapshot(observation),
                ForgeObservationRequest::PullRequestReviewSnapshot(item),
            ) => {
                observation.validate()?;
                observation.item == *item
            }
            _ => false,
        };
        if !matches {
            bail!("forge observation did not match its exact request and revision");
        }
        Ok(())
    }
}

impl<'de> Deserialize<'de> for ForgeObservation {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(match ForgeObservationWire::deserialize(deserializer)? {
            ForgeObservationWire::ItemThread(value) => Self::ItemThread(value),
            ForgeObservationWire::PullRequestReviewSnapshot(value) => {
                Self::PullRequestReviewSnapshot(value)
            }
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AppendCommentEffect {
    effect_id: String,
    item: ForgeItem,
    expected_actor: ForgeActor,
    body: String,
    body_digest: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AppendCommentEffectWire {
    effect_id: String,
    item: ForgeItem,
    expected_actor: ForgeActor,
    body: String,
    body_digest: String,
}

impl AppendCommentEffect {
    pub fn new(
        effect_id: impl Into<String>,
        item: ForgeItem,
        expected_actor: ForgeActor,
        body: impl Into<String>,
    ) -> Result<Self> {
        let body = body.into();
        let value = Self {
            effect_id: effect_id.into(),
            item,
            expected_actor,
            body_digest: sha256_identity(body.as_bytes()),
            body,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn effect_id(&self) -> &str {
        &self.effect_id
    }

    pub fn item(&self) -> &ForgeItem {
        &self.item
    }

    pub fn expected_actor(&self) -> &ForgeActor {
        &self.expected_actor
    }

    pub fn body(&self) -> &str {
        &self.body
    }

    pub fn body_digest(&self) -> &str {
        &self.body_digest
    }

    fn validate(&self) -> Result<()> {
        validate_stable_id(&self.effect_id, "forge effect id")?;
        self.item.validate()?;
        self.expected_actor.validate()?;
        if self.expected_actor.provider_id() != self.item.repository.provider_id() {
            bail!("forge effect actor is not bound to the target provider");
        }
        validate_bounded_text(
            &self.body,
            "forge comment effect body",
            MAX_BODY_BYTES,
            false,
        )?;
        if self.body_digest != sha256_identity(self.body.as_bytes()) {
            bail!("forge comment effect body digest does not match its exact body");
        }
        validate_serialized(self, MAX_REQUEST_BYTES, "forge comment effect request")
    }
}

impl<'de> Deserialize<'de> for AppendCommentEffect {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = AppendCommentEffectWire::deserialize(deserializer)?;
        let value = Self::new(wire.effect_id, wire.item, wire.expected_actor, wire.body)
            .map_err(serde::de::Error::custom)?;
        if value.body_digest != wire.body_digest {
            return Err(serde::de::Error::custom(
                "forge comment effect serialized body digest does not match",
            ));
        }
        Ok(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "effect", content = "request", rename_all = "snake_case")]
pub enum ForgeEffectRequest {
    AppendComment(AppendCommentEffect),
}

#[derive(Deserialize)]
#[serde(
    deny_unknown_fields,
    tag = "effect",
    content = "request",
    rename_all = "snake_case"
)]
enum ForgeEffectRequestWire {
    AppendComment(AppendCommentEffect),
}

impl ForgeEffectRequest {
    pub fn append_comment(effect: AppendCommentEffect) -> Result<Self> {
        effect.validate()?;
        Ok(Self::AppendComment(effect))
    }

    pub fn as_append_comment(&self) -> &AppendCommentEffect {
        match self {
            Self::AppendComment(effect) => effect,
        }
    }

    fn validate(&self) -> Result<()> {
        self.as_append_comment().validate()
    }
}

impl<'de> Deserialize<'de> for ForgeEffectRequest {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        match ForgeEffectRequestWire::deserialize(deserializer)? {
            ForgeEffectRequestWire::AppendComment(effect) => Self::append_comment(effect),
        }
        .map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ForgeMutationReceipt {
    effect_id: String,
    item: ForgeItem,
    body_digest: String,
    actor: ForgeActor,
    provider_comment_id: ProviderObjectId,
    url: String,
    created_at: ForgeTimestamp,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ForgeMutationReceiptWire {
    effect_id: String,
    item: ForgeItem,
    body_digest: String,
    actor: ForgeActor,
    provider_comment_id: ProviderObjectId,
    url: String,
    created_at: ForgeTimestamp,
}

impl ForgeMutationReceipt {
    pub fn new(
        effect_id: impl Into<String>,
        item: ForgeItem,
        body_digest: impl Into<String>,
        actor: ForgeActor,
        provider_comment_id: ProviderObjectId,
        url: impl Into<String>,
        created_at: ForgeTimestamp,
    ) -> Result<Self> {
        let value = Self {
            effect_id: effect_id.into(),
            item,
            body_digest: body_digest.into(),
            actor,
            provider_comment_id,
            url: url.into(),
            created_at,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn effect_id(&self) -> &str {
        &self.effect_id
    }

    pub fn repository(&self) -> &ForgeRepository {
        self.item.repository()
    }

    pub fn item(&self) -> &ForgeItem {
        &self.item
    }

    pub fn item_kind(&self) -> ForgeItemKind {
        self.item.kind()
    }

    pub fn item_number(&self) -> u64 {
        self.item.number()
    }

    pub fn provider_item_id(&self) -> &ProviderObjectId {
        self.item.provider_item_id()
    }

    pub fn revision(&self) -> &str {
        self.item.revision()
    }

    pub fn head_oid(&self) -> Option<&str> {
        self.item.head_oid()
    }

    pub fn base_oid(&self) -> Option<&str> {
        self.item.base_oid()
    }

    pub fn body_digest(&self) -> &str {
        &self.body_digest
    }

    pub fn actor(&self) -> &ForgeActor {
        &self.actor
    }

    pub fn provider_comment_id(&self) -> &ProviderObjectId {
        &self.provider_comment_id
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    pub fn created_at(&self) -> &ForgeTimestamp {
        &self.created_at
    }

    fn validate(&self) -> Result<()> {
        validate_stable_id(&self.effect_id, "forge receipt effect id")?;
        self.item.validate()?;
        validate_sha256_identity(&self.body_digest, "receipt body digest")?;
        self.actor.validate()?;
        if self.actor.provider_id() != self.item.repository().provider_id() {
            bail!("forge receipt actor is not bound to the repository provider");
        }
        require_object_id(
            &self.provider_comment_id,
            self.item.repository().provider_id(),
            ProviderObjectKind::Comment,
            "receipt comment provider id",
        )?;
        validate_https_url(&self.url)?;
        validate_serialized(self, MAX_REQUEST_BYTES, "forge mutation receipt")
    }

    fn validate_for_request(&self, request: &ForgeEffectRequest) -> Result<()> {
        self.validate()?;
        let effect = request.as_append_comment();
        if self.effect_id != effect.effect_id
            || self.item != effect.item
            || self.body_digest != effect.body_digest
            || self.actor != effect.expected_actor
        {
            bail!("forge mutation receipt does not bind the exact effect request");
        }
        Ok(())
    }
}

impl<'de> Deserialize<'de> for ForgeMutationReceipt {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = ForgeMutationReceiptWire::deserialize(deserializer)?;
        Self::new(
            wire.effect_id,
            wire.item,
            wire.body_digest,
            wire.actor,
            wire.provider_comment_id,
            wire.url,
            wire.created_at,
        )
        .map_err(serde::de::Error::custom)
    }
}

/// Exact compare-and-swap merge request created only after merge authority has
/// been recomputed from a current forge observation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct PullRequestMergeEffect {
    effect_id: String,
    item: ForgeItem,
    approved_actor: ForgeActor,
    evidence_digest: String,
    ground_truth_digest: String,
    completion_mode: CompletionMode,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PullRequestMergeEffectWire {
    effect_id: String,
    item: ForgeItem,
    approved_actor: ForgeActor,
    evidence_digest: String,
    ground_truth_digest: String,
    completion_mode: CompletionMode,
}

impl PullRequestMergeEffect {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        effect_id: impl Into<String>,
        item: ForgeItem,
        approved_actor: ForgeActor,
        evidence_digest: impl Into<String>,
        ground_truth_digest: impl Into<String>,
        completion_mode: CompletionMode,
    ) -> Result<Self> {
        let effect = Self {
            effect_id: effect_id.into(),
            item,
            approved_actor,
            evidence_digest: evidence_digest.into(),
            ground_truth_digest: ground_truth_digest.into(),
            completion_mode,
        };
        effect.validate()?;
        Ok(effect)
    }

    pub(crate) fn effect_id(&self) -> &str {
        &self.effect_id
    }

    pub(crate) fn item(&self) -> &ForgeItem {
        &self.item
    }

    pub(crate) fn approved_actor(&self) -> &ForgeActor {
        &self.approved_actor
    }

    pub(crate) fn evidence_digest(&self) -> &str {
        &self.evidence_digest
    }

    pub(crate) fn ground_truth_digest(&self) -> &str {
        &self.ground_truth_digest
    }

    pub(crate) fn completion_mode(&self) -> CompletionMode {
        self.completion_mode
    }

    pub(crate) fn validate(&self) -> Result<()> {
        validate_stable_id(&self.effect_id, "forge merge effect id")?;
        self.item.validate()?;
        if self.item.kind() != ForgeItemKind::PullRequest {
            bail!("forge merge effect requires a pull-request item");
        }
        self.approved_actor.validate()?;
        if self.approved_actor.provider_id() != self.item.repository().provider_id() {
            bail!("forge merge approval actor is not bound to the target provider");
        }
        validate_sha256_identity(&self.evidence_digest, "merge evidence digest")?;
        validate_sha256_identity(&self.ground_truth_digest, "merge ground-truth digest")?;
        if self.completion_mode.history_flattening() {
            bail!("forge merge effect refuses a history-flattening completion mode");
        }
        validate_serialized(self, MAX_REQUEST_BYTES, "forge pull-request merge effect")
    }
}

impl<'de> Deserialize<'de> for PullRequestMergeEffect {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = PullRequestMergeEffectWire::deserialize(deserializer)?;
        Self::new(
            wire.effect_id,
            wire.item,
            wire.approved_actor,
            wire.evidence_digest,
            wire.ground_truth_digest,
            wire.completion_mode,
        )
        .map_err(serde::de::Error::custom)
    }
}

/// Provider-authenticated merge receipt. The authenticated effect WAL stores
/// this exact value before declaring the operation complete.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct PullRequestMergeReceipt {
    effect_id: String,
    item: ForgeItem,
    approved_actor: ForgeActor,
    evidence_digest: String,
    ground_truth_digest: String,
    completion_mode: CompletionMode,
    provider_merge_id: ProviderObjectId,
    merged_oid: String,
    url: String,
    merged_at: ForgeTimestamp,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PullRequestMergeReceiptWire {
    effect_id: String,
    item: ForgeItem,
    approved_actor: ForgeActor,
    evidence_digest: String,
    ground_truth_digest: String,
    completion_mode: CompletionMode,
    provider_merge_id: ProviderObjectId,
    merged_oid: String,
    url: String,
    merged_at: ForgeTimestamp,
}

impl PullRequestMergeReceipt {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        effect_id: impl Into<String>,
        item: ForgeItem,
        approved_actor: ForgeActor,
        evidence_digest: impl Into<String>,
        ground_truth_digest: impl Into<String>,
        completion_mode: CompletionMode,
        provider_merge_id: ProviderObjectId,
        merged_oid: impl Into<String>,
        url: impl Into<String>,
        merged_at: ForgeTimestamp,
    ) -> Result<Self> {
        let receipt = Self {
            effect_id: effect_id.into(),
            item,
            approved_actor,
            evidence_digest: evidence_digest.into(),
            ground_truth_digest: ground_truth_digest.into(),
            completion_mode,
            provider_merge_id,
            merged_oid: merged_oid.into(),
            url: url.into(),
            merged_at,
        };
        receipt.validate()?;
        Ok(receipt)
    }

    #[cfg(test)]
    pub(crate) fn item(&self) -> &ForgeItem {
        &self.item
    }

    #[cfg(test)]
    pub(crate) fn approved_actor(&self) -> &ForgeActor {
        &self.approved_actor
    }

    #[cfg(test)]
    pub(crate) fn evidence_digest(&self) -> &str {
        &self.evidence_digest
    }

    #[cfg(test)]
    pub(crate) fn ground_truth_digest(&self) -> &str {
        &self.ground_truth_digest
    }

    #[cfg(test)]
    pub(crate) fn completion_mode(&self) -> CompletionMode {
        self.completion_mode
    }

    pub(crate) fn provider_merge_id(&self) -> &ProviderObjectId {
        &self.provider_merge_id
    }

    pub(crate) fn merged_oid(&self) -> &str {
        &self.merged_oid
    }

    pub(crate) fn url(&self) -> &str {
        &self.url
    }

    pub(crate) fn merged_at(&self) -> &ForgeTimestamp {
        &self.merged_at
    }

    fn validate(&self) -> Result<()> {
        validate_stable_id(&self.effect_id, "forge merge receipt effect id")?;
        self.item.validate()?;
        if self.item.kind() != ForgeItemKind::PullRequest {
            bail!("forge merge receipt requires a pull-request item");
        }
        self.approved_actor.validate()?;
        if self.approved_actor.provider_id() != self.item.repository().provider_id() {
            bail!("forge merge receipt approval actor is not bound to the target provider");
        }
        validate_sha256_identity(&self.evidence_digest, "merge receipt evidence digest")?;
        validate_sha256_identity(
            &self.ground_truth_digest,
            "merge receipt ground-truth digest",
        )?;
        if self.completion_mode.history_flattening() {
            bail!("forge merge receipt records a prohibited completion mode");
        }
        require_object_id(
            &self.provider_merge_id,
            self.item.repository().provider_id(),
            ProviderObjectKind::Merge,
            "merge receipt provider id",
        )?;
        validate_git_oid(&self.merged_oid, "merged commit OID")?;
        validate_https_url(&self.url)?;
        validate_serialized(self, MAX_REQUEST_BYTES, "forge pull-request merge receipt")
    }

    pub(crate) fn validate_for_effect(&self, effect: &PullRequestMergeEffect) -> Result<()> {
        self.validate()?;
        effect.validate()?;
        if self.effect_id != effect.effect_id
            || self.item != effect.item
            || self.approved_actor != effect.approved_actor
            || self.evidence_digest != effect.evidence_digest
            || self.ground_truth_digest != effect.ground_truth_digest
            || self.completion_mode != effect.completion_mode
        {
            bail!("forge merge receipt does not bind the exact authorized effect");
        }
        Ok(())
    }
}

impl<'de> Deserialize<'de> for PullRequestMergeReceipt {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = PullRequestMergeReceiptWire::deserialize(deserializer)?;
        Self::new(
            wire.effect_id,
            wire.item,
            wire.approved_actor,
            wire.evidence_digest,
            wire.ground_truth_digest,
            wire.completion_mode,
            wire.provider_merge_id,
            wire.merged_oid,
            wire.url,
            wire.merged_at,
        )
        .map_err(serde::de::Error::custom)
    }
}

/// Separate, crate-private mutation boundary for authenticated pull-request
/// merges. Keeping this out of the public comment transport prevents ordinary
/// requester-controlled forge calls from acquiring merge authority.
pub(crate) trait PullRequestMergeTransport {
    fn observe_pull_request_for_merge(
        &self,
        candidate: &ForgeItem,
    ) -> Result<PullRequestReviewSnapshot>;

    fn lookup_pull_request_merge(
        &self,
        effect: &PullRequestMergeEffect,
    ) -> Result<Vec<PullRequestMergeReceipt>>;

    fn execute_pull_request_merge(
        &self,
        effect: &PullRequestMergeEffect,
    ) -> Result<PullRequestMergeReceipt>;

    fn verify_pull_request_merge(
        &self,
        effect: &PullRequestMergeEffect,
        receipt: &PullRequestMergeReceipt,
    ) -> Result<PullRequestMergeReceipt>;
}

/// Object-safe provider-neutral boundary. It contains no trust or reducer policy.
pub trait ForgeTransport {
    fn observe(&self, request: &ForgeObservationRequest) -> Result<ForgeObservation>;
    fn execute(&self, request: &ForgeEffectRequest) -> Result<ForgeMutationReceipt>;
}

#[derive(Debug, Clone)]
struct FakeEffectRecord {
    request_digest: String,
    receipt: ForgeMutationReceipt,
}

#[cfg(test)]
#[derive(Debug, Clone)]
struct FakeMergeRecord {
    effect_digest: String,
    receipt: PullRequestMergeReceipt,
}

#[derive(Debug, Default)]
pub struct FakeForgeTransport {
    observations: BTreeMap<String, ForgeObservation>,
    effects: Mutex<BTreeMap<String, FakeEffectRecord>>,
    #[cfg(test)]
    merge_observations: BTreeMap<String, PullRequestReviewSnapshot>,
    #[cfg(test)]
    merges: Mutex<BTreeMap<String, FakeMergeRecord>>,
}

impl FakeForgeTransport {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register_observation(
        &mut self,
        request: ForgeObservationRequest,
        observation: ForgeObservation,
    ) -> Result<()> {
        request.validate()?;
        observation.validate_for_request(&request)?;
        let key = request_digest(&request)?;
        match self.observations.entry(key) {
            Entry::Vacant(entry) => {
                entry.insert(observation);
                Ok(())
            }
            Entry::Occupied(_) => {
                bail!("fake forge observation request was registered more than once")
            }
        }
    }

    /// Register the current provider state for one stable pull request. The
    /// candidate may carry an older head so stale-head behavior can be tested
    /// without weakening exact observation validation elsewhere.
    #[cfg(test)]
    pub(crate) fn register_pull_request_merge_observation(
        &mut self,
        candidate: &ForgeItem,
        snapshot: PullRequestReviewSnapshot,
    ) -> Result<()> {
        candidate.validate()?;
        snapshot.validate()?;
        if candidate.kind() != ForgeItemKind::PullRequest
            || !same_pull_request_identity(candidate, snapshot.item())
        {
            bail!("fake merge observation does not match the stable pull-request identity");
        }
        let key = pull_request_identity_digest(candidate)?;
        match self.merge_observations.entry(key) {
            Entry::Vacant(entry) => {
                entry.insert(snapshot);
                Ok(())
            }
            Entry::Occupied(_) => {
                bail!("fake forge merge observation was registered more than once")
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn pull_request_merge_count(&self) -> Result<usize> {
        Ok(self
            .merges
            .lock()
            .map_err(|_| anyhow::anyhow!("fake forge merge ledger lock was poisoned"))?
            .len())
    }
}

impl ForgeTransport for FakeForgeTransport {
    fn observe(&self, request: &ForgeObservationRequest) -> Result<ForgeObservation> {
        request.validate()?;
        let observation = self
            .observations
            .get(&request_digest(request)?)
            .context("fake forge has no exact observation for the request")?
            .clone();
        observation.validate_for_request(request)?;
        Ok(observation)
    }

    fn execute(&self, request: &ForgeEffectRequest) -> Result<ForgeMutationReceipt> {
        request.validate()?;
        let effect = request.as_append_comment();
        let request_digest = effect_request_digest(request)?;
        let mut effects = self
            .effects
            .lock()
            .map_err(|_| anyhow::anyhow!("fake forge effect ledger lock was poisoned"))?;
        if let Some(record) = effects.get(effect.effect_id()) {
            if record.request_digest != request_digest {
                bail!("fake forge effect id was reused with a different payload");
            }
            record.receipt.validate_for_request(request)?;
            return Ok(record.receipt.clone());
        }
        let comment_digest = crate::artifacts::state_auth::sha256_hex(
            format!("forge-fake-comment-v1\0{request_digest}").as_bytes(),
        );
        let provider_comment_id = ProviderObjectId::new(
            effect.item.repository.provider_id(),
            ProviderObjectKind::Comment,
            format!("comment:{comment_digest}"),
        )?;
        let item_segment = match effect.item.kind {
            ForgeItemKind::Issue => "issues",
            ForgeItemKind::PullRequest => "pull",
        };
        let url = format!(
            "https://{}/{}/{}/comments/{}",
            effect.item.repository.canonical_locator,
            item_segment,
            effect.item.number,
            provider_comment_id.stable_id()
        );
        let receipt = ForgeMutationReceipt::new(
            effect.effect_id.clone(),
            effect.item.clone(),
            effect.body_digest.clone(),
            effect.expected_actor.clone(),
            provider_comment_id,
            url,
            ForgeTimestamp::new("2000-01-01T00:00:00Z")?,
        )?;
        receipt.validate_for_request(request)?;
        effects.insert(
            effect.effect_id.clone(),
            FakeEffectRecord {
                request_digest,
                receipt: receipt.clone(),
            },
        );
        Ok(receipt)
    }
}

#[cfg(test)]
impl PullRequestMergeTransport for FakeForgeTransport {
    fn observe_pull_request_for_merge(
        &self,
        candidate: &ForgeItem,
    ) -> Result<PullRequestReviewSnapshot> {
        candidate.validate()?;
        if candidate.kind() != ForgeItemKind::PullRequest {
            bail!("fake forge merge observation requires a pull-request candidate");
        }
        let snapshot = self
            .merge_observations
            .get(&pull_request_identity_digest(candidate)?)
            .context("fake forge has no current merge observation for the pull request")?
            .clone();
        snapshot.validate()?;
        if !same_pull_request_identity(candidate, snapshot.item()) {
            bail!("fake forge returned a different pull-request identity");
        }
        Ok(snapshot)
    }

    fn lookup_pull_request_merge(
        &self,
        effect: &PullRequestMergeEffect,
    ) -> Result<Vec<PullRequestMergeReceipt>> {
        effect.validate()?;
        let digest = pull_request_merge_effect_digest(effect)?;
        let merges = self
            .merges
            .lock()
            .map_err(|_| anyhow::anyhow!("fake forge merge ledger lock was poisoned"))?;
        let Some(record) = merges.get(effect.effect_id()) else {
            return Ok(Vec::new());
        };
        if record.effect_digest != digest {
            bail!("fake forge merge effect id was reused with different authority");
        }
        record.receipt.validate_for_effect(effect)?;
        Ok(vec![record.receipt.clone()])
    }

    fn execute_pull_request_merge(
        &self,
        effect: &PullRequestMergeEffect,
    ) -> Result<PullRequestMergeReceipt> {
        effect.validate()?;
        let current = self
            .merge_observations
            .get(&pull_request_identity_digest(effect.item())?)
            .context("fake forge lost the current pull-request state before merge")?;
        if current.item() != effect.item() {
            bail!("fake forge pull-request head changed before the compare-and-swap merge");
        }

        let effect_digest = pull_request_merge_effect_digest(effect)?;
        let mut merges = self
            .merges
            .lock()
            .map_err(|_| anyhow::anyhow!("fake forge merge ledger lock was poisoned"))?;
        if let Some(record) = merges.get(effect.effect_id()) {
            if record.effect_digest != effect_digest {
                bail!("fake forge merge effect id was reused with different authority");
            }
            record.receipt.validate_for_effect(effect)?;
            return Ok(record.receipt.clone());
        }

        let raw_digest = crate::artifacts::state_auth::sha256_hex(
            format!("forge-fake-merge-v1\0{effect_digest}").as_bytes(),
        );
        let head_width = effect
            .item()
            .head_oid()
            .expect("validated merge effects contain a head OID")
            .len();
        let merged_oid = raw_digest[..head_width].to_string();
        let provider_merge_id = ProviderObjectId::new(
            effect.item().repository().provider_id(),
            ProviderObjectKind::Merge,
            format!("merge:{raw_digest}"),
        )?;
        let url = format!(
            "https://{}/pull/{}/merge/{}",
            effect.item().repository().canonical_locator(),
            effect.item().number(),
            provider_merge_id.stable_id()
        );
        let receipt = PullRequestMergeReceipt::new(
            effect.effect_id().to_string(),
            effect.item().clone(),
            effect.approved_actor().clone(),
            effect.evidence_digest().to_string(),
            effect.ground_truth_digest().to_string(),
            effect.completion_mode(),
            provider_merge_id,
            merged_oid,
            url,
            ForgeTimestamp::new("2000-01-01T00:00:00Z")?,
        )?;
        receipt.validate_for_effect(effect)?;
        merges.insert(
            effect.effect_id().to_string(),
            FakeMergeRecord {
                effect_digest,
                receipt: receipt.clone(),
            },
        );
        Ok(receipt)
    }

    fn verify_pull_request_merge(
        &self,
        effect: &PullRequestMergeEffect,
        receipt: &PullRequestMergeReceipt,
    ) -> Result<PullRequestMergeReceipt> {
        effect.validate()?;
        receipt.validate_for_effect(effect)?;
        let matches = self.lookup_pull_request_merge(effect)?;
        if matches.as_slice() != [receipt.clone()] {
            bail!("fake forge merge receipt was missing, duplicated, or changed");
        }
        Ok(receipt.clone())
    }
}

fn validate_actor_identity<'a>(actors: impl Iterator<Item = &'a ForgeActor>) -> Result<()> {
    let mut by_id = BTreeMap::<ProviderObjectId, ForgeActor>::new();
    let mut by_handle = BTreeMap::<(String, String), ProviderObjectId>::new();
    for actor in actors {
        actor.validate()?;
        if let Some(existing) = by_id.insert(actor.provider_actor_id.clone(), actor.clone()) {
            if existing != *actor {
                bail!("forge actors conflict for one stable provider actor id");
            }
        }
        let handle = (actor.provider_id.clone(), actor.canonical_handle.clone());
        if let Some(existing) = by_handle.insert(handle, actor.provider_actor_id.clone()) {
            if existing != actor.provider_actor_id {
                bail!("forge actor handle is ambiguous across stable provider ids");
            }
        }
    }
    Ok(())
}

fn validate_https_url(value: &str) -> Result<()> {
    if value.len() > MAX_URL_BYTES
        || !value.starts_with("https://")
        || value.len() == "https://".len()
        || value.contains(['\\', '@'])
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        bail!("forge URL is not a bounded canonical HTTPS URL");
    }
    Ok(())
}

fn sha256_identity(bytes: &[u8]) -> String {
    format!("sha256:{}", crate::artifacts::state_auth::sha256_hex(bytes))
}

fn validate_sha256_identity(value: &str, label: &str) -> Result<()> {
    let digest = value
        .strip_prefix("sha256:")
        .context(format!("{label} omitted its sha256 prefix"))?;
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("{label} must contain exactly 64 lowercase hexadecimal characters");
    }
    Ok(())
}

fn request_digest(request: &ForgeObservationRequest) -> Result<String> {
    let encoded =
        serde_json::to_vec(request).context("failed to bind forge observation request")?;
    Ok(sha256_identity(
        [b"forge-observation-request-v1\0".as_slice(), &encoded]
            .concat()
            .as_slice(),
    ))
}

fn effect_request_digest(request: &ForgeEffectRequest) -> Result<String> {
    let encoded = serde_json::to_vec(request).context("failed to bind forge effect request")?;
    Ok(sha256_identity(
        [b"forge-effect-request-v1\0".as_slice(), &encoded]
            .concat()
            .as_slice(),
    ))
}

#[cfg(test)]
fn same_pull_request_identity(left: &ForgeItem, right: &ForgeItem) -> bool {
    left.kind() == ForgeItemKind::PullRequest
        && right.kind() == ForgeItemKind::PullRequest
        && left.repository() == right.repository()
        && left.number() == right.number()
        && left.provider_item_id() == right.provider_item_id()
}

#[cfg(test)]
fn pull_request_identity_digest(item: &ForgeItem) -> Result<String> {
    item.validate()?;
    if item.kind() != ForgeItemKind::PullRequest {
        bail!("pull-request identity digest requires a pull-request item");
    }
    let encoded = serde_json::to_vec(&(
        "forge-pull-request-identity-v1",
        item.repository(),
        item.number(),
        item.provider_item_id(),
    ))
    .context("failed to bind stable pull-request identity")?;
    Ok(sha256_identity(&encoded))
}

#[cfg(test)]
fn pull_request_merge_effect_digest(effect: &PullRequestMergeEffect) -> Result<String> {
    effect.validate()?;
    let encoded = serde_json::to_vec(effect).context("failed to bind forge merge effect")?;
    Ok(sha256_identity(
        [b"forge-pull-request-merge-effect-v1\0".as_slice(), &encoded]
            .concat()
            .as_slice(),
    ))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GithubRunnerRequest {
    ObserveItemThread(ForgeObservationRequest),
    ObservePullRequestReviewSnapshot(ForgeObservationRequest),
    AppendComment(ForgeEffectRequest),
}

impl GithubRunnerRequest {
    pub fn observation(&self) -> Option<&ForgeObservationRequest> {
        match self {
            Self::ObserveItemThread(request) | Self::ObservePullRequestReviewSnapshot(request) => {
                Some(request)
            }
            Self::AppendComment(_) => None,
        }
    }

    pub fn effect(&self) -> Option<&ForgeEffectRequest> {
        match self {
            Self::AppendComment(request) => Some(request),
            Self::ObserveItemThread(_) | Self::ObservePullRequestReviewSnapshot(_) => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GithubRunnerResponseKind {
    ItemThread,
    PullRequestReviewSnapshot,
    AppendCommentReceipts,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GithubRunnerResponse {
    kind: GithubRunnerResponseKind,
    json: String,
}

impl GithubRunnerResponse {
    pub fn item_thread_json(json: impl Into<String>) -> Result<Self> {
        Self::new(GithubRunnerResponseKind::ItemThread, json.into())
    }

    pub fn pull_request_review_snapshot_json(json: impl Into<String>) -> Result<Self> {
        Self::new(
            GithubRunnerResponseKind::PullRequestReviewSnapshot,
            json.into(),
        )
    }

    pub fn append_comment_receipts_json(json: impl Into<String>) -> Result<Self> {
        Self::new(GithubRunnerResponseKind::AppendCommentReceipts, json.into())
    }

    fn new(kind: GithubRunnerResponseKind, json: String) -> Result<Self> {
        if json.len() > MAX_RESPONSE_BYTES || json.as_bytes().contains(&0) {
            bail!("GitHub runner response is malformed or exceeds its byte limit");
        }
        Ok(Self { kind, json })
    }

    fn require(self, expected: GithubRunnerResponseKind) -> Result<String> {
        if self.kind != expected {
            bail!("GitHub runner returned a response for a different finite operation");
        }
        Ok(self.json)
    }
}

/// Finite GitHub execution hook. Requests never contain executables, argv,
/// endpoint strings, REST paths, or GraphQL documents.
pub trait GithubRunner {
    fn run(&self, request: &GithubRunnerRequest) -> Result<GithubRunnerResponse>;
}

/// Production wiring remains fail-closed until the existing private gh
/// boundary exposes matching finite review/thread operations.
#[derive(Debug, Default, Clone, Copy)]
pub struct GithubProductionRunner;

impl GithubProductionRunner {
    pub fn new() -> Self {
        Self
    }
}

impl GithubRunner for GithubProductionRunner {
    fn run(&self, _request: &GithubRunnerRequest) -> Result<GithubRunnerResponse> {
        bail!(
            "production GitHub forge transport is fail-closed: no finite GhCommandContext review/thread hook is registered"
        )
    }
}

#[derive(Debug)]
pub struct GithubForge<R: GithubRunner> {
    runner: R,
}

impl<R: GithubRunner> GithubForge<R> {
    pub fn new(runner: R) -> Self {
        Self { runner }
    }

    pub fn into_runner(self) -> R {
        self.runner
    }
}

impl<R: GithubRunner> ForgeTransport for GithubForge<R> {
    fn observe(&self, request: &ForgeObservationRequest) -> Result<ForgeObservation> {
        request.validate()?;
        require_github_item(request.item())?;
        match request {
            ForgeObservationRequest::ItemThread(_) => {
                let response = self
                    .runner
                    .run(&GithubRunnerRequest::ObserveItemThread(request.clone()))?
                    .require(GithubRunnerResponseKind::ItemThread)?;
                let wire: GithubItemThreadWire =
                    parse_bounded_json(&response, "GitHub item-thread response")?;
                let observation = ForgeObservation::ItemThread(github_item_thread_observation(
                    wire,
                    request.item(),
                )?);
                observation.validate_for_request(request)?;
                Ok(observation)
            }
            ForgeObservationRequest::PullRequestReviewSnapshot(_) => {
                let response = self
                    .runner
                    .run(&GithubRunnerRequest::ObservePullRequestReviewSnapshot(
                        request.clone(),
                    ))?
                    .require(GithubRunnerResponseKind::PullRequestReviewSnapshot)?;
                let wire: GithubPrReviewSnapshotWire =
                    parse_bounded_json(&response, "GitHub PR-review response")?;
                let observation = ForgeObservation::PullRequestReviewSnapshot(
                    github_pr_review_snapshot(wire, request.item())?,
                );
                observation.validate_for_request(request)?;
                Ok(observation)
            }
        }
    }

    fn execute(&self, request: &ForgeEffectRequest) -> Result<ForgeMutationReceipt> {
        request.validate()?;
        require_github_item(request.as_append_comment().item())?;
        let response = self
            .runner
            .run(&GithubRunnerRequest::AppendComment(request.clone()))?
            .require(GithubRunnerResponseKind::AppendCommentReceipts)?;
        let wire: GithubAppendCommentReceiptsWire =
            parse_bounded_json(&response, "GitHub append-comment response")?;
        github_comment_receipt(wire, request)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct GithubRepositoryWire {
    id: String,
    name_with_owner: String,
    url: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum GithubItemKindWire {
    Issue,
    PullRequest,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct GithubItemWire {
    id: String,
    number: u64,
    kind: GithubItemKindWire,
    revision_id: String,
    url: String,
    #[serde(deserialize_with = "required_nullable")]
    head_oid: Option<String>,
    #[serde(deserialize_with = "required_nullable")]
    base_oid: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct GithubActorWire {
    id: String,
    login: String,
    #[serde(rename = "type")]
    kind: GithubActorKindWire,
}

#[derive(Debug, Clone, Copy, Deserialize)]
enum GithubActorKindWire {
    User,
    Bot,
    Organization,
    Mannequin,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct GithubCommentWire {
    id: String,
    database_id: u64,
    url: String,
    body: String,
    created_at: ForgeTimestamp,
    author: GithubActorWire,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct GithubPageInfoWire {
    has_next_page: bool,
    #[serde(deserialize_with = "required_nullable")]
    end_cursor: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct GithubItemThreadWire {
    repository: GithubRepositoryWire,
    item: GithubItemWire,
    observed_at: ForgeTimestamp,
    comments: Vec<GithubCommentWire>,
    page_info: GithubPageInfoWire,
    truncated: bool,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum GithubReviewStateWire {
    Approved,
    ChangesRequested,
    Commented,
    Dismissed,
    Pending,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct GithubReviewWire {
    id: String,
    author: GithubActorWire,
    state: GithubReviewStateWire,
    body: String,
    submitted_at: ForgeTimestamp,
    commit_oid: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct GithubReviewThreadWire {
    id: String,
    is_resolved: bool,
    comments: Vec<GithubCommentWire>,
    page_info: GithubPageInfoWire,
    truncated: bool,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum GithubCheckStatusWire {
    Queued,
    InProgress,
    Completed,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum GithubCheckConclusionWire {
    Success,
    Failure,
    Neutral,
    Cancelled,
    Skipped,
    TimedOut,
    ActionRequired,
    StartupFailure,
    Stale,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct GithubCheckWire {
    id: String,
    actor: GithubActorWire,
    name: String,
    status: GithubCheckStatusWire,
    #[serde(deserialize_with = "required_nullable")]
    conclusion: Option<GithubCheckConclusionWire>,
    head_oid: String,
    updated_at: ForgeTimestamp,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct GithubPrReviewSnapshotWire {
    repository: GithubRepositoryWire,
    item: GithubItemWire,
    observed_at: ForgeTimestamp,
    reviews: Vec<GithubReviewWire>,
    reviews_page_info: GithubPageInfoWire,
    review_threads: Vec<GithubReviewThreadWire>,
    review_threads_page_info: GithubPageInfoWire,
    checks: Vec<GithubCheckWire>,
    checks_page_info: GithubPageInfoWire,
    truncated: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct GithubAppendCommentWire {
    effect_id: String,
    repository: GithubRepositoryWire,
    item: GithubItemWire,
    revision_id: String,
    body_digest: String,
    comment: GithubCommentWire,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct GithubAppendCommentReceiptsWire {
    receipts: Vec<GithubAppendCommentWire>,
    page_info: GithubPageInfoWire,
    truncated: bool,
}

fn require_github_item(item: &ForgeItem) -> Result<()> {
    item.validate()?;
    if item.repository.provider_id() != "github" {
        bail!("GitHub forge requires an item bound to provider id 'github'");
    }
    let components = item.repository.canonical_locator().split('/').count();
    if components != 3 {
        bail!("GitHub repository locator must use canonical host/owner/name form");
    }
    Ok(())
}

fn require_complete_page(page: &GithubPageInfoWire, truncated: bool, label: &str) -> Result<()> {
    if truncated || page.has_next_page || page.end_cursor.is_some() {
        bail!("{label} is truncated or has incomplete pagination");
    }
    Ok(())
}

fn validate_github_repository_wire(
    wire: &GithubRepositoryWire,
    expected: &ForgeRepository,
) -> Result<()> {
    require_object_id(
        expected.provider_repository_id(),
        "github",
        ProviderObjectKind::Repository,
        "GitHub repository id",
    )?;
    if wire.id != expected.provider_repository_id().stable_id()
        || wire.name_with_owner
            != expected
                .canonical_locator()
                .split_once('/')
                .map(|(_, name)| name)
                .unwrap_or_default()
        || wire.url != format!("https://{}", expected.canonical_locator())
    {
        bail!("GitHub response repository does not match its exact bound repository");
    }
    validate_https_url(&wire.url)
}

fn validate_github_item_wire(wire: &GithubItemWire, expected: &ForgeItem) -> Result<()> {
    let kind = match wire.kind {
        GithubItemKindWire::Issue => ForgeItemKind::Issue,
        GithubItemKindWire::PullRequest => ForgeItemKind::PullRequest,
    };
    if wire.id != expected.provider_item_id().stable_id()
        || wire.number != expected.number()
        || kind != expected.kind()
        || wire.revision_id != expected.revision()
        || wire.head_oid.as_deref() != expected.head_oid()
        || wire.base_oid.as_deref() != expected.base_oid()
    {
        bail!("GitHub response item does not match its exact provider item and revision");
    }
    let item_segment = match expected.kind() {
        ForgeItemKind::Issue => "issues",
        ForgeItemKind::PullRequest => "pull",
    };
    let expected_url = format!(
        "https://{}/{}/{}",
        expected.repository().canonical_locator(),
        item_segment,
        expected.number()
    );
    if wire.url != expected_url {
        bail!("GitHub response item URL does not match the exact repository and number");
    }
    Ok(())
}

fn github_actor(wire: GithubActorWire) -> Result<ForgeActor> {
    let kind = match wire.kind {
        GithubActorKindWire::User => ReportedActorKind::Human,
        GithubActorKindWire::Bot => ReportedActorKind::Bot,
        GithubActorKindWire::Organization => ReportedActorKind::Organization,
        GithubActorKindWire::Mannequin => ReportedActorKind::Unknown,
    };
    ForgeActor::new(
        "github",
        ProviderObjectId::new("github", ProviderObjectKind::Actor, wire.id)?,
        wire.login,
        kind,
    )
}

fn github_comment(
    wire: GithubCommentWire,
    item: &ForgeItem,
    mutation: bool,
) -> Result<ForgeComment> {
    if wire.database_id == 0 {
        bail!("GitHub comment omitted a positive database id");
    }
    let issue_fragment = format!("#issuecomment-{}", wire.database_id);
    let review_fragment = format!("#discussion_r{}", wire.database_id);
    let base = format!(
        "https://{}{}{}",
        item.repository().canonical_locator(),
        match item.kind() {
            ForgeItemKind::Issue => "/issues/",
            ForgeItemKind::PullRequest => "/pull/",
        },
        item.number()
    );
    let exact_issue = format!("{base}{issue_fragment}");
    let exact_review = format!("{base}{review_fragment}");
    if wire.url != exact_issue && (mutation || wire.url != exact_review) {
        bail!("GitHub comment URL is not bound to its repository, item, and database id");
    }
    ForgeComment::new(
        ProviderObjectId::new("github", ProviderObjectKind::Comment, wire.id)?,
        github_actor(wire.author)?,
        wire.body,
        wire.url,
        wire.created_at,
    )
}

fn github_item_thread_observation(
    wire: GithubItemThreadWire,
    item: &ForgeItem,
) -> Result<ItemThreadObservation> {
    require_complete_page(&wire.page_info, wire.truncated, "GitHub item comments")?;
    if wire.comments.len() > MAX_COMMENTS {
        bail!("GitHub item comments exceed their count limit");
    }
    validate_github_repository_wire(&wire.repository, item.repository())?;
    validate_github_item_wire(&wire.item, item)?;
    let comments = wire
        .comments
        .into_iter()
        .map(|comment| github_comment(comment, item, false))
        .collect::<Result<Vec<_>>>()?;
    ItemThreadObservation::new(item.clone(), wire.observed_at, comments)
}

fn github_pr_review_snapshot(
    wire: GithubPrReviewSnapshotWire,
    item: &ForgeItem,
) -> Result<PullRequestReviewSnapshot> {
    require_complete_page(&wire.reviews_page_info, wire.truncated, "GitHub reviews")?;
    require_complete_page(
        &wire.review_threads_page_info,
        wire.truncated,
        "GitHub review threads",
    )?;
    require_complete_page(&wire.checks_page_info, wire.truncated, "GitHub checks")?;
    validate_github_repository_wire(&wire.repository, item.repository())?;
    validate_github_item_wire(&wire.item, item)?;
    if wire.reviews.len() > MAX_REVIEWS
        || wire.review_threads.len() > MAX_THREADS
        || wire.checks.len() > MAX_CHECKS
    {
        bail!("GitHub PR review response exceeds a collection count limit");
    }
    let reviews = wire
        .reviews
        .into_iter()
        .map(|review| {
            let state = match review.state {
                GithubReviewStateWire::Approved => ForgeReviewState::Approved,
                GithubReviewStateWire::ChangesRequested => ForgeReviewState::ChangesRequested,
                GithubReviewStateWire::Commented => ForgeReviewState::Commented,
                GithubReviewStateWire::Dismissed => ForgeReviewState::Dismissed,
                GithubReviewStateWire::Pending => ForgeReviewState::Pending,
            };
            ForgeReview::new(
                ProviderObjectId::new("github", ProviderObjectKind::Review, review.id)?,
                github_actor(review.author)?,
                state,
                review.body,
                review.submitted_at,
                review.commit_oid,
            )
        })
        .collect::<Result<Vec<_>>>()?;
    let threads = wire
        .review_threads
        .into_iter()
        .map(|thread| {
            require_complete_page(
                &thread.page_info,
                thread.truncated,
                "GitHub thread comments",
            )?;
            let comments = thread
                .comments
                .into_iter()
                .map(|comment| github_comment(comment, item, false))
                .collect::<Result<Vec<_>>>()?;
            ForgeReviewThread::new(
                ProviderObjectId::new("github", ProviderObjectKind::ReviewThread, thread.id)?,
                thread.is_resolved,
                comments,
            )
        })
        .collect::<Result<Vec<_>>>()?;
    let checks = wire
        .checks
        .into_iter()
        .map(|check| {
            let status = match check.status {
                GithubCheckStatusWire::Queued => ForgeCheckStatus::Queued,
                GithubCheckStatusWire::InProgress => ForgeCheckStatus::InProgress,
                GithubCheckStatusWire::Completed => ForgeCheckStatus::Completed,
            };
            let conclusion = check.conclusion.map(|conclusion| match conclusion {
                GithubCheckConclusionWire::Success => ForgeCheckConclusion::Success,
                GithubCheckConclusionWire::Failure => ForgeCheckConclusion::Failure,
                GithubCheckConclusionWire::Neutral => ForgeCheckConclusion::Neutral,
                GithubCheckConclusionWire::Cancelled => ForgeCheckConclusion::Cancelled,
                GithubCheckConclusionWire::Skipped => ForgeCheckConclusion::Skipped,
                GithubCheckConclusionWire::TimedOut => ForgeCheckConclusion::TimedOut,
                GithubCheckConclusionWire::ActionRequired => ForgeCheckConclusion::ActionRequired,
                GithubCheckConclusionWire::StartupFailure => ForgeCheckConclusion::StartupFailure,
                GithubCheckConclusionWire::Stale => ForgeCheckConclusion::Stale,
            });
            ForgeCheck::new(
                ProviderObjectId::new("github", ProviderObjectKind::Check, check.id)?,
                github_actor(check.actor)?,
                check.name,
                status,
                conclusion,
                check.head_oid,
                check.updated_at,
            )
        })
        .collect::<Result<Vec<_>>>()?;
    PullRequestReviewSnapshot::new(item.clone(), wire.observed_at, reviews, threads, checks)
}

fn github_comment_receipt(
    mut wire: GithubAppendCommentReceiptsWire,
    request: &ForgeEffectRequest,
) -> Result<ForgeMutationReceipt> {
    require_complete_page(
        &wire.page_info,
        wire.truncated,
        "GitHub append-comment reconciliation",
    )?;
    if wire.receipts.len() != 1 {
        bail!("GitHub comment mutation requires exactly one matching receipt");
    }
    let receipt = wire
        .receipts
        .pop()
        .context("GitHub comment receipt disappeared during reconciliation")?;
    let effect = request.as_append_comment();
    validate_github_repository_wire(&receipt.repository, effect.item.repository())?;
    validate_github_item_wire(&receipt.item, &effect.item)?;
    if receipt.effect_id != effect.effect_id
        || receipt.revision_id != effect.item.revision
        || receipt.body_digest != effect.body_digest
        || receipt.comment.body != effect.body
    {
        bail!("GitHub comment receipt does not match the effect, revision, or exact body digest");
    }
    let comment = github_comment(receipt.comment, &effect.item, true)?;
    let neutral = ForgeMutationReceipt::new(
        effect.effect_id.clone(),
        effect.item.clone(),
        effect.body_digest.clone(),
        comment.author.clone(),
        comment.provider_comment_id.clone(),
        comment.url,
        comment.created_at,
    )?;
    neutral.validate_for_request(request)?;
    Ok(neutral)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};
    use std::{collections::VecDeque, sync::Mutex};

    const OBSERVED_AT: &str = "2026-08-16T01:02:03Z";
    const CREATED_AT: &str = "2026-08-15T01:02:03Z";

    #[derive(Debug)]
    struct ScriptedGithubRunner {
        responses: Mutex<VecDeque<GithubRunnerResponse>>,
        requests: Mutex<Vec<GithubRunnerRequest>>,
    }

    impl ScriptedGithubRunner {
        fn new(responses: impl IntoIterator<Item = GithubRunnerResponse>) -> Self {
            Self {
                responses: Mutex::new(responses.into_iter().collect()),
                requests: Mutex::new(Vec::new()),
            }
        }

        fn request_count(&self) -> Result<usize> {
            Ok(self
                .requests
                .lock()
                .map_err(|_| anyhow::anyhow!("script request lock poisoned"))?
                .len())
        }
    }

    impl GithubRunner for ScriptedGithubRunner {
        fn run(&self, request: &GithubRunnerRequest) -> Result<GithubRunnerResponse> {
            self.requests
                .lock()
                .map_err(|_| anyhow::anyhow!("script request lock poisoned"))?
                .push(request.clone());
            self.responses
                .lock()
                .map_err(|_| anyhow::anyhow!("script response lock poisoned"))?
                .pop_front()
                .context("scripted GitHub runner exhausted its response queue")
        }
    }

    fn object(kind: ProviderObjectKind, stable_id: &str) -> ProviderObjectId {
        ProviderObjectId::new("github", kind, stable_id).expect("valid provider object id")
    }

    fn repository() -> ForgeRepository {
        ForgeRepository::new(
            "github",
            "github.com/meta-develop/maco",
            object(ProviderObjectKind::Repository, "R_repo"),
        )
        .expect("valid repository")
    }

    fn actor(id: &str, handle: &str, kind: ReportedActorKind) -> ForgeActor {
        ForgeActor::new(
            "github",
            object(ProviderObjectKind::Actor, id),
            handle,
            kind,
        )
        .expect("valid actor")
    }

    fn issue() -> ForgeItem {
        ForgeItem::new(
            repository(),
            ForgeItemKind::Issue,
            89,
            object(ProviderObjectKind::Item, "I_issue"),
            "revision:issue:1",
            None,
            None,
        )
        .expect("valid issue")
    }

    fn pr() -> ForgeItem {
        ForgeItem::new(
            repository(),
            ForgeItemKind::PullRequest,
            90,
            object(ProviderObjectKind::Item, "PR_review"),
            "revision:pr:1",
            Some("1".repeat(40)),
            Some("2".repeat(40)),
        )
        .expect("valid PR")
    }

    fn repository_json() -> Value {
        json!({
            "id": "R_repo",
            "nameWithOwner": "meta-develop/maco",
            "url": "https://github.com/meta-develop/maco"
        })
    }

    fn item_json(item: &ForgeItem) -> Value {
        let segment = match item.kind() {
            ForgeItemKind::Issue => "issues",
            ForgeItemKind::PullRequest => "pull",
        };
        json!({
            "id": item.provider_item_id().stable_id(),
            "number": item.number(),
            "kind": match item.kind() {
                ForgeItemKind::Issue => "issue",
                ForgeItemKind::PullRequest => "pull_request",
            },
            "revisionId": item.revision(),
            "url": format!("https://github.com/meta-develop/maco/{segment}/{}", item.number()),
            "headOid": item.head_oid(),
            "baseOid": item.base_oid(),
        })
    }

    fn actor_json(id: &str, login: &str, kind: &str) -> Value {
        json!({"id": id, "login": login, "type": kind})
    }

    fn complete_page() -> Value {
        json!({"hasNextPage": false, "endCursor": null})
    }

    fn issue_comment_json(id: &str, database_id: u64, author: Value, body: &str) -> Value {
        json!({
            "id": id,
            "databaseId": database_id,
            "url": format!(
                "https://github.com/meta-develop/maco/issues/89#issuecomment-{database_id}"
            ),
            "body": body,
            "createdAt": CREATED_AT,
            "author": author,
        })
    }

    fn pr_review_comment_json(id: &str, database_id: u64, author: Value, body: &str) -> Value {
        json!({
            "id": id,
            "databaseId": database_id,
            "url": format!(
                "https://github.com/meta-develop/maco/pull/90#discussion_r{database_id}"
            ),
            "body": body,
            "createdAt": CREATED_AT,
            "author": author,
        })
    }

    fn pr_issue_comment_json(id: &str, database_id: u64, author: Value, body: &str) -> Value {
        json!({
            "id": id,
            "databaseId": database_id,
            "url": format!(
                "https://github.com/meta-develop/maco/pull/90#issuecomment-{database_id}"
            ),
            "body": body,
            "createdAt": CREATED_AT,
            "author": author,
        })
    }

    fn issue_thread_json() -> Value {
        let item = issue();
        json!({
            "repository": repository_json(),
            "item": item_json(&item),
            "observedAt": OBSERVED_AT,
            "comments": [issue_comment_json(
                "IC_one",
                101,
                actor_json("U_alice", "alice", "User"),
                "claim state"
            )],
            "pageInfo": complete_page(),
            "truncated": false,
        })
    }

    fn pr_snapshot_json() -> Value {
        let item = pr();
        json!({
            "repository": repository_json(),
            "item": item_json(&item),
            "observedAt": OBSERVED_AT,
            "reviews": [{
                "id": "PRR_one",
                "author": actor_json("U_bob", "bob", "User"),
                "state": "CHANGES_REQUESTED",
                "body": "please fix",
                "submittedAt": CREATED_AT,
                "commitOid": item.head_oid(),
            }],
            "reviewsPageInfo": complete_page(),
            "reviewThreads": [{
                "id": "PRT_one",
                "isResolved": false,
                "comments": [pr_review_comment_json(
                    "PRRC_one",
                    202,
                    actor_json("B_review", "review-bot", "Bot"),
                    "advisory"
                )],
                "pageInfo": complete_page(),
                "truncated": false,
            }],
            "reviewThreadsPageInfo": complete_page(),
            "checks": [{
                "id": "CHK_one",
                "actor": actor_json("B_ci", "ci-bot", "Bot"),
                "name": "test",
                "status": "COMPLETED",
                "conclusion": "SUCCESS",
                "headOid": item.head_oid(),
                "updatedAt": CREATED_AT,
            }],
            "checksPageInfo": complete_page(),
            "truncated": false,
        })
    }

    fn append_effect(effect_id: &str, body: &str) -> ForgeEffectRequest {
        ForgeEffectRequest::append_comment(
            AppendCommentEffect::new(
                effect_id,
                issue(),
                actor("U_writer", "writer", ReportedActorKind::Human),
                body,
            )
            .expect("valid append effect"),
        )
        .expect("valid effect request")
    }

    fn append_pr_effect(effect_id: &str, body: &str) -> ForgeEffectRequest {
        ForgeEffectRequest::append_comment(
            AppendCommentEffect::new(
                effect_id,
                pr(),
                actor("U_writer", "writer", ReportedActorKind::Human),
                body,
            )
            .expect("valid PR append effect"),
        )
        .expect("valid PR effect request")
    }

    fn mutation_receipt_json(request: &ForgeEffectRequest) -> Value {
        let effect = request.as_append_comment();
        let comment = match effect.item().kind() {
            ForgeItemKind::Issue => issue_comment_json(
                "IC_created",
                303,
                actor_json("U_writer", "writer", "User"),
                effect.body(),
            ),
            ForgeItemKind::PullRequest => pr_issue_comment_json(
                "IC_created",
                303,
                actor_json("U_writer", "writer", "User"),
                effect.body(),
            ),
        };
        json!({
            "receipts": [{
                "effectId": effect.effect_id(),
                "repository": repository_json(),
                "item": item_json(effect.item()),
                "revisionId": effect.item().revision(),
                "bodyDigest": effect.body_digest(),
                "comment": comment,
            }],
            "pageInfo": complete_page(),
            "truncated": false,
        })
    }

    #[test]
    fn scripted_github_observes_complete_issue_thread_deterministically() {
        let request = ForgeObservationRequest::item_thread(issue()).expect("valid request");
        let response = GithubRunnerResponse::item_thread_json(issue_thread_json().to_string())
            .expect("valid response");
        let forge = GithubForge::new(ScriptedGithubRunner::new([response]));
        let observation = forge.observe(&request).expect("observe issue thread");
        let ForgeObservation::ItemThread(thread) = observation else {
            panic!("expected item thread");
        };
        assert_eq!(thread.item(), request.item());
        assert_eq!(thread.comments().len(), 1);
        assert_eq!(thread.comments()[0].author().canonical_handle(), "alice");
        assert_eq!(forge.runner.request_count().expect("request count"), 1);
    }

    #[test]
    fn scripted_github_observes_pr_snapshot_bound_to_current_head() {
        let request =
            ForgeObservationRequest::pull_request_review_snapshot(pr()).expect("valid request");
        let response =
            GithubRunnerResponse::pull_request_review_snapshot_json(pr_snapshot_json().to_string())
                .expect("valid response");
        let forge = GithubForge::new(ScriptedGithubRunner::new([response]));
        let observation = forge.observe(&request).expect("observe PR review snapshot");
        let ForgeObservation::PullRequestReviewSnapshot(snapshot) = observation else {
            panic!("expected PR snapshot");
        };
        assert_eq!(snapshot.reviews().len(), 1);
        assert_eq!(snapshot.threads().len(), 1);
        assert_eq!(snapshot.checks().len(), 1);
        assert_eq!(
            snapshot.reviews()[0].commit_oid(),
            request.item().head_oid().unwrap()
        );
        assert_eq!(
            snapshot.checks()[0].head_oid(),
            request.item().head_oid().unwrap()
        );
    }

    #[test]
    fn neutral_deserialization_rejects_unknown_missing_and_provider_mismatch() {
        let mut value = serde_json::to_value(issue()).expect("serialize issue");
        value
            .as_object_mut()
            .expect("item object")
            .insert("unknown".to_string(), json!(true));
        assert!(serde_json::from_value::<ForgeItem>(value).is_err());

        let mut missing = serde_json::to_value(issue()).expect("serialize issue");
        missing
            .as_object_mut()
            .expect("item object")
            .remove("head_oid");
        assert!(serde_json::from_value::<ForgeItem>(missing).is_err());

        let wrong = ForgeRepository::new(
            "github",
            "github.com/meta-develop/maco",
            ProviderObjectId::new("gitlab", ProviderObjectKind::Repository, "R_repo")
                .expect("valid isolated id"),
        );
        assert!(wrong.is_err());
    }

    #[test]
    fn identifiers_oids_and_calendar_timestamps_fail_closed() {
        assert!(ProviderObjectId::new("GitHub", ProviderObjectKind::Item, "I").is_err());
        assert!(ProviderObjectId::new("github", ProviderObjectKind::Item, "bad/id").is_err());
        assert!(ForgeTimestamp::new("2024-02-29T23:59:59Z").is_ok());
        assert!(ForgeTimestamp::new("2023-02-29T23:59:59Z").is_err());
        assert!(ForgeTimestamp::new("2024-04-31T00:00:00Z").is_err());
        assert!(ForgeTimestamp::new("2024-02-29T00:00:00+00:00").is_err());
        assert!(ForgeTimestamp::new(format!("2024-02-29T00:00:00Z{}", "0".repeat(500))).is_err());

        assert!(ForgeItem::new(
            repository(),
            ForgeItemKind::Issue,
            1,
            object(ProviderObjectKind::Item, "I_bad"),
            "revision:1",
            Some("1".repeat(40)),
            None,
        )
        .is_err());
        assert!(ForgeItem::new(
            repository(),
            ForgeItemKind::PullRequest,
            1,
            object(ProviderObjectKind::Item, "PR_bad"),
            "revision:1",
            Some("A".repeat(40)),
            Some("2".repeat(40)),
        )
        .is_err());
        assert!(ForgeItem::new(
            repository(),
            ForgeItemKind::PullRequest,
            1,
            object(ProviderObjectKind::Item, "PR_bad2"),
            "revision:1",
            Some("1".repeat(40)),
            Some("2".repeat(64)),
        )
        .is_err());
    }

    #[test]
    fn count_size_and_incomplete_pagination_limits_are_enforced() {
        let author = actor("U_alice", "alice", ReportedActorKind::Human);
        let comments = (0..=MAX_COMMENTS)
            .map(|index| {
                ForgeComment::new(
                    object(ProviderObjectKind::Comment, &format!("IC_{index}")),
                    author.clone(),
                    "x",
                    format!("https://github.com/meta-develop/maco/issues/89#issuecomment-{index}"),
                    ForgeTimestamp::new(CREATED_AT).expect("timestamp"),
                )
                .expect("comment")
            })
            .collect();
        assert!(ItemThreadObservation::new(
            issue(),
            ForgeTimestamp::new(OBSERVED_AT).expect("timestamp"),
            comments,
        )
        .is_err());
        assert!(
            GithubRunnerResponse::item_thread_json("x".repeat(MAX_RESPONSE_BYTES + 1)).is_err()
        );

        let mut paginated = issue_thread_json();
        paginated["pageInfo"]["hasNextPage"] = json!(true);
        paginated["pageInfo"]["endCursor"] = json!("cursor");
        let response = GithubRunnerResponse::item_thread_json(paginated.to_string())
            .expect("bounded response");
        let forge = GithubForge::new(ScriptedGithubRunner::new([response]));
        let request = ForgeObservationRequest::item_thread(issue()).expect("request");
        assert!(forge.observe(&request).is_err());
    }

    #[test]
    fn duplicate_objects_and_conflicting_actor_identity_are_rejected() {
        let original =
            issue_comment_json("IC_one", 101, actor_json("U_alice", "alice", "User"), "one");
        let mut duplicate = issue_thread_json();
        duplicate["comments"] = json!([original.clone(), original]);
        let forge = GithubForge::new(ScriptedGithubRunner::new([
            GithubRunnerResponse::item_thread_json(duplicate.to_string()).expect("response"),
        ]));
        assert!(forge
            .observe(&ForgeObservationRequest::item_thread(issue()).expect("request"))
            .is_err());

        let mut ambiguous = issue_thread_json();
        ambiguous["comments"] = json!([
            issue_comment_json("IC_one", 101, actor_json("U_one", "same", "User"), "one"),
            issue_comment_json("IC_two", 102, actor_json("U_two", "same", "Bot"), "two")
        ]);
        let forge = GithubForge::new(ScriptedGithubRunner::new([
            GithubRunnerResponse::item_thread_json(ambiguous.to_string()).expect("response"),
        ]));
        assert!(forge
            .observe(&ForgeObservationRequest::item_thread(issue()).expect("request"))
            .is_err());

        let mut conflicting = issue_thread_json();
        conflicting["comments"] = json!([
            issue_comment_json("IC_one", 101, actor_json("U_same", "one", "User"), "one"),
            issue_comment_json("IC_two", 102, actor_json("U_same", "two", "User"), "two")
        ]);
        let forge = GithubForge::new(ScriptedGithubRunner::new([
            GithubRunnerResponse::item_thread_json(conflicting.to_string()).expect("response"),
        ]));
        assert!(forge
            .observe(&ForgeObservationRequest::item_thread(issue()).expect("request"))
            .is_err());
    }

    #[test]
    fn fake_observation_and_effect_retry_are_deterministic_and_collision_safe() {
        let item = issue();
        let request = ForgeObservationRequest::item_thread(item.clone()).expect("request");
        let observation = ForgeObservation::ItemThread(
            ItemThreadObservation::new(
                item,
                ForgeTimestamp::new(OBSERVED_AT).expect("timestamp"),
                Vec::new(),
            )
            .expect("observation"),
        );
        let mut fake = FakeForgeTransport::new();
        fake.register_observation(request.clone(), observation.clone())
            .expect("register observation");
        assert_eq!(fake.observe(&request).expect("observe"), observation);

        let first = append_effect("effect-1", "bounded body");
        let receipt = fake.execute(&first).expect("first effect");
        assert_eq!(fake.execute(&first).expect("retry effect"), receipt);
        let collision = append_effect("effect-1", "different body");
        assert!(fake.execute(&collision).is_err());

        let boxed: Box<dyn ForgeTransport> = Box::new(fake);
        assert_eq!(
            boxed.observe(&request).expect("object-safe observe"),
            observation
        );
    }

    #[test]
    fn fake_duplicate_observation_registration_preserves_the_original() {
        let item = issue();
        let request = ForgeObservationRequest::item_thread(item.clone()).expect("request");
        let original = ForgeObservation::ItemThread(
            ItemThreadObservation::new(
                item.clone(),
                ForgeTimestamp::new("2026-08-16T00:00:00Z").expect("timestamp"),
                Vec::new(),
            )
            .expect("original observation"),
        );
        let replacement = ForgeObservation::ItemThread(
            ItemThreadObservation::new(
                item,
                ForgeTimestamp::new("2026-08-16T00:00:01Z").expect("timestamp"),
                Vec::new(),
            )
            .expect("replacement observation"),
        );
        let mut fake = FakeForgeTransport::new();
        fake.register_observation(request.clone(), original.clone())
            .expect("register original");
        assert!(fake
            .register_observation(request.clone(), replacement)
            .is_err());
        assert_eq!(
            fake.observe(&request).expect("retained observation"),
            original
        );
    }

    #[test]
    fn fake_pr_receipt_round_trip_preserves_complete_item_provenance() {
        let request = append_pr_effect("effect-pr-fake", "PR body");
        let fake = FakeForgeTransport::new();
        let receipt = fake.execute(&request).expect("fake PR receipt");
        assert_eq!(receipt.item(), request.as_append_comment().item());
        assert_eq!(
            receipt.head_oid(),
            request.as_append_comment().item().head_oid()
        );
        assert_eq!(
            receipt.base_oid(),
            request.as_append_comment().item().base_oid()
        );

        let serialized = serde_json::to_value(&receipt).expect("serialize receipt");
        let restored: ForgeMutationReceipt =
            serde_json::from_value(serialized.clone()).expect("deserialize receipt");
        assert_eq!(restored, receipt);
        restored
            .validate_for_request(&request)
            .expect("round-trip request binding");

        let mut missing_head = serialized.clone();
        missing_head["item"]
            .as_object_mut()
            .expect("item object")
            .remove("head_oid");
        assert!(serde_json::from_value::<ForgeMutationReceipt>(missing_head).is_err());

        let mut mismatched_head = serialized.clone();
        mismatched_head["item"]["head_oid"] = json!("3".repeat(40));
        let mismatched: ForgeMutationReceipt =
            serde_json::from_value(mismatched_head).expect("intrinsically valid other PR head");
        assert!(mismatched.validate_for_request(&request).is_err());

        let issue_request = append_effect("effect-issue-oid", "issue body");
        let issue_receipt = fake.execute(&issue_request).expect("fake issue receipt");
        let mut issue_with_oid = serde_json::to_value(issue_receipt).expect("serialize issue");
        issue_with_oid["item"]["head_oid"] = json!("1".repeat(40));
        assert!(serde_json::from_value::<ForgeMutationReceipt>(issue_with_oid).is_err());
    }

    #[test]
    fn scripted_github_append_comment_requires_one_exact_receipt() {
        let request = append_effect("effect-2", "publish once");
        let response = GithubRunnerResponse::append_comment_receipts_json(
            mutation_receipt_json(&request).to_string(),
        )
        .expect("response");
        let forge = GithubForge::new(ScriptedGithubRunner::new([response]));
        let receipt = forge.execute(&request).expect("exact receipt");
        assert_eq!(receipt.effect_id(), "effect-2");
        assert_eq!(
            receipt.revision(),
            request.as_append_comment().item().revision()
        );
        assert_eq!(
            receipt.body_digest(),
            request.as_append_comment().body_digest()
        );
        assert_eq!(
            receipt.actor(),
            request.as_append_comment().expected_actor()
        );
        assert_eq!(receipt.provider_comment_id().stable_id(), "IC_created");
        assert_eq!(receipt.created_at().as_str(), CREATED_AT);
    }

    #[test]
    fn scripted_github_pr_append_receipt_preserves_and_requires_exact_oids() {
        let request = append_pr_effect("effect-pr-github", "publish PR comment");
        let valid = mutation_receipt_json(&request);
        let response = GithubRunnerResponse::append_comment_receipts_json(valid.to_string())
            .expect("response");
        let forge = GithubForge::new(ScriptedGithubRunner::new([response]));
        let receipt = forge.execute(&request).expect("exact PR receipt");
        assert_eq!(receipt.item(), request.as_append_comment().item());
        assert_eq!(
            receipt.head_oid(),
            Some("1111111111111111111111111111111111111111")
        );
        assert_eq!(
            receipt.base_oid(),
            Some("2222222222222222222222222222222222222222")
        );
        let restored: ForgeMutationReceipt =
            serde_json::from_slice(&serde_json::to_vec(&receipt).expect("serialize receipt"))
                .expect("deserialize receipt");
        assert_eq!(restored, receipt);

        let mut missing = mutation_receipt_json(&request);
        missing["receipts"][0]["item"]
            .as_object_mut()
            .expect("wire item")
            .remove("headOid");
        let response = GithubRunnerResponse::append_comment_receipts_json(missing.to_string())
            .expect("bounded response");
        let forge = GithubForge::new(ScriptedGithubRunner::new([response]));
        assert!(forge.execute(&request).is_err());

        let mut mismatch = mutation_receipt_json(&request);
        mismatch["receipts"][0]["item"]["baseOid"] = json!("3".repeat(40));
        let response = GithubRunnerResponse::append_comment_receipts_json(mismatch.to_string())
            .expect("bounded response");
        let forge = GithubForge::new(ScriptedGithubRunner::new([response]));
        assert!(forge.execute(&request).is_err());
    }

    #[test]
    fn scripted_github_append_comment_rejects_zero_multiple_and_mismatched_receipts() {
        let request = append_effect("effect-3", "publish once");
        let valid = mutation_receipt_json(&request);
        let mut invalid = Vec::new();

        let mut zero = valid.clone();
        zero["receipts"] = json!([]);
        invalid.push(zero);

        let mut multiple = valid.clone();
        let receipt = multiple["receipts"][0].clone();
        multiple["receipts"] = json!([receipt.clone(), receipt]);
        invalid.push(multiple);

        for (path, bad) in [
            ("effectId", json!("different-effect")),
            ("revisionId", json!("revision:different")),
            ("bodyDigest", json!(sha256_identity(b"different"))),
        ] {
            let mut mismatch = valid.clone();
            mismatch["receipts"][0][path] = bad;
            invalid.push(mismatch);
        }

        let mut actor_mismatch = valid.clone();
        actor_mismatch["receipts"][0]["comment"]["author"]["id"] = json!("U_other");
        invalid.push(actor_mismatch);

        let mut id_url_mismatch = valid.clone();
        id_url_mismatch["receipts"][0]["comment"]["databaseId"] = json!(999);
        invalid.push(id_url_mismatch);

        let mut item_mismatch = valid.clone();
        item_mismatch["receipts"][0]["item"]["id"] = json!("I_other");
        invalid.push(item_mismatch);

        let mut incomplete = valid;
        incomplete["pageInfo"]["hasNextPage"] = json!(true);
        incomplete["pageInfo"]["endCursor"] = json!("cursor");
        invalid.push(incomplete);

        for value in invalid {
            let response = GithubRunnerResponse::append_comment_receipts_json(value.to_string())
                .expect("bounded response");
            let forge = GithubForge::new(ScriptedGithubRunner::new([response]));
            assert!(forge.execute(&request).is_err(), "accepted {value}");
        }
    }

    #[test]
    fn github_wire_rejects_unknown_missing_nested_fields_and_stale_oids() {
        let request =
            ForgeObservationRequest::pull_request_review_snapshot(pr()).expect("valid request");
        let mut variants = Vec::new();

        let mut unknown = pr_snapshot_json();
        unknown["repository"]["unexpected"] = json!(true);
        variants.push(unknown);

        let mut missing = pr_snapshot_json();
        missing["reviews"][0]
            .as_object_mut()
            .expect("review object")
            .remove("commitOid");
        variants.push(missing);

        let mut stale_review = pr_snapshot_json();
        stale_review["reviews"][0]["commitOid"] = json!("3".repeat(40));
        variants.push(stale_review);

        let mut stale_check = pr_snapshot_json();
        stale_check["checks"][0]["headOid"] = json!("3".repeat(40));
        variants.push(stale_check);

        let mut future = pr_snapshot_json();
        future["checks"][0]["updatedAt"] = json!("2026-08-17T00:00:00Z");
        variants.push(future);

        for value in variants {
            let response =
                GithubRunnerResponse::pull_request_review_snapshot_json(value.to_string())
                    .expect("bounded response");
            let forge = GithubForge::new(ScriptedGithubRunner::new([response]));
            assert!(forge.observe(&request).is_err(), "accepted {value}");
        }
    }

    #[test]
    fn mismatched_runner_response_and_production_runner_fail_closed() {
        let request = ForgeObservationRequest::item_thread(issue()).expect("request");
        let wrong =
            GithubRunnerResponse::pull_request_review_snapshot_json(pr_snapshot_json().to_string())
                .expect("response");
        let forge = GithubForge::new(ScriptedGithubRunner::new([wrong]));
        assert!(forge.observe(&request).is_err());

        let production = GithubForge::new(GithubProductionRunner::new());
        let error = production.observe(&request).expect_err("must fail closed");
        assert!(error.to_string().contains("fail-closed"));
    }
}
