//! Closed publication-effect descriptor and parent-observed completion material (#410).
//!
//! Fresh hosts replay bound completions from authenticated journal history alone.
//! Live submission uses [`PublicationEffectLiveVerifier`]; historical reduction uses
//! [`HistoricalEffectReplayContext`] and never performs provider I/O.
//!
//! **Git push provider helper (upcoming):** read `GitPushPublicationEffectFieldsV1::network_locator`
//! and call read-only observation with `observation_remote_url()` plus `lookup_ref` (same as
//! publication `observe_remote_ref`). Configure git HTTP with `git_command_url()` only when the
//! subprocess needs publication-normalized HTTPS. Build descriptors via
//! [`PublicationEffectDescriptorV1::try_new_git_push`] so `target_digest` and
//! `remote_binding_digest` match the exact external-effect target bytes.

use super::coordination_journal::{CoordinationOwnerIdentity, EffectReconciliationReceipt};
use crate::artifacts::state_auth::sha256_hex;
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

const DESCRIPTOR_SCHEMA: &str = "maco.coordination-publication-effect-descriptor";
const DESCRIPTOR_VERSION: u32 = 1;
const MATERIAL_SCHEMA: &str = "maco.parent-observed-publication-material";
const MATERIAL_VERSION: u32 = 1;

const MAX_EFFECT_ID_BYTES: usize = 128;
const MAX_SELECTOR_BYTES: usize = 2 * 1024;
const MAX_REMOTE_NAME_BYTES: usize = 256;
const MAX_REF_BYTES: usize = 1024;
const MAX_BRANCH_BYTES: usize = 256;
const MAX_GITHUB_SLUG_BYTES: usize = 100;
const MAX_GITHUB_LOGIN_BYTES: usize = 256;
const MAX_URL_BYTES: usize = 8 * 1024;
const MAX_MARKER_BYTES: usize = 512;
const MAX_PUBLICATION_REMOTE_URL_BYTES: usize = 8 * 1024;
const MAX_PUBLICATION_HOST_BYTES: usize = 253;
const MAX_PUBLICATION_PATH_BYTES: usize = 2 * 1024;
const MAX_PUBLICATION_PATH_COMPONENTS: usize = 32;

const GIT_NETWORK_LOCATOR_SCHEMA: &str = "maco.coordination-publication-git-network-locator";
const GIT_NETWORK_LOCATOR_VERSION: u32 = 1;
const GIT_PUSH_EXTERNAL_EFFECT_TARGET_VERSION: u32 = 1;
const GIT_PUSH_EXTERNAL_EFFECT_PAYLOAD_VERSION: u32 = 1;
const GITHUB_PR_EXTERNAL_EFFECT_TARGET_VERSION: u32 = 1;
const GITHUB_PR_EXTERNAL_EFFECT_PAYLOAD_VERSION: u32 = 1;
const EXTERNAL_EFFECT_MARKER_PREFIX: &str = "maco-external-effect";

/// Sealed context: only coordination admission may construct this for live verification.
#[derive(Debug, Clone, Copy)]
pub struct LiveEffectVerificationContext(());

impl LiveEffectVerificationContext {
    pub(crate) fn admission_live() -> Self {
        Self(())
    }
}

/// Sealed context: only journal historical reduction may construct this for replay.
#[derive(Debug, Clone, Copy)]
pub struct HistoricalEffectReplayContext(());

impl HistoricalEffectReplayContext {
    pub(crate) fn journal_replay() -> Self {
        Self(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublicationEffectLiveVerification {
    Verified,
    Refused,
    Unknown,
}

/// Read-only provider verification for a bound live completion (no journal recursion).
pub trait PublicationEffectLiveVerifier: Send + Sync {
    fn verify_live_bound_completion(
        &self,
        owner: &CoordinationOwnerIdentity,
        descriptor: &PublicationEffectDescriptorV1,
        material: &ParentObservedPublicationMaterialV1,
    ) -> PublicationEffectLiveVerification;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicationEffectDescriptorV1 {
    schema: String,
    version: u32,
    effect_id: String,
    transport_provider: String,
    repository_selector: String,
    repository_identity: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    source_provenance_digest: Option<String>,
    target_digest: String,
    payload_digest: String,
    operation: PublicationEffectOperationV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum PublicationEffectOperationV1 {
    GitPush(GitPushPublicationEffectFieldsV1),
    GithubPullRequest(GithubPullRequestPublicationEffectFieldsV1),
}

/// Exact HTTPS `remote_url` from the external-effect Git push target (not a git remote alias).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicationGitNetworkLocatorV1 {
    schema: String,
    version: u32,
    remote_url: String,
}

impl PublicationGitNetworkLocatorV1 {
    /// Refuses local/file/SSH/SCP and any URL with userinfo, query, fragment, or escapes.
    pub fn try_new(remote_url: impl Into<String>) -> Result<Self> {
        let remote_url = remote_url.into();
        validate_publication_https_remote_url(&remote_url)?;
        let value = Self {
            schema: GIT_NETWORK_LOCATOR_SCHEMA.to_string(),
            version: GIT_NETWORK_LOCATOR_VERSION,
            remote_url,
        };
        value.validate()?;
        Ok(value)
    }

    /// Byte-exact URL stored in the external-effect target JSON (`remote_url` field).
    pub fn observation_remote_url(&self) -> &str {
        &self.remote_url
    }

    /// Normalized HTTPS URL for git subprocess configuration (publication `command_url` rules).
    pub fn git_command_url(&self) -> Result<String> {
        publication_https_command_url(&self.remote_url)
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if self.schema != GIT_NETWORK_LOCATOR_SCHEMA || self.version != GIT_NETWORK_LOCATOR_VERSION
        {
            bail!("git network locator has an unsupported schema or version");
        }
        validate_publication_https_remote_url(&self.remote_url)?;
        Ok(())
    }
}

/// Stable digest of `maco_publication_remote_binding_v1` (remote name + exact target URL).
pub fn git_push_remote_binding_digest(
    remote_name: &str,
    locator: &PublicationGitNetworkLocatorV1,
) -> Result<String> {
    validate_bounded_text(remote_name, "git remote name", MAX_REMOTE_NAME_BYTES, false)?;
    locator.validate()?;
    stable_json_digest(&(
        "maco_publication_remote_binding_v1",
        remote_name,
        locator.observation_remote_url(),
    ))
}

/// Stable digest of the Git push external-effect payload object (part2 producer shape).
pub fn git_push_external_effect_payload_digest(expected_oid: &str) -> Result<String> {
    validate_git_oid(expected_oid, "expected oid")?;
    stable_json_digest(&serde_json::json!({
        "version": GIT_PUSH_EXTERNAL_EFFECT_PAYLOAD_VERSION,
        "expected_oid": expected_oid,
    }))
}

/// Stable digest of the GitHub PR external-effect target object (part2 producer shape).
pub fn github_pull_request_external_effect_target_digest(
    repository_selector: &str,
    expected_oid: &str,
    expected_base_oid: &str,
    base_branch: &str,
) -> Result<String> {
    validate_bounded_text(
        repository_selector,
        "repository selector",
        MAX_SELECTOR_BYTES,
        false,
    )?;
    validate_git_oid(expected_oid, "expected oid")?;
    validate_git_oid(expected_base_oid, "expected base oid")?;
    validate_bounded_text(base_branch, "base branch", MAX_BRANCH_BYTES, false)?;
    stable_json_digest(&serde_json::json!({
        "version": GITHUB_PR_EXTERNAL_EFFECT_TARGET_VERSION,
        "repository": repository_selector,
        "expected_oid": expected_oid,
        "expected_base_oid": expected_base_oid,
        "base": base_branch,
    }))
}

/// Stable digest of the Git push external-effect target object (part2 producer shape).
pub fn git_push_external_effect_target_digest(
    repository_selector: &str,
    remote_name: &str,
    locator: &PublicationGitNetworkLocatorV1,
    base_branch: &str,
    expected_base_oid: &str,
) -> Result<String> {
    validate_bounded_text(
        repository_selector,
        "repository selector",
        MAX_SELECTOR_BYTES,
        false,
    )?;
    validate_bounded_text(remote_name, "git remote name", MAX_REMOTE_NAME_BYTES, false)?;
    validate_bounded_text(base_branch, "git base branch", MAX_BRANCH_BYTES, false)?;
    validate_git_oid(expected_base_oid, "expected base oid")?;
    locator.validate()?;
    stable_json_digest(&serde_json::json!({
        "version": GIT_PUSH_EXTERNAL_EFFECT_TARGET_VERSION,
        "repository": repository_selector,
        "remote_name": remote_name,
        "remote_url": locator.observation_remote_url(),
        "base": base_branch,
        "expected_base_oid": expected_base_oid,
    }))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GitPushPublicationEffectFieldsV1 {
    network_locator: PublicationGitNetworkLocatorV1,
    remote_name: String,
    lookup_ref: String,
    base_branch: String,
    expected_base_oid: String,
    expected_head_oid: String,
    remote_binding_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GithubPullRequestPublicationEffectFieldsV1 {
    repository_owner: String,
    repository_name: String,
    lookup_head_branch: String,
    base_branch: String,
    expected_base_oid: String,
    expected_head_oid: String,
    draft: bool,
    expected_author: String,
    marker: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParentObservedPublicationMaterialV1 {
    schema: String,
    version: u32,
    reserve_event_nonce: String,
    descriptor: PublicationEffectDescriptorV1,
    observation: ParentObservedPublicationObservationV1,
    canonical_material_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ParentObservedPublicationObservationV1 {
    GitPush(GitPushParentObservationV1),
    GithubPullRequest(GithubPullRequestParentObservationV1),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GitPushParentObservationV1 {
    lookup_ref: String,
    observed_head_oid: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GithubPullRequestParentObservationV1 {
    number: u64,
    url: String,
    head_oid: String,
    base_oid: String,
    base_ref_name: String,
    head_ref_name: String,
    author: String,
    is_draft: bool,
    state: String,
}

#[derive(Debug, Clone)]
pub struct PublicationEffectDescriptorBinding {
    pub effect_id: String,
    pub transport_provider: String,
    pub repository_selector: String,
    pub repository_identity: String,
    pub source_provenance_digest: Option<String>,
    pub target_digest: String,
    pub payload_digest: String,
}

#[derive(Debug, Clone)]
pub struct GithubPullRequestPublicationEffectIdentity {
    pub repository_owner: String,
    pub repository_name: String,
    pub lookup_head_branch: String,
    pub base_branch: String,
    pub expected_base_oid: String,
    pub expected_head_oid: String,
    pub draft: bool,
    pub expected_author: String,
    pub marker: String,
}

#[derive(Debug, Clone)]
pub struct GithubPullRequestParentObservationInput {
    pub number: u64,
    pub url: String,
    pub head_oid: String,
    pub base_oid: String,
    pub base_ref_name: String,
    pub head_ref_name: String,
    pub author: String,
    pub is_draft: bool,
    pub state: String,
}

impl PublicationEffectDescriptorV1 {
    pub fn try_new_git_push(
        binding: PublicationEffectDescriptorBinding,
        fields: GitPushPublicationEffectFieldsV1,
    ) -> Result<Self> {
        let repository_selector = binding.repository_selector;
        let target_digest = binding.target_digest;
        fields.validate()?;
        let expected_target = git_push_external_effect_target_digest(
            &repository_selector,
            fields.remote_name(),
            fields.network_locator(),
            fields.base_branch(),
            fields.expected_base_oid(),
        )?;
        if target_digest != expected_target {
            bail!("git push descriptor target digest does not match the external effect target");
        }
        let value = Self {
            schema: DESCRIPTOR_SCHEMA.to_string(),
            version: DESCRIPTOR_VERSION,
            effect_id: binding.effect_id,
            transport_provider: binding.transport_provider,
            repository_selector,
            repository_identity: binding.repository_identity,
            source_provenance_digest: binding.source_provenance_digest,
            target_digest,
            payload_digest: binding.payload_digest,
            operation: PublicationEffectOperationV1::GitPush(fields),
        };
        value.validate()?;
        Ok(value)
    }

    pub fn try_new_github_pull_request(
        binding: PublicationEffectDescriptorBinding,
        fields: GithubPullRequestPublicationEffectFieldsV1,
    ) -> Result<Self> {
        let repository_selector = binding.repository_selector;
        let target_digest = binding.target_digest;
        fields.validate()?;
        let expected_target = github_pull_request_external_effect_target_digest(
            &repository_selector,
            fields.expected_head_oid(),
            fields.expected_base_oid(),
            fields.base_branch(),
        )?;
        if target_digest != expected_target {
            bail!(
                "github pull request descriptor target digest does not match the external effect target"
            );
        }
        let value = Self {
            schema: DESCRIPTOR_SCHEMA.to_string(),
            version: DESCRIPTOR_VERSION,
            effect_id: binding.effect_id,
            transport_provider: binding.transport_provider,
            repository_selector,
            repository_identity: binding.repository_identity,
            source_provenance_digest: binding.source_provenance_digest,
            target_digest,
            payload_digest: binding.payload_digest,
            operation: PublicationEffectOperationV1::GithubPullRequest(fields),
        };
        value.validate()?;
        Ok(value)
    }

    pub fn effect_id(&self) -> &str {
        &self.effect_id
    }

    pub fn operation(&self) -> &PublicationEffectOperationV1 {
        &self.operation
    }

    pub fn repository_selector(&self) -> &str {
        &self.repository_selector
    }

    pub fn repository_identity(&self) -> &str {
        &self.repository_identity
    }

    pub fn transport_provider(&self) -> &str {
        &self.transport_provider
    }

    pub fn target_digest(&self) -> &str {
        &self.target_digest
    }

    pub fn payload_digest(&self) -> &str {
        &self.payload_digest
    }

    pub fn source_provenance_digest(&self) -> Option<&str> {
        self.source_provenance_digest.as_deref()
    }

    pub fn expected_external_effect_marker(&self) -> String {
        format!(
            "<!-- {EXTERNAL_EFFECT_MARKER_PREFIX}:v2:{} -->",
            self.effect_id()
        )
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema != DESCRIPTOR_SCHEMA || self.version != DESCRIPTOR_VERSION {
            bail!("publication effect descriptor has an unsupported schema or version");
        }
        validate_effect_id(&self.effect_id)?;
        validate_bounded_text(
            &self.transport_provider,
            "transport provider",
            MAX_SELECTOR_BYTES,
            false,
        )?;
        validate_bounded_text(
            &self.repository_selector,
            "repository selector",
            MAX_SELECTOR_BYTES,
            false,
        )?;
        validate_bounded_text(
            &self.repository_identity,
            "repository identity",
            MAX_SELECTOR_BYTES,
            false,
        )?;
        if let Some(digest) = &self.source_provenance_digest {
            validate_sha256_hex(digest, "source provenance digest")?;
        }
        validate_sha256_hex(&self.target_digest, "target digest")?;
        validate_sha256_hex(&self.payload_digest, "payload digest")?;
        self.validate_external_effect_bindings()?;
        Ok(())
    }

    fn validate_external_effect_bindings(&self) -> Result<()> {
        match &self.operation {
            PublicationEffectOperationV1::GitPush(fields) => {
                fields.validate()?;
                if self.transport_provider() != "git" {
                    bail!("git push descriptor used a non-git transport provider");
                }
                let expected_target = git_push_external_effect_target_digest(
                    self.repository_selector(),
                    fields.remote_name(),
                    fields.network_locator(),
                    fields.base_branch(),
                    fields.expected_base_oid(),
                )?;
                if self.target_digest() != expected_target {
                    bail!("git push descriptor target digest does not match its fields");
                }
                let expected_payload =
                    git_push_external_effect_payload_digest(fields.expected_head_oid())?;
                if self.payload_digest() != expected_payload {
                    bail!("git push descriptor payload digest does not match expected head oid");
                }
            }
            PublicationEffectOperationV1::GithubPullRequest(fields) => {
                fields.validate()?;
                if self.transport_provider() != "github" {
                    bail!("github pull request descriptor used a non-github transport provider");
                }
                validate_external_effect_marker_for_descriptor(self, fields.marker())?;
                let expected_target = github_pull_request_external_effect_target_digest(
                    self.repository_selector(),
                    fields.expected_head_oid(),
                    fields.expected_base_oid(),
                    fields.base_branch(),
                )?;
                if self.target_digest() != expected_target {
                    bail!("github pull request descriptor target digest does not match its fields");
                }
            }
        }
        if self.source_provenance_digest.is_some() {
            // Source-guard effect_id uses guard fields not stored on the descriptor; marker/id
            // binding for that path is owned by the publication facade worker.
        } else {
            let expected_effect_id = expected_publication_effect_id_without_source(self)?;
            if self.effect_id() != expected_effect_id {
                bail!("descriptor effect id does not match canonical external-effect binding");
            }
        }
        Ok(())
    }
}

impl GitPushPublicationEffectFieldsV1 {
    pub fn new(
        remote_name: impl Into<String>,
        network_locator: PublicationGitNetworkLocatorV1,
        lookup_ref: impl Into<String>,
        base_branch: impl Into<String>,
        expected_base_oid: impl Into<String>,
        expected_head_oid: impl Into<String>,
        remote_binding_digest: impl Into<String>,
    ) -> Result<Self> {
        let remote_name = remote_name.into();
        let remote_binding_digest = remote_binding_digest.into();
        let value = Self {
            network_locator,
            remote_name,
            lookup_ref: lookup_ref.into(),
            base_branch: base_branch.into(),
            expected_base_oid: expected_base_oid.into(),
            expected_head_oid: expected_head_oid.into(),
            remote_binding_digest,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn network_locator(&self) -> &PublicationGitNetworkLocatorV1 {
        &self.network_locator
    }

    pub fn remote_name(&self) -> &str {
        &self.remote_name
    }

    pub fn lookup_ref(&self) -> &str {
        &self.lookup_ref
    }

    pub fn base_branch(&self) -> &str {
        &self.base_branch
    }

    pub fn expected_base_oid(&self) -> &str {
        &self.expected_base_oid
    }

    pub fn expected_head_oid(&self) -> &str {
        &self.expected_head_oid
    }

    pub fn remote_binding_digest(&self) -> &str {
        &self.remote_binding_digest
    }

    fn validate(&self) -> Result<()> {
        self.network_locator.validate()?;
        validate_bounded_text(
            &self.remote_name,
            "git remote name",
            MAX_REMOTE_NAME_BYTES,
            false,
        )?;
        validate_publication_ref(&self.lookup_ref, "git lookup ref")?;
        validate_bounded_text(
            &self.base_branch,
            "git base branch",
            MAX_BRANCH_BYTES,
            false,
        )?;
        validate_git_oid(&self.expected_base_oid, "expected base oid")?;
        validate_git_oid(&self.expected_head_oid, "expected head oid")?;
        validate_sha256_hex(&self.remote_binding_digest, "remote binding digest")?;
        let expected_binding =
            git_push_remote_binding_digest(&self.remote_name, &self.network_locator)?;
        if self.remote_binding_digest != expected_binding {
            bail!("git push remote binding digest does not match locator and remote name");
        }
        Ok(())
    }
}

impl GithubPullRequestPublicationEffectFieldsV1 {
    pub fn new(identity: GithubPullRequestPublicationEffectIdentity) -> Result<Self> {
        let value = Self {
            repository_owner: identity.repository_owner,
            repository_name: identity.repository_name,
            lookup_head_branch: identity.lookup_head_branch,
            base_branch: identity.base_branch,
            expected_base_oid: identity.expected_base_oid,
            expected_head_oid: identity.expected_head_oid,
            draft: identity.draft,
            expected_author: identity.expected_author,
            marker: identity.marker,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn repository_owner(&self) -> &str {
        &self.repository_owner
    }

    pub fn repository_name(&self) -> &str {
        &self.repository_name
    }

    pub fn lookup_head_branch(&self) -> &str {
        &self.lookup_head_branch
    }

    pub fn base_branch(&self) -> &str {
        &self.base_branch
    }

    pub fn expected_base_oid(&self) -> &str {
        &self.expected_base_oid
    }

    pub fn expected_head_oid(&self) -> &str {
        &self.expected_head_oid
    }

    pub fn draft(&self) -> bool {
        self.draft
    }

    pub fn expected_author(&self) -> &str {
        &self.expected_author
    }

    pub fn marker(&self) -> &str {
        &self.marker
    }

    fn validate(&self) -> Result<()> {
        validate_github_slug(&self.repository_owner, "repository owner")?;
        validate_github_slug(&self.repository_name, "repository name")?;
        validate_bounded_text(
            &self.lookup_head_branch,
            "lookup head branch",
            MAX_BRANCH_BYTES,
            false,
        )?;
        validate_bounded_text(&self.base_branch, "base branch", MAX_BRANCH_BYTES, false)?;
        validate_git_oid(&self.expected_base_oid, "expected base oid")?;
        validate_git_oid(&self.expected_head_oid, "expected head oid")?;
        validate_bounded_text(
            &self.expected_author,
            "expected author",
            MAX_GITHUB_LOGIN_BYTES,
            false,
        )?;
        validate_bounded_text(&self.marker, "effect marker", MAX_MARKER_BYTES, false)?;
        Ok(())
    }
}

/// Stable digest of the GitHub PR external-effect payload object (part2 producer shape).
pub fn github_pull_request_external_effect_payload_digest(
    title: &str,
    unmarked_body: &str,
    draft: bool,
    expected_author: &str,
) -> Result<String> {
    validate_bounded_text(title, "pull request title", MAX_MARKER_BYTES, false)?;
    if unmarked_body.len() > MAX_URL_BYTES || unmarked_body.as_bytes().contains(&0) {
        bail!("pull request body exceeds bounds for payload digest");
    }
    validate_bounded_text(
        expected_author,
        "expected author",
        MAX_GITHUB_LOGIN_BYTES,
        false,
    )?;
    stable_json_digest(&serde_json::json!({
        "version": GITHUB_PR_EXTERNAL_EFFECT_PAYLOAD_VERSION,
        "title": title,
        "body": unmarked_body,
        "draft": draft,
        "expected_author": expected_author,
    }))
}

pub fn validate_external_effect_marker_for_descriptor(
    descriptor: &PublicationEffectDescriptorV1,
    marker: &str,
) -> Result<()> {
    validate_effect_marker(marker)?;
    if marker != descriptor.expected_external_effect_marker() {
        bail!("effect marker does not match descriptor effect id");
    }
    Ok(())
}

pub fn unmarked_pr_body_from_marked_body(marked_body: &str, marker: &str) -> Result<String> {
    validate_effect_marker(marker)?;
    if marked_body == marker {
        return Ok(String::new());
    }
    let suffix = format!("\n\n{marker}");
    if marked_body.ends_with(&suffix) {
        return Ok(marked_body[..marked_body.len() - suffix.len()].to_string());
    }
    bail!("marked pull request body did not end with the exact effect marker");
}

impl GitPushParentObservationV1 {
    pub fn try_new(
        lookup_ref: impl Into<String>,
        observed_head_oid: impl Into<String>,
    ) -> Result<Self> {
        let value = Self {
            lookup_ref: lookup_ref.into(),
            observed_head_oid: observed_head_oid.into(),
        };
        validate_publication_ref(&value.lookup_ref, "git observation lookup ref")?;
        validate_git_oid(&value.observed_head_oid, "observed head oid")?;
        Ok(value)
    }
}

impl GithubPullRequestParentObservationV1 {
    pub fn try_new(input: GithubPullRequestParentObservationInput) -> Result<Self> {
        let value = Self {
            number: input.number,
            url: input.url,
            head_oid: input.head_oid,
            base_oid: input.base_oid,
            base_ref_name: input.base_ref_name,
            head_ref_name: input.head_ref_name,
            author: input.author,
            is_draft: input.is_draft,
            state: input.state,
        };
        if value.number == 0 {
            bail!("github pull request observation number is invalid");
        }
        validate_bounded_text(&value.url, "github pull request url", MAX_URL_BYTES, false)?;
        validate_git_oid(&value.head_oid, "observed pr head oid")?;
        validate_git_oid(&value.base_oid, "observed pr base oid")?;
        validate_bounded_text(
            &value.base_ref_name,
            "base ref name",
            MAX_BRANCH_BYTES,
            false,
        )?;
        validate_bounded_text(
            &value.head_ref_name,
            "head ref name",
            MAX_BRANCH_BYTES,
            false,
        )?;
        validate_bounded_text(&value.author, "pr author", MAX_GITHUB_LOGIN_BYTES, false)?;
        validate_bounded_text(&value.state, "pr state", MAX_BRANCH_BYTES, false)?;
        Ok(value)
    }
}

fn validate_effect_marker(marker: &str) -> Result<()> {
    let effect_id = marker
        .strip_prefix(&format!("<!-- {EXTERNAL_EFFECT_MARKER_PREFIX}:v2:"))
        .and_then(|value| value.strip_suffix(" -->"))
        .context("external effect marker was malformed")?;
    validate_effect_id(effect_id)?;
    Ok(())
}

impl ParentObservedPublicationMaterialV1 {
    pub fn try_new(
        reserve_event_nonce: impl Into<String>,
        descriptor: PublicationEffectDescriptorV1,
        observation: ParentObservedPublicationObservationV1,
    ) -> Result<Self> {
        let reserve_event_nonce = reserve_event_nonce.into();
        validate_event_nonce(&reserve_event_nonce)?;
        descriptor.validate()?;
        observation.validate_against_descriptor(&descriptor)?;
        let canonical_material_digest =
            canonical_parent_observed_digest(&reserve_event_nonce, &descriptor, &observation)?;
        let value = Self {
            schema: MATERIAL_SCHEMA.to_string(),
            version: MATERIAL_VERSION,
            reserve_event_nonce,
            descriptor,
            observation,
            canonical_material_digest,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn reserve_event_nonce(&self) -> &str {
        &self.reserve_event_nonce
    }

    pub fn descriptor(&self) -> &PublicationEffectDescriptorV1 {
        &self.descriptor
    }

    pub fn observation(&self) -> &ParentObservedPublicationObservationV1 {
        &self.observation
    }

    pub fn canonical_material_digest(&self) -> &str {
        &self.canonical_material_digest
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if self.schema != MATERIAL_SCHEMA || self.version != MATERIAL_VERSION {
            bail!("parent observed publication material has an unsupported schema or version");
        }
        validate_event_nonce(&self.reserve_event_nonce)?;
        self.descriptor.validate()?;
        self.observation
            .validate_against_descriptor(&self.descriptor)?;
        let expected = canonical_parent_observed_digest(
            &self.reserve_event_nonce,
            &self.descriptor,
            &self.observation,
        )?;
        if self.canonical_material_digest != expected {
            bail!("parent observed publication material digest is not canonical");
        }
        Ok(())
    }
}

impl ParentObservedPublicationObservationV1 {
    fn validate_against_descriptor(
        &self,
        descriptor: &PublicationEffectDescriptorV1,
    ) -> Result<()> {
        match (&self, &descriptor.operation) {
            (
                ParentObservedPublicationObservationV1::GitPush(observed),
                PublicationEffectOperationV1::GitPush(fields),
            ) => observed.validate_against(fields),
            (
                ParentObservedPublicationObservationV1::GithubPullRequest(observed),
                PublicationEffectOperationV1::GithubPullRequest(fields),
            ) => observed.validate_against(fields),
            _ => bail!("parent observation operation does not match its descriptor"),
        }
    }
}

impl GitPushParentObservationV1 {
    fn validate_against(&self, fields: &GitPushPublicationEffectFieldsV1) -> Result<()> {
        validate_publication_ref(&self.lookup_ref, "git observation lookup ref")?;
        validate_git_oid(&self.observed_head_oid, "observed head oid")?;
        if self.lookup_ref != fields.lookup_ref {
            bail!("git push observation lookup ref does not match descriptor");
        }
        if self.observed_head_oid != fields.expected_head_oid {
            bail!("git push observation head oid does not match descriptor expected head");
        }
        Ok(())
    }
}

impl GithubPullRequestParentObservationV1 {
    fn validate_against(&self, fields: &GithubPullRequestPublicationEffectFieldsV1) -> Result<()> {
        if self.number == 0 {
            bail!("github pull request observation number is invalid");
        }
        validate_bounded_text(&self.url, "github pull request url", MAX_URL_BYTES, false)?;
        validate_git_oid(&self.head_oid, "observed pr head oid")?;
        validate_git_oid(&self.base_oid, "observed pr base oid")?;
        validate_bounded_text(
            &self.base_ref_name,
            "base ref name",
            MAX_BRANCH_BYTES,
            false,
        )?;
        validate_bounded_text(
            &self.head_ref_name,
            "head ref name",
            MAX_BRANCH_BYTES,
            false,
        )?;
        validate_bounded_text(&self.author, "pr author", MAX_GITHUB_LOGIN_BYTES, false)?;
        validate_bounded_text(&self.state, "pr state", MAX_BRANCH_BYTES, false)?;
        if self.head_oid != fields.expected_head_oid {
            bail!("github pull request observation head oid does not match descriptor");
        }
        if self.base_oid != fields.expected_base_oid {
            bail!("github pull request observation base oid does not match descriptor");
        }
        if self.base_ref_name != fields.base_branch {
            bail!("github pull request observation base ref does not match descriptor");
        }
        if self.head_ref_name != fields.lookup_head_branch {
            bail!("github pull request observation head ref does not match descriptor branch");
        }
        if self.author != fields.expected_author {
            bail!("github pull request observation author does not match descriptor");
        }
        if self.is_draft != fields.draft {
            bail!("github pull request observation draft state does not match descriptor");
        }
        if self.state != "OPEN" {
            bail!("github pull request observation state is not OPEN");
        }
        Ok(())
    }
}

pub(crate) fn effect_reconciliation_is_bound(receipt: &EffectReconciliationReceipt) -> bool {
    receipt.parent_observed_material().is_some()
}

pub(crate) fn verify_bound_effect_complete_for_replay(
    _ctx: HistoricalEffectReplayContext,
    reserve_event_nonce: &str,
    descriptor: &PublicationEffectDescriptorV1,
    receipt: &EffectReconciliationReceipt,
) -> Result<()> {
    let material = receipt
        .parent_observed_material()
        .context("bound effect completion lacks parent observed material")?;
    if material.reserve_event_nonce() != reserve_event_nonce {
        bail!("bound effect completion reserve nonce does not match reservation");
    }
    if material.descriptor() != descriptor {
        bail!("bound effect completion descriptor does not match reservation");
    }
    if material.descriptor().effect_id() != receipt.effect_id() {
        bail!("bound effect completion effect id does not match reconciliation receipt");
    }
    if receipt.verified_material_sha256() != material.canonical_material_digest() {
        bail!("bound effect completion digest does not match sealed parent material");
    }
    material.validate()?;
    Ok(())
}

pub(crate) fn verify_bound_effect_complete_live(
    _ctx: LiveEffectVerificationContext,
    verifier: Option<&dyn PublicationEffectLiveVerifier>,
    owner: &CoordinationOwnerIdentity,
    reserve_event_nonce: &str,
    descriptor: &PublicationEffectDescriptorV1,
    receipt: &EffectReconciliationReceipt,
) -> Result<PublicationEffectLiveVerification> {
    verify_bound_effect_complete_for_replay(
        HistoricalEffectReplayContext::journal_replay(),
        reserve_event_nonce,
        descriptor,
        receipt,
    )?;
    let material = receipt
        .parent_observed_material()
        .expect("replay check established parent material");
    let verifier =
        verifier.context("bound effect completion requires a live publication verifier")?;
    Ok(verifier.verify_live_bound_completion(owner, descriptor, material))
}

fn canonical_parent_observed_digest(
    reserve_event_nonce: &str,
    descriptor: &PublicationEffectDescriptorV1,
    observation: &ParentObservedPublicationObservationV1,
) -> Result<String> {
    Ok(sha256_hex(
        &serde_json::to_vec(&(
            MATERIAL_SCHEMA,
            MATERIAL_VERSION,
            reserve_event_nonce,
            descriptor,
            observation,
        ))
        .context("failed to encode parent observed publication material")?,
    ))
}

fn validate_effect_id(value: &str) -> Result<()> {
    validate_sha256_hex(value, "effect id")?;
    if value.len() > MAX_EFFECT_ID_BYTES {
        bail!("effect id exceeds its byte limit");
    }
    Ok(())
}

fn validate_event_nonce(value: &str) -> Result<()> {
    validate_bounded_text(value, "event nonce", MAX_EFFECT_ID_BYTES, false)?;
    Ok(())
}

fn validate_sha256_hex(value: &str, label: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        bail!("{label} is not canonical lowercase SHA-256 hexadecimal");
    }
    Ok(())
}

fn validate_git_oid(value: &str, label: &str) -> Result<()> {
    if !matches!(value.len(), 40 | 64)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        bail!("{label} is not a canonical lowercase Git OID");
    }
    Ok(())
}

fn validate_bounded_text(value: &str, label: &str, limit: usize, allow_empty: bool) -> Result<()> {
    if value.is_empty() && !allow_empty {
        bail!("{label} must not be empty");
    }
    if value.len() > limit || value.as_bytes().contains(&0) {
        bail!("{label} exceeds its byte limit or is not canonical text");
    }
    Ok(())
}

fn validate_github_slug(value: &str, label: &str) -> Result<()> {
    validate_bounded_text(value, label, MAX_GITHUB_SLUG_BYTES, false)?;
    Ok(())
}

fn validate_publication_ref(value: &str, label: &str) -> Result<()> {
    validate_bounded_text(value, label, MAX_REF_BYTES, false)?;
    if !value.starts_with("refs/") {
        bail!("{label} must be a fully qualified git ref");
    }
    Ok(())
}

fn stable_json_digest(value: &impl Serialize) -> Result<String> {
    Ok(sha256_hex(
        &serde_json::to_vec(value).context("failed to encode stable publication binding")?,
    ))
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "snake_case")]
enum ExternalEffectOperationDigestLabel {
    GitPush,
    GithubPullRequest,
}

fn external_effect_operation_digest_label(
    operation: &PublicationEffectOperationV1,
) -> ExternalEffectOperationDigestLabel {
    match operation {
        PublicationEffectOperationV1::GitPush(_) => ExternalEffectOperationDigestLabel::GitPush,
        PublicationEffectOperationV1::GithubPullRequest(_) => {
            ExternalEffectOperationDigestLabel::GithubPullRequest
        }
    }
}

fn expected_publication_effect_id_without_source(
    descriptor: &PublicationEffectDescriptorV1,
) -> Result<String> {
    expected_publication_effect_id_without_source_parts(
        descriptor.transport_provider(),
        descriptor.repository_selector(),
        descriptor.repository_identity(),
        descriptor.operation(),
        descriptor.target_digest(),
        descriptor.payload_digest(),
    )
}

/// Canonical git-push publication descriptor shared by coordination fixtures (no source grant).
#[cfg(test)]
pub(crate) fn canonical_git_push_publication_fixture() -> Result<PublicationEffectDescriptorV1> {
    let locator = PublicationGitNetworkLocatorV1::try_new("https://github.com/acme/repo.git")?;
    let fields = GitPushPublicationEffectFieldsV1::new(
        "origin",
        locator.clone(),
        "refs/heads/maco/effects/abcd",
        "main",
        "c".repeat(40),
        "d".repeat(40),
        git_push_remote_binding_digest("origin", &locator)?,
    )?;
    let target_digest = git_push_external_effect_target_digest(
        "github.com/acme/repo",
        fields.remote_name(),
        fields.network_locator(),
        fields.base_branch(),
        fields.expected_base_oid(),
    )?;
    let payload_digest = git_push_external_effect_payload_digest(fields.expected_head_oid())?;
    let operation = PublicationEffectOperationV1::GitPush(fields.clone());
    let effect_id = expected_publication_effect_id_without_source_parts(
        "git",
        "github.com/acme/repo",
        "repo-binding",
        &operation,
        &target_digest,
        &payload_digest,
    )?;
    PublicationEffectDescriptorV1::try_new_git_push(
        PublicationEffectDescriptorBinding {
            effect_id,
            transport_provider: "git".to_string(),
            repository_selector: "github.com/acme/repo".to_string(),
            repository_identity: "repo-binding".to_string(),
            source_provenance_digest: None,
            target_digest,
            payload_digest,
        },
        fields,
    )
}

pub(crate) fn expected_publication_effect_id_without_source_parts(
    transport_provider: &str,
    repository_selector: &str,
    repository_identity: &str,
    operation: &PublicationEffectOperationV1,
    target_digest: &str,
    payload_digest: &str,
) -> Result<String> {
    let operation = external_effect_operation_digest_label(operation);
    let logical_binding = stable_json_digest(&(
        "maco_external_effect_logical_v2",
        transport_provider,
        repository_selector,
        repository_identity,
        operation.clone(),
        target_digest,
        payload_digest,
    ))?;
    stable_json_digest(&(
        "maco_external_effect_id_v2",
        logical_binding,
        operation,
        target_digest,
        payload_digest,
    ))
}

fn validate_publication_https_remote_url(remote_url: &str) -> Result<()> {
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
    if remote_url.starts_with("file://") || remote_url.starts_with('/') {
        bail!(
            "local/file publication remotes cannot be encoded as a network git locator; use canonical HTTPS"
        );
    }
    let remainder = remote_url.strip_prefix("https://").context(
        "publication supports only canonical HTTPS remotes; SSH, HTTP, git, helpers, and SCP syntax are refused",
    )?;
    let (authority, path) = remainder
        .split_once('/')
        .context("HTTPS publication remote omitted a repository path")?;
    if authority.contains('@') {
        bail!("HTTPS publication remote may not contain userinfo");
    }
    let host = normalize_publication_github_host(authority)?;
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
    Ok(())
}

fn publication_https_command_url(remote_url: &str) -> Result<String> {
    validate_publication_https_remote_url(remote_url)?;
    let remainder = remote_url
        .strip_prefix("https://")
        .expect("validated HTTPS remote");
    let (authority, path) = remainder
        .split_once('/')
        .context("HTTPS publication remote omitted a repository path")?;
    let host = normalize_publication_github_host(authority)?;
    let path = if path.ends_with(".git") {
        path.to_string()
    } else {
        format!("{path}.git")
    };
    Ok(format!("https://{host}/{path}"))
}

fn normalize_publication_github_host(host: &str) -> Result<String> {
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
        bail!("publication HTTPS host is invalid");
    }
    if hostname.split('.').any(|label| {
        label.is_empty() || label.len() > 63 || label.starts_with('-') || label.ends_with('-')
    }) {
        bail!("publication HTTPS DNS label is invalid");
    }
    let port = port
        .map(|port| {
            let parsed = port
                .parse::<u16>()
                .ok()
                .filter(|parsed| *parsed != 0)
                .context("publication HTTPS port is invalid")?;
            if port != parsed.to_string() {
                bail!("publication HTTPS port was not canonical");
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::publication::coordination_journal::{
        EffectReconciliationOutcome, EffectReconciliationReceipt,
    };

    const SAMPLE_HTTPS_REMOTE: &str = "https://github.com/acme/repo.git";

    fn sample_locator() -> PublicationGitNetworkLocatorV1 {
        PublicationGitNetworkLocatorV1::try_new(SAMPLE_HTTPS_REMOTE).expect("locator")
    }

    fn sample_git_push_fields() -> GitPushPublicationEffectFieldsV1 {
        let locator = sample_locator();
        GitPushPublicationEffectFieldsV1::new(
            "origin",
            locator,
            "refs/heads/maco/effects/abcd",
            "main",
            "c".repeat(40),
            "d".repeat(40),
            git_push_remote_binding_digest("origin", &sample_locator()).expect("binding"),
        )
        .expect("fields")
    }

    fn sample_git_descriptor() -> PublicationEffectDescriptorV1 {
        let fields = sample_git_push_fields();
        let target_digest = git_push_external_effect_target_digest(
            "github.com/acme/repo",
            fields.remote_name(),
            fields.network_locator(),
            fields.base_branch(),
            fields.expected_base_oid(),
        )
        .expect("target digest");
        let payload_digest =
            git_push_external_effect_payload_digest(fields.expected_head_oid()).expect("payload");
        let operation = PublicationEffectOperationV1::GitPush(fields.clone());
        let effect_id = expected_publication_effect_id_without_source_parts(
            "git",
            "github.com/acme/repo",
            "repo-binding",
            &operation,
            &target_digest,
            &payload_digest,
        )
        .expect("effect id");
        PublicationEffectDescriptorV1::try_new_git_push(
            PublicationEffectDescriptorBinding {
                effect_id,
                transport_provider: "git".to_string(),
                repository_selector: "github.com/acme/repo".to_string(),
                repository_identity: "repo-binding".to_string(),
                source_provenance_digest: None,
                target_digest,
                payload_digest,
            },
            fields,
        )
        .expect("descriptor")
    }

    fn sample_git_observation() -> ParentObservedPublicationObservationV1 {
        ParentObservedPublicationObservationV1::GitPush(
            GitPushParentObservationV1::try_new("refs/heads/maco/effects/abcd", "d".repeat(40))
                .expect("git observation"),
        )
    }

    fn sample_material(
        reserve_nonce: &str,
        descriptor: PublicationEffectDescriptorV1,
    ) -> ParentObservedPublicationMaterialV1 {
        ParentObservedPublicationMaterialV1::try_new(
            reserve_nonce,
            descriptor,
            sample_git_observation(),
        )
        .expect("material")
    }

    struct RecordingLiveVerifier {
        calls: std::sync::Mutex<usize>,
        outcome: PublicationEffectLiveVerification,
    }

    impl PublicationEffectLiveVerifier for RecordingLiveVerifier {
        fn verify_live_bound_completion(
            &self,
            _owner: &CoordinationOwnerIdentity,
            _descriptor: &PublicationEffectDescriptorV1,
            _material: &ParentObservedPublicationMaterialV1,
        ) -> PublicationEffectLiveVerification {
            *self.calls.lock().expect("lock") += 1;
            self.outcome
        }
    }

    #[test]
    fn fresh_host_replay_accepts_bound_completion_without_live_verifier() {
        let descriptor = sample_git_descriptor();
        let material = sample_material("evt-reserve", descriptor.clone());
        let receipt = EffectReconciliationReceipt::new_bound(
            descriptor.effect_id(),
            EffectReconciliationOutcome::Completed,
            material,
        )
        .expect("receipt");
        verify_bound_effect_complete_for_replay(
            HistoricalEffectReplayContext::journal_replay(),
            "evt-reserve",
            &descriptor,
            &receipt,
        )
        .expect("replay");
    }

    #[test]
    fn tampered_reserve_nonce_is_refused_on_replay() {
        let descriptor = sample_git_descriptor();
        let material = sample_material("evt-reserve", descriptor.clone());
        let receipt = EffectReconciliationReceipt::new_bound(
            descriptor.effect_id(),
            EffectReconciliationOutcome::Completed,
            material,
        )
        .expect("receipt");
        assert!(verify_bound_effect_complete_for_replay(
            HistoricalEffectReplayContext::journal_replay(),
            "evt-other",
            &descriptor,
            &receipt,
        )
        .is_err());
    }

    #[test]
    fn live_completion_refuses_without_verifier() {
        let descriptor = sample_git_descriptor();
        let material = sample_material("evt-reserve", descriptor.clone());
        let receipt = EffectReconciliationReceipt::new_bound(
            descriptor.effect_id(),
            EffectReconciliationOutcome::Completed,
            material,
        )
        .expect("receipt");
        let owner = CoordinationOwnerIdentity::new("run", "nonce").expect("owner");
        assert!(verify_bound_effect_complete_live(
            LiveEffectVerificationContext::admission_live(),
            None,
            &owner,
            "evt-reserve",
            &descriptor,
            &receipt,
        )
        .is_err());
    }

    #[test]
    fn live_completion_invokes_verifier_after_replay_checks() {
        let descriptor = sample_git_descriptor();
        let material = sample_material("evt-reserve", descriptor.clone());
        let receipt = EffectReconciliationReceipt::new_bound(
            descriptor.effect_id(),
            EffectReconciliationOutcome::Completed,
            material,
        )
        .expect("receipt");
        let owner = CoordinationOwnerIdentity::new("run", "nonce").expect("owner");
        let verifier = RecordingLiveVerifier {
            calls: std::sync::Mutex::new(0),
            outcome: PublicationEffectLiveVerification::Verified,
        };
        let outcome = verify_bound_effect_complete_live(
            LiveEffectVerificationContext::admission_live(),
            Some(&verifier),
            &owner,
            "evt-reserve",
            &descriptor,
            &receipt,
        )
        .expect("live");
        assert_eq!(outcome, PublicationEffectLiveVerification::Verified);
        assert_eq!(*verifier.calls.lock().expect("lock"), 1);
    }

    #[test]
    fn historical_replay_ignores_hypothetical_current_lookup_ref_drift() {
        let descriptor = sample_git_descriptor();
        let material = sample_material("evt-reserve", descriptor.clone());
        let receipt = EffectReconciliationReceipt::new_bound(
            descriptor.effect_id(),
            EffectReconciliationOutcome::Completed,
            material,
        )
        .expect("receipt");
        let mut current_descriptor = descriptor.clone();
        if let PublicationEffectOperationV1::GitPush(fields) = &mut current_descriptor.operation {
            fields.lookup_ref = "refs/heads/maco/effects/deleted".to_string();
        }
        verify_bound_effect_complete_for_replay(
            HistoricalEffectReplayContext::journal_replay(),
            "evt-reserve",
            &descriptor,
            &receipt,
        )
        .expect("sealed journal material still replays");
        assert_ne!(current_descriptor, descriptor);
    }

    #[test]
    fn fresh_host_git_push_locator_is_usable_for_read_only_observation() {
        let locator = sample_locator();
        assert_eq!(locator.observation_remote_url(), SAMPLE_HTTPS_REMOTE);
        assert_eq!(
            locator.git_command_url().expect("command url"),
            "https://github.com/acme/repo.git"
        );
        let fields = sample_git_push_fields();
        assert_eq!(
            fields.network_locator().observation_remote_url(),
            SAMPLE_HTTPS_REMOTE
        );
    }

    #[test]
    fn tampered_git_push_locator_rejects_binding_and_target_digest() {
        let locator = sample_locator();
        let bad_binding = "a".repeat(64);
        assert!(GitPushPublicationEffectFieldsV1::new(
            "origin",
            locator.clone(),
            "refs/heads/maco/effects/abcd",
            "main",
            "c".repeat(40),
            "d".repeat(40),
            bad_binding,
        )
        .is_err());
        let fields = sample_git_push_fields();
        assert!(PublicationEffectDescriptorV1::try_new_git_push(
            PublicationEffectDescriptorBinding {
                effect_id: "f".repeat(64),
                transport_provider: "git".to_string(),
                repository_selector: "github.com/acme/repo".to_string(),
                repository_identity: "repo-binding".to_string(),
                source_provenance_digest: None,
                target_digest: "a".repeat(64),
                payload_digest: "b".repeat(64),
            },
            fields,
        )
        .is_err());
    }

    #[test]
    fn forbidden_git_push_locator_forms_are_refused() {
        assert!(PublicationGitNetworkLocatorV1::try_new("file:///tmp/repo.git").is_err());
        assert!(PublicationGitNetworkLocatorV1::try_new("/bare/repo.git").is_err());
        assert!(
            PublicationGitNetworkLocatorV1::try_new("https://token@github.com/acme/repo.git")
                .is_err()
        );
        assert!(PublicationGitNetworkLocatorV1::try_new(
            "https://github.com/acme/repo.git?token=secret"
        )
        .is_err());
    }

    #[test]
    fn serde_deserialized_git_push_rejects_tampered_target_digest() {
        let descriptor = sample_git_descriptor();
        let mut wire = serde_json::to_value(&descriptor).expect("wire");
        wire["target_digest"] = serde_json::json!("a".repeat(64));
        let tampered: PublicationEffectDescriptorV1 =
            serde_json::from_value(wire).expect("deserialize");
        assert!(tampered.validate().is_err());
    }

    #[test]
    fn serde_deserialized_git_push_rejects_payload_not_matching_head_oid() {
        let descriptor = sample_git_descriptor();
        let mut wire = serde_json::to_value(&descriptor).expect("wire");
        wire["payload_digest"] = serde_json::json!("b".repeat(64));
        let tampered: PublicationEffectDescriptorV1 =
            serde_json::from_value(wire).expect("deserialize");
        assert!(tampered.validate().is_err());
    }

    #[test]
    fn serde_deserialized_git_push_rejects_tampered_effect_id() {
        let descriptor = sample_git_descriptor();
        let mut wire = serde_json::to_value(&descriptor).expect("wire");
        wire["effect_id"] = serde_json::json!("f".repeat(64));
        let tampered: PublicationEffectDescriptorV1 =
            serde_json::from_value(wire).expect("deserialize");
        assert!(tampered.validate().is_err());
    }

    #[test]
    fn serde_deserialized_pr_rejects_tampered_target_digest() {
        let target_digest = github_pull_request_external_effect_target_digest(
            "github.com/acme/repo",
            &"d".repeat(40),
            &"c".repeat(40),
            "main",
        )
        .expect("target");
        let payload_digest =
            github_pull_request_external_effect_payload_digest("title", "body", false, "bot")
                .expect("payload");
        let fields = GithubPullRequestPublicationEffectFieldsV1::new(
            GithubPullRequestPublicationEffectIdentity {
                repository_owner: "acme".to_string(),
                repository_name: "repo".to_string(),
                lookup_head_branch: "maco/effects/abcd".to_string(),
                base_branch: "main".to_string(),
                expected_base_oid: "c".repeat(40),
                expected_head_oid: "d".repeat(40),
                draft: false,
                expected_author: "bot".to_string(),
                marker: "<!-- maco-external-effect:v2:placeholder -->".to_string(),
            },
        )
        .expect("fields");
        let effect_id = expected_publication_effect_id_without_source_parts(
            "github",
            "github.com/acme/repo",
            "repo-binding",
            &PublicationEffectOperationV1::GithubPullRequest(fields.clone()),
            &target_digest,
            &payload_digest,
        )
        .expect("effect id");
        let marker = format!("<!-- maco-external-effect:v2:{effect_id} -->");
        let fields = GithubPullRequestPublicationEffectFieldsV1::new(
            GithubPullRequestPublicationEffectIdentity {
                repository_owner: "acme".to_string(),
                repository_name: "repo".to_string(),
                lookup_head_branch: "maco/effects/abcd".to_string(),
                base_branch: "main".to_string(),
                expected_base_oid: "c".repeat(40),
                expected_head_oid: "d".repeat(40),
                draft: false,
                expected_author: "bot".to_string(),
                marker,
            },
        )
        .expect("fields");
        let descriptor = PublicationEffectDescriptorV1::try_new_github_pull_request(
            PublicationEffectDescriptorBinding {
                effect_id,
                transport_provider: "github".to_string(),
                repository_selector: "github.com/acme/repo".to_string(),
                repository_identity: "repo-binding".to_string(),
                source_provenance_digest: None,
                target_digest,
                payload_digest,
            },
            fields,
        )
        .expect("descriptor");
        let mut wire = serde_json::to_value(&descriptor).expect("wire");
        wire["target_digest"] = serde_json::json!("a".repeat(64));
        let tampered: PublicationEffectDescriptorV1 =
            serde_json::from_value(wire).expect("deserialize");
        assert!(tampered.validate().is_err());
    }

    #[test]
    fn opaque_legacy_receipt_has_no_bound_material() {
        let receipt = EffectReconciliationReceipt::new(
            "effect-1",
            EffectReconciliationOutcome::Completed,
            "a".repeat(64),
        )
        .expect("legacy");
        assert!(!effect_reconciliation_is_bound(&receipt));
    }
}
