#[cfg(target_os = "linux")]
use crate::process_runner::trusted_linux_runtime_root;
#[cfg(unix)]
use crate::safe_state::device_id_to_u64;
use crate::{
    llm::Redactor,
    pinned_exec::PinnedDirectExecutable,
    process_runner::{
        run_process, EnvironmentMode, ProcessOutput, ProcessSpec, SideEffectConfinementProfile,
        StdinMode, StrictOfflineWorkspaceProfile,
    },
    safe_state::{
        remove_direct_child_tree, unsigned_to_u32, unsigned_to_u64, BoundedRegularReader,
        FileIdentity, SafeRoot, TreeLinkPolicy,
    },
};
use anyhow::{bail, Context, Result};
use serde::{de::Error as _, Deserialize, Deserializer, Serialize, Serializer};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::{OsStr, OsString},
    fs::File,
    io::{Read, Write},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

#[cfg(unix)]
use std::os::unix::{
    ffi::{OsStrExt, OsStringExt},
    fs::{MetadataExt, OpenOptionsExt},
    io::{AsRawFd, FromRawFd},
};

const REVIEW_OUTPUT_LIMIT: usize = 8 * 1024;
const REVIEW_CAPTURE_LIMIT_BYTES: usize = 4 * 1024 * 1024;
const REVIEW_JSON_LIMIT_BYTES: usize = 256 * 1024;
pub const REVIEW_LENS_REQUEST_LIMIT_BYTES: usize = 256 * 1024;
const REVIEW_INPUT_LIMIT_BYTES: usize = REVIEW_LENS_REQUEST_LIMIT_BYTES;
const REVIEW_CONFIG_LIMIT_BYTES: usize = 64 * 1024;
const REVIEW_COMMAND_LIMIT_BYTES: usize = 16 * 1024;
const REVIEW_ARG_LIMIT: usize = 128;
const REVIEW_ARG_LIMIT_BYTES: usize = 4 * 1024;
const REVIEW_TIMEOUT_LIMIT_SECONDS: u64 = 24 * 60 * 60;
const REVIEW_DEFAULT_TIMEOUT_SECONDS: u64 = 300;
const REVIEW_ATTEMPT_LIMIT: usize = 64;
const REVIEW_BLOCKING_ATTEMPTS_LIMIT: usize = 64;
const REVIEW_CHANGED_PATH_LIMIT: usize = 512;
const REVIEW_FINDING_LIMIT: usize = 128;
const REVIEW_LENS_LIMIT: usize = 64;
const REVIEW_LENS_AGGREGATE_LIMIT_BYTES: usize = 256 * 1024;
const REVIEW_PATH_LIMIT_BYTES: usize = 4 * 1024;
const REVIEW_TARGET_LIMIT_BYTES: usize = 512;
const REVIEW_SHORT_TEXT_LIMIT_BYTES: usize = 256;
const REVIEW_LONG_TEXT_LIMIT_BYTES: usize = 32 * 1024;
const REVIEW_SNAPSHOT_ENTRY_LIMIT: usize = 32 * 1024;
const REVIEW_SNAPSHOT_FILE_LIMIT_BYTES: u64 = 32 * 1024 * 1024;
const REVIEW_SNAPSHOT_TOTAL_LIMIT_BYTES: u64 = 256 * 1024 * 1024;
const REVIEW_SYMLINK_LIMIT_BYTES: usize = 4 * 1024;
const REVIEW_PREWALK_MAX_DEPTH: usize = 128;
const REVIEW_PREWALK_TIMEOUT: Duration = Duration::from_secs(5);
const REVIEW_SCHEMA_VERSION: u32 = 1;
const REVIEW_SANDBOX_POLICY_VERSION: u32 = 2;
const EXTERNAL_REVIEWER_BINDING_DOMAIN: &[u8] = b"MACO\0external-reviewer-binding\0v1\0";
const EXTERNAL_REVIEW_REQUEST_DOMAIN: &[u8] = b"MACO\0external-review-request\0v1\0";
const FAKE_REVIEW_REQUEST_DOMAIN: &[u8] = b"MACO\0fake-review-request\0v1\0";
const REVIEW_LENS_BACKEND_CONFIG_DOMAIN: &[u8] = b"MACO\0review-lens-backend-config\0v1\0";
const REVIEW_LENS_EVIDENCE_CONTENT_DOMAIN: &[u8] = b"MACO\0review-lens-evidence-content\0v1\0";
const REVIEW_LENS_REQUEST_DOMAIN: &[u8] = b"MACO\0review-lens-request\0v1\0";
const SANITIZED_REVIEW_VIEW_DOMAIN: &[u8] = b"MACO\0sanitized-review-view\0v1\0";
const REVIEW_SHA256_IDENTITY_PREFIX: &str = "sha256:";
const REVIEW_TRANSCRIPT_COMPLETE_MARKER: &str =
    "complete: authoritative transcript is reproduced in head_excerpt";
const REVIEW_TRANSCRIPT_TRUNCATED_MARKER: &str =
    "truncated: middle omitted; authoritative full transcript retained in authenticated parent artifact";

pub const DEFAULT_DIFF_REVIEW_LENS_ID: &str = "default-diff-review";
pub const DEFAULT_OUTPUT_REVIEW_LENS_ID: &str = "default-output-report-review";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReviewExecutionRuntime {
    Verified,
    #[cfg(test)]
    NonpublishableSimulation,
}

#[derive(Debug, Clone)]
pub struct ReviewPrOptions {
    pub repo: PathBuf,
    pub target: String,
    pub reviewer: ReviewerConfig,
    pub attempt: usize,
    pub changed_paths: Vec<PathBuf>,
    pub diff_summary: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReviewerConfig {
    pub mode: ReviewerMode,
    pub blocking_attempts: usize,
    pub finding: Option<FakeReviewFindingTemplate>,
    pub program: Option<PathBuf>,
    pub args: Vec<String>,
    /// Legacy shell-string input. Real external review authority rejects it.
    pub command: Option<String>,
    pub timeout_seconds: Option<u64>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ReviewerConfigWire {
    #[serde(default = "review_schema_version")]
    version: u32,
    #[serde(default)]
    mode: ReviewerMode,
    #[serde(default)]
    blocking_attempts: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    finding: Option<FakeReviewFindingTemplate>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    program: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    args: Vec<String>,
    /// Version-1 compatibility input only; external authority fails closed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    command: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    timeout_seconds: Option<u64>,
}

impl Serialize for ReviewerConfig {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        ReviewerConfigWire {
            version: REVIEW_SCHEMA_VERSION,
            mode: self.mode,
            blocking_attempts: self.blocking_attempts,
            finding: self.finding.clone(),
            program: self.program.clone(),
            args: self.args.clone(),
            command: self.command.clone(),
            timeout_seconds: self.timeout_seconds,
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ReviewerConfig {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = ReviewerConfigWire::deserialize(deserializer)?;
        if wire.version != REVIEW_SCHEMA_VERSION {
            return Err(D::Error::custom(
                "reviewer config version is unsupported; expected version 1",
            ));
        }
        Ok(Self {
            mode: wire.mode,
            blocking_attempts: wire.blocking_attempts,
            finding: wire.finding,
            program: wire.program,
            args: wire.args,
            command: wire.command,
            timeout_seconds: wire.timeout_seconds,
        })
    }
}

impl Default for ReviewerConfig {
    fn default() -> Self {
        Self {
            mode: ReviewerMode::Fake,
            blocking_attempts: 0,
            finding: None,
            program: None,
            args: Vec::new(),
            command: None,
            timeout_seconds: None,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewerMode {
    #[default]
    Fake,
    #[serde(alias = "external")]
    ExternalCommand,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FakeReviewFindingTemplate {
    pub severity: String,
    pub path: Option<PathBuf>,
    pub summary: String,
    pub suggested_fix: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct FakeReviewFindingTemplateWire {
    #[serde(default = "review_schema_version")]
    version: u32,
    #[serde(default = "default_review_severity")]
    severity: String,
    #[serde(default)]
    path: Option<PathBuf>,
    #[serde(default = "default_review_summary")]
    summary: String,
    #[serde(default = "default_suggested_fix")]
    suggested_fix: String,
}

impl Serialize for FakeReviewFindingTemplate {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        FakeReviewFindingTemplateWire {
            version: REVIEW_SCHEMA_VERSION,
            severity: self.severity.clone(),
            path: self.path.clone(),
            summary: self.summary.clone(),
            suggested_fix: self.suggested_fix.clone(),
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for FakeReviewFindingTemplate {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = FakeReviewFindingTemplateWire::deserialize(deserializer)?;
        if wire.version != REVIEW_SCHEMA_VERSION {
            return Err(D::Error::custom(
                "fake review finding version is unsupported; expected version 1",
            ));
        }
        Ok(Self {
            severity: wire.severity,
            path: wire.path,
            summary: wire.summary,
            suggested_fix: wire.suggested_fix,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct ReviewReport {
    pub version: u32,
    pub status: ReviewReportStatus,
    pub success: bool,
    pub target: String,
    pub reviewer: ReviewerIdentity,
    pub attempt: usize,
    pub request_binding: String,
    pub findings: Vec<ReviewFinding>,
    pub blocking_finding_count: usize,
    pub changed_paths: Vec<PathBuf>,
    pub diff_source: String,
    pub ci_reaction_supported: bool,
    pub ci_reaction: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub diagnostics: Option<ReviewCommandDiagnostics>,
    pub next_action: String,
}

/// In-process publication evidence issued only by the review boundary that
/// executed and verified the exact request. The authority fields remain
/// private so report JSON, test fixtures, and callers cannot manufacture real
/// publication authority from well-formed strings alone.
pub(crate) struct PublicationReviewResult {
    report: ReviewReport,
    authority: Option<BoundExternalReviewAuthority>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BoundExternalReviewAuthority {
    repo: PathBuf,
    target: String,
    reviewer: ReviewerConfig,
    attempt: usize,
    changed_paths: Vec<PathBuf>,
    diff_summary: Option<String>,
    report_version: u32,
    request_binding: String,
    reviewer_identity: ReviewerIdentity,
}

impl PublicationReviewResult {
    pub(crate) fn into_report(self) -> ReviewReport {
        self.report
    }

    pub(crate) fn has_exact_external_authority(&self, expected: &ReviewPrOptions) -> bool {
        let Some(authority) = &self.authority else {
            return false;
        };
        expected.reviewer.mode == ReviewerMode::ExternalCommand
            && authority.repo == expected.repo
            && authority.target == expected.target
            && authority.reviewer == expected.reviewer
            && authority.attempt == expected.attempt
            && authority.changed_paths == expected.changed_paths
            && authority.diff_summary == expected.diff_summary
            && self.report.version == authority.report_version
            && self.report.target == authority.target
            && self.report.attempt == authority.attempt
            && self.report.changed_paths == authority.changed_paths
            && self.report.request_binding == authority.request_binding
            && self.report.reviewer == authority.reviewer_identity
    }

    #[cfg(test)]
    pub(crate) fn issue_for_test(
        options: ReviewPrOptions,
        report: ReviewReport,
        external_authority: bool,
    ) -> Self {
        let authority = external_authority
            .then(|| BoundExternalReviewAuthority::from_verified(&options, &report));
        Self { report, authority }
    }
}

impl BoundExternalReviewAuthority {
    fn from_verified(options: &ReviewPrOptions, report: &ReviewReport) -> Self {
        Self {
            repo: options.repo.clone(),
            target: options.target.clone(),
            reviewer: options.reviewer.clone(),
            attempt: options.attempt,
            changed_paths: options.changed_paths.clone(),
            diff_summary: options.diff_summary.clone(),
            report_version: report.version,
            request_binding: report.request_binding.clone(),
            reviewer_identity: report.reviewer.clone(),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct ReviewCommandDiagnostics {
    pub timed_out: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_seconds: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    pub stdout: ReviewOutputSummary,
    pub stderr: ReviewOutputSummary,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process_error: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct ReviewOutputSummary {
    pub text: String,
    pub truncated: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewReportStatus {
    Passed,
    Blocked,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct ReviewerIdentity {
    pub mode: ReviewerMode,
    pub reviewer_id: String,
    pub model: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct ReviewFinding {
    pub severity: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<PathBuf>,
    pub summary: String,
    pub suggested_fix: String,
    pub blocking: bool,
}

/// A reusable review lens with an explicit backend/model selection and a
/// confidentiality-bounded information scope.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewLensConfig {
    pub id: String,
    pub backend: ReviewLensBackendConfig,
    pub information_scope: ReviewInformationScope,
}

/// The execution source for a review lens.
///
/// Model-backed lenses are dispatched by the supervisor's model runtime, with
/// every executable selection represented directly on the variant. The
/// autopilot-oriented [`ReviewerConfig`] is deliberately absent: its fake and
/// direct-program modes are not executable through this boundary. Precomputed
/// lenses let independently verified evidence, such as future process evidence,
/// participate in the same aggregation without pretending that it was produced
/// by a model invocation.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, tag = "kind", rename_all = "snake_case")]
pub enum ReviewLensBackendConfig {
    Model {
        backend_id: String,
        model: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reasoning_effort: Option<String>,
    },
    Precomputed {
        backend_id: String,
        model: String,
        evidence_kind: ReviewLensEvidenceKind,
    },
}

impl ReviewLensBackendConfig {
    pub fn backend_id(&self) -> &str {
        match self {
            Self::Model { backend_id, .. } | Self::Precomputed { backend_id, .. } => backend_id,
        }
    }

    pub fn model(&self) -> &str {
        match self {
            Self::Model { model, .. } | Self::Precomputed { model, .. } => model,
        }
    }

    pub fn reasoning_effort(&self) -> Option<&str> {
        match self {
            Self::Model {
                reasoning_effort, ..
            } => reasoning_effort.as_deref(),
            Self::Precomputed { .. } => None,
        }
    }

    fn expected_evidence_kind(&self) -> ReviewLensEvidenceKind {
        match self {
            Self::Model { .. } => ReviewLensEvidenceKind::ModelReview,
            Self::Precomputed { evidence_kind, .. } => *evidence_kind,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewInformationScope {
    FullChildTranscript,
    DiffOnly,
    OutputReportOnly,
}

/// Unscoped parent-side inputs. This type is deliberately not serializable;
/// callers must first convert it to [`ReviewLensRequest`] through
/// [`build_review_lens_request`].
#[derive(Debug, Clone, Copy)]
pub struct ReviewLensRequestSources<'a> {
    pub child_transcript: &'a str,
    pub diff: &'a str,
    pub output_report: &'a str,
}

/// Exact supervisor bindings that must accompany a bounded full-transcript
/// review. `serde_json::Value` keeps this review-layer type independent of the
/// supervisor's report and candidate types while retaining their complete,
/// canonical serialized representations.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewLensBindingMaterial {
    pub candidate_binding: serde_json::Value,
    pub path_bindings: serde_json::Value,
    pub validation_bindings: serde_json::Value,
}

/// Parent-authenticated transcript input used to construct a bounded request.
///
/// The caller remains responsible for authenticating `child_transcript`
/// against the retained artifact before calling this constructor. The artifact
/// path is carried into the request so the digest and length remain tied to the
/// separately retained authority rather than being mistaken for a complete
/// inline transcript.
#[derive(Debug, Clone, Copy)]
pub(crate) struct BoundedReviewLensRequestSources<'a> {
    pub child_transcript: &'a str,
    pub authoritative_transcript_path: &'a Path,
    pub diff: &'a str,
    pub output_report: &'a str,
    pub bindings: &'a ReviewLensBindingMaterial,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BoundedReviewTranscript {
    pub authoritative_artifact: PathBuf,
    pub original_bytes: u64,
    pub sha256: String,
    pub truncated: bool,
    pub omitted_bytes: u64,
    pub truncation_marker: String,
    pub head_excerpt: String,
    pub tail_excerpt: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewLensRequest {
    #[serde(deserialize_with = "deserialize_review_schema_version")]
    pub version: u32,
    pub lens_id: String,
    pub backend_id: String,
    pub model: String,
    pub request_binding: String,
    pub information: ReviewLensScopedInformation,
}

/// The only review material that crosses a lens boundary.
///
/// The narrow variants do not contain optional fields for excluded material.
/// Their serialized representation therefore cannot disclose a transcript or
/// report merely because a caller populated the parent-side sources.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, tag = "scope", rename_all = "snake_case")]
pub enum ReviewLensScopedInformation {
    FullChildTranscript {
        child_transcript: String,
        diff: String,
        output_report: String,
    },
    BoundedFullChildTranscript {
        child_transcript: Box<BoundedReviewTranscript>,
        bindings: ReviewLensBindingMaterial,
        diff: String,
        output_report: String,
    },
    DiffOnly {
        diff: String,
    },
    OutputReportOnly {
        output_report: String,
    },
}

impl ReviewLensScopedInformation {
    pub fn scope(&self) -> ReviewInformationScope {
        match self {
            Self::FullChildTranscript { .. } | Self::BoundedFullChildTranscript { .. } => {
                ReviewInformationScope::FullChildTranscript
            }
            Self::DiffOnly { .. } => ReviewInformationScope::DiffOnly,
            Self::OutputReportOnly { .. } => ReviewInformationScope::OutputReportOnly,
        }
    }
}

#[derive(Serialize)]
struct ReviewLensRequestBindingPayload<'a> {
    version: u32,
    lens: &'a ReviewLensDescriptor,
    backend_configuration_id: &'a str,
    information: &'a ReviewLensScopedInformation,
}

pub fn build_review_lens_request(
    lens: &ReviewLensConfig,
    sources: ReviewLensRequestSources<'_>,
) -> Result<ReviewLensRequest> {
    validate_review_lens_config(lens)?;
    if matches!(lens.backend, ReviewLensBackendConfig::Precomputed { .. }) {
        bail!("precomputed review lenses do not receive model request material");
    }
    validate_review_lens_selected_input(lens.information_scope, sources)?;
    let information = match lens.information_scope {
        ReviewInformationScope::FullChildTranscript => {
            ReviewLensScopedInformation::FullChildTranscript {
                child_transcript: sources.child_transcript.to_string(),
                diff: sources.diff.to_string(),
                output_report: sources.output_report.to_string(),
            }
        }
        ReviewInformationScope::DiffOnly => ReviewLensScopedInformation::DiffOnly {
            diff: sources.diff.to_string(),
        },
        ReviewInformationScope::OutputReportOnly => ReviewLensScopedInformation::OutputReportOnly {
            output_report: sources.output_report.to_string(),
        },
    };
    build_review_lens_request_from_information(lens, information)
}

/// Constructs the bounded full-transcript representation used at the parent
/// review boundary. Required report, diff, candidate, path, and validation
/// material is never shortened. If that material plus transcript
/// authentication metadata cannot fit, construction fails closed. Otherwise
/// the largest deterministic, balanced UTF-8 head/tail excerpt that fits is
/// selected by serialized request size.
pub(crate) fn build_bounded_review_lens_request(
    lens: &ReviewLensConfig,
    sources: BoundedReviewLensRequestSources<'_>,
) -> Result<ReviewLensRequest> {
    validate_review_lens_config(lens)?;
    if matches!(lens.backend, ReviewLensBackendConfig::Precomputed { .. }) {
        bail!("precomputed review lenses do not receive model request material");
    }
    if lens.information_scope != ReviewInformationScope::FullChildTranscript {
        return build_review_lens_request(
            lens,
            ReviewLensRequestSources {
                child_transcript: sources.child_transcript,
                diff: sources.diff,
                output_report: sources.output_report,
            },
        );
    }
    validate_repo_relative_path(
        sources.authoritative_transcript_path,
        "authoritative review transcript artifact",
    )?;
    validate_review_lens_binding_material(sources.bindings)?;
    let sha256 = sha256_hex(sources.child_transcript.as_bytes());

    let complete = bounded_review_transcript(
        sources.child_transcript,
        sources.authoritative_transcript_path,
        &sha256,
        sources.child_transcript.len(),
        false,
    )?;
    if let Ok(request) = build_bounded_review_lens_request_with_transcript(lens, sources, complete)
    {
        return Ok(request);
    }

    let minimal = bounded_review_transcript(
        sources.child_transcript,
        sources.authoritative_transcript_path,
        &sha256,
        0,
        true,
    )?;
    let mut best = build_bounded_review_lens_request_with_transcript(lens, sources, minimal)
        .with_context(|| {
            format!(
                "required review report and candidate/path/validation bindings cannot fit or authenticate within the {} byte review-lens request limit",
                REVIEW_INPUT_LIMIT_BYTES
            )
        })?;

    let mut low = 0usize;
    let mut high = sources.child_transcript.len().saturating_sub(1);
    while low < high {
        let middle = low + (high - low).div_ceil(2);
        let transcript = bounded_review_transcript(
            sources.child_transcript,
            sources.authoritative_transcript_path,
            &sha256,
            middle,
            true,
        )?;
        match build_bounded_review_lens_request_with_transcript(lens, sources, transcript) {
            Ok(request) => {
                low = middle;
                best = request;
            }
            Err(_) => high = middle.saturating_sub(1),
        }
    }
    Ok(best)
}

fn build_bounded_review_lens_request_with_transcript(
    lens: &ReviewLensConfig,
    sources: BoundedReviewLensRequestSources<'_>,
    child_transcript: BoundedReviewTranscript,
) -> Result<ReviewLensRequest> {
    build_review_lens_request_from_information(
        lens,
        ReviewLensScopedInformation::BoundedFullChildTranscript {
            child_transcript: Box::new(child_transcript),
            bindings: sources.bindings.clone(),
            diff: sources.diff.to_string(),
            output_report: sources.output_report.to_string(),
        },
    )
}

fn bounded_review_transcript(
    transcript: &str,
    authoritative_artifact: &Path,
    sha256: &str,
    excerpt_byte_budget: usize,
    truncated: bool,
) -> Result<BoundedReviewTranscript> {
    let (head_excerpt, tail_excerpt) = if truncated {
        bounded_head_tail_excerpt(transcript, excerpt_byte_budget)
    } else {
        (transcript, "")
    };
    let excerpt_bytes = head_excerpt
        .len()
        .checked_add(tail_excerpt.len())
        .context("bounded review transcript excerpt byte length overflow")?;
    let omitted_bytes = transcript
        .len()
        .checked_sub(excerpt_bytes)
        .context("bounded review transcript excerpts overlap")?;
    Ok(BoundedReviewTranscript {
        authoritative_artifact: authoritative_artifact.to_path_buf(),
        original_bytes: u64::try_from(transcript.len())
            .context("authoritative review transcript byte length overflow")?,
        sha256: sha256.to_string(),
        truncated,
        omitted_bytes: u64::try_from(omitted_bytes)
            .context("omitted review transcript byte length overflow")?,
        truncation_marker: if truncated {
            REVIEW_TRANSCRIPT_TRUNCATED_MARKER
        } else {
            REVIEW_TRANSCRIPT_COMPLETE_MARKER
        }
        .to_string(),
        head_excerpt: head_excerpt.to_string(),
        tail_excerpt: tail_excerpt.to_string(),
    })
}

fn bounded_head_tail_excerpt(transcript: &str, byte_budget: usize) -> (&str, &str) {
    let byte_budget = byte_budget.min(transcript.len());
    let mut head_end = byte_budget.div_ceil(2);
    while !transcript.is_char_boundary(head_end) {
        head_end -= 1;
    }
    let mut tail_start = transcript.len().saturating_sub(byte_budget / 2);
    while !transcript.is_char_boundary(tail_start) {
        tail_start += 1;
    }
    debug_assert!(head_end <= tail_start);
    (&transcript[..head_end], &transcript[tail_start..])
}

fn validate_review_lens_binding_material(bindings: &ReviewLensBindingMaterial) -> Result<()> {
    for (label, value) in [
        ("candidate binding", &bindings.candidate_binding),
        ("path bindings", &bindings.path_bindings),
        ("validation bindings", &bindings.validation_bindings),
    ] {
        if !value.is_object() {
            bail!("review lens {label} must be a complete JSON object");
        }
    }
    Ok(())
}

fn build_review_lens_request_from_information(
    lens: &ReviewLensConfig,
    information: ReviewLensScopedInformation,
) -> Result<ReviewLensRequest> {
    let descriptor = ReviewLensDescriptor::from(lens);
    let backend_configuration_id = review_lens_backend_configuration_id(&lens.backend)?;
    let binding_payload = serde_json::to_vec(&ReviewLensRequestBindingPayload {
        version: REVIEW_SCHEMA_VERSION,
        lens: &descriptor,
        backend_configuration_id: &backend_configuration_id,
        information: &information,
    })
    .context("failed to serialize review lens request identity")?;
    if binding_payload.len() > REVIEW_INPUT_LIMIT_BYTES {
        bail!(
            "review lens scoped request payload exceeds its {} byte limit",
            REVIEW_INPUT_LIMIT_BYTES
        );
    }
    let request_binding = domain_sha256(REVIEW_LENS_REQUEST_DOMAIN, &binding_payload);
    let request = ReviewLensRequest {
        version: REVIEW_SCHEMA_VERSION,
        lens_id: descriptor.id,
        backend_id: descriptor.backend_id,
        model: descriptor.model,
        request_binding,
        information,
    };
    let serialized =
        serde_json::to_vec(&request).context("failed to serialize bounded review lens request")?;
    if serialized.len() > REVIEW_INPUT_LIMIT_BYTES {
        bail!(
            "review lens scoped request exceeds its {} byte limit",
            REVIEW_INPUT_LIMIT_BYTES
        );
    }
    Ok(request)
}

#[cfg(test)]
pub(crate) fn review_lens_request_binding_payload_len_for_test(
    lens: &ReviewLensConfig,
    information: &ReviewLensScopedInformation,
) -> Result<usize> {
    validate_review_lens_config(lens)?;
    let descriptor = ReviewLensDescriptor::from(lens);
    let backend_configuration_id = review_lens_backend_configuration_id(&lens.backend)?;
    Ok(serde_json::to_vec(&ReviewLensRequestBindingPayload {
        version: REVIEW_SCHEMA_VERSION,
        lens: &descriptor,
        backend_configuration_id: &backend_configuration_id,
        information,
    })
    .context("failed to serialize review lens request identity for boundary test")?
    .len())
}

fn validate_review_lens_selected_input(
    scope: ReviewInformationScope,
    sources: ReviewLensRequestSources<'_>,
) -> Result<()> {
    let included_bytes = match scope {
        ReviewInformationScope::FullChildTranscript => sources
            .child_transcript
            .len()
            .checked_add(sources.diff.len())
            .and_then(|total| total.checked_add(sources.output_report.len())),
        ReviewInformationScope::DiffOnly => Some(sources.diff.len()),
        ReviewInformationScope::OutputReportOnly => Some(sources.output_report.len()),
    }
    .context("review lens scoped input byte total overflow")?;
    if included_bytes > REVIEW_INPUT_LIMIT_BYTES {
        bail!(
            "review lens scoped input exceeds its {} byte limit",
            REVIEW_INPUT_LIMIT_BYTES
        );
    }
    Ok(())
}

/// Cheap local scope templates. Neither lens receives the full child
/// transcript, but both use the same deterministic local backend label and are
/// not independent production authorities. Integrations must replace their
/// backend/model selections before treating them as authoritative lenses.
pub fn cheap_default_review_lenses() -> Vec<ReviewLensConfig> {
    let backend = || ReviewLensBackendConfig::Model {
        backend_id: "deterministic-local-reviewer".to_string(),
        model: "deterministic-local-reviewer".to_string(),
        reasoning_effort: None,
    };
    vec![
        ReviewLensConfig {
            id: DEFAULT_DIFF_REVIEW_LENS_ID.to_string(),
            backend: backend(),
            information_scope: ReviewInformationScope::DiffOnly,
        },
        ReviewLensConfig {
            id: DEFAULT_OUTPUT_REVIEW_LENS_ID.to_string(),
            backend: backend(),
            information_scope: ReviewInformationScope::OutputReportOnly,
        },
    ]
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewLensEvidenceKind {
    ModelReview,
    ProcessEvidence,
    ExternalValidation,
}

/// Public-safe identity for a configured lens. Execution configuration such as
/// reviewer programs, arguments, and fake findings remains parent-private.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewLensDescriptor {
    pub id: String,
    pub backend_id: String,
    pub model: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reasoning_effort: Option<String>,
    pub information_scope: ReviewInformationScope,
    pub expected_evidence_kind: ReviewLensEvidenceKind,
}

impl ReviewLensDescriptor {
    fn from_config(lens: &ReviewLensConfig) -> Self {
        Self {
            id: lens.id.clone(),
            backend_id: lens.backend.backend_id().to_string(),
            model: lens.backend.model().to_string(),
            reasoning_effort: lens.backend.reasoning_effort().map(str::to_string),
            information_scope: lens.information_scope,
            expected_evidence_kind: lens.backend.expected_evidence_kind(),
        }
    }
}

impl From<&ReviewLensConfig> for ReviewLensDescriptor {
    fn from(lens: &ReviewLensConfig) -> Self {
        Self::from_config(lens)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReviewLensEvidence {
    pub kind: ReviewLensEvidenceKind,
    /// Parent-normalized content identity in `sha256:<64 lowercase hex>` form.
    /// It is a consistency identity, not evidence-producer authentication.
    pub binding: String,
    pub lens: ReviewLensDescriptor,
    pub backend_configuration_id: String,
    pub request_binding: String,
    pub coverage: ReviewLensCoverage,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReviewLensEvidenceWire {
    kind: ReviewLensEvidenceKind,
    binding: String,
    lens: ReviewLensDescriptor,
    backend_configuration_id: String,
    request_binding: String,
    coverage: ReviewLensCoverage,
}

#[derive(Serialize)]
struct ReviewLensEvidenceWireRef<'a> {
    kind: ReviewLensEvidenceKind,
    binding: &'a str,
    lens: &'a ReviewLensDescriptor,
    backend_configuration_id: &'a str,
    request_binding: &'a str,
    coverage: &'a ReviewLensCoverage,
}

impl Serialize for ReviewLensEvidence {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        validate_review_evidence(self).map_err(serde::ser::Error::custom)?;
        ReviewLensEvidenceWireRef {
            kind: self.kind,
            binding: &self.binding,
            lens: &self.lens,
            backend_configuration_id: &self.backend_configuration_id,
            request_binding: &self.request_binding,
            coverage: &self.coverage,
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ReviewLensEvidence {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = ReviewLensEvidenceWire::deserialize(deserializer)?;
        let evidence = Self {
            kind: wire.kind,
            binding: wire.binding,
            lens: wire.lens,
            backend_configuration_id: wire.backend_configuration_id,
            request_binding: wire.request_binding,
            coverage: wire.coverage,
        };
        validate_review_evidence(&evidence).map_err(D::Error::custom)?;
        Ok(evidence)
    }
}

impl ReviewLensEvidence {
    pub fn for_lens(
        lens: &ReviewLensConfig,
        kind: ReviewLensEvidenceKind,
        evidence_content: String,
        request_binding: String,
        coverage: ReviewLensCoverage,
    ) -> Result<Self> {
        validate_review_lens_config(lens)?;
        let binding = review_lens_evidence_content_identity(&evidence_content)?;
        let evidence = Self {
            kind,
            binding,
            lens: ReviewLensDescriptor::from(lens),
            backend_configuration_id: review_lens_backend_configuration_id(&lens.backend)?,
            request_binding,
            coverage,
        };
        validate_review_evidence(&evidence)?;
        Ok(evidence)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewLensCoverage {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub worker_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub paths: Vec<PathBuf>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewCoverageRequirement {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub worker_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub paths: Vec<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewLensVerdictStatus {
    Accept,
    Reject,
    ProceduralFailure,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewLensVerdict {
    /// Stable routing id used to associate a returned verdict with its
    /// configured lens. The separately reported descriptor is validated
    /// against that configuration.
    pub lens_id: String,
    pub lens: ReviewLensDescriptor,
    pub request_binding: String,
    pub verdict: ReviewLensVerdictStatus,
    pub coverage: ReviewLensCoverage,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<ReviewLensEvidence>,
}

impl ReviewLensVerdict {
    pub fn for_lens(
        lens: &ReviewLensConfig,
        request_binding: String,
        verdict: ReviewLensVerdictStatus,
        coverage: ReviewLensCoverage,
        evidence: Vec<(ReviewLensEvidenceKind, String)>,
    ) -> Result<Self> {
        validate_review_lens_config(lens)?;
        validate_review_digest_identity(&request_binding, "review lens request binding")?;
        validate_review_coverage_metadata(&coverage, "review lens verdict coverage")?;
        if evidence.len() > REVIEW_FINDING_LIMIT {
            bail!("review lens evidence exceeds its item limit");
        }
        if verdict != ReviewLensVerdictStatus::ProceduralFailure
            && !evidence
                .iter()
                .any(|(kind, _)| *kind == lens.backend.expected_evidence_kind())
        {
            bail!("review lens verdict lacks its configured evidence kind");
        }
        let evidence = evidence
            .into_iter()
            .map(|(kind, binding)| {
                ReviewLensEvidence::for_lens(
                    lens,
                    kind,
                    binding,
                    request_binding.clone(),
                    coverage.clone(),
                )
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            lens_id: lens.id.clone(),
            lens: ReviewLensDescriptor::from(lens),
            request_binding,
            verdict,
            coverage,
            evidence,
        })
    }

    fn missing(lens: &ReviewLensConfig) -> Self {
        Self {
            lens_id: lens.id.clone(),
            lens: ReviewLensDescriptor::from(lens),
            request_binding: String::new(),
            verdict: ReviewLensVerdictStatus::ProceduralFailure,
            coverage: ReviewLensCoverage::default(),
            evidence: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, tag = "kind", rename_all = "snake_case")]
pub enum ReviewAggregationPolicy {
    #[default]
    AllMustAccept,
    ValidatedQuorum {
        minimum_accepts: usize,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewAggregationDecision {
    Accept,
    Reject,
    ProceduralFailure,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AggregatedReviewLensVerdict {
    pub lens: ReviewLensDescriptor,
    pub reported: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_binding: Option<String>,
    pub reported_verdict: ReviewLensVerdictStatus,
    pub effective_verdict: ReviewLensVerdictStatus,
    pub coverage: ReviewLensCoverage,
    pub evidence: Vec<ReviewLensEvidence>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub validation_errors: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReviewLensAggregateAuthority {
    ParentComputed,
    DeserializedNonAuthoritative,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReviewLensAggregate {
    pub version: u32,
    pub policy: ReviewAggregationPolicy,
    pub decision: ReviewAggregationDecision,
    pub required_accepts: usize,
    pub validated_accepts: usize,
    pub rejected_lenses: usize,
    pub procedural_failures: usize,
    pub required_coverage: ReviewCoverageRequirement,
    pub lens_verdicts: Vec<AggregatedReviewLensVerdict>,
    authority: ReviewLensAggregateAuthority,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReviewLensAggregateWire {
    #[serde(deserialize_with = "deserialize_review_schema_version")]
    version: u32,
    policy: ReviewAggregationPolicy,
    decision: ReviewAggregationDecision,
    required_accepts: usize,
    validated_accepts: usize,
    rejected_lenses: usize,
    procedural_failures: usize,
    required_coverage: ReviewCoverageRequirement,
    lens_verdicts: Vec<AggregatedReviewLensVerdict>,
}

#[derive(Serialize)]
struct ReviewLensAggregateWireRef<'a> {
    version: u32,
    policy: &'a ReviewAggregationPolicy,
    decision: &'a ReviewAggregationDecision,
    required_accepts: usize,
    validated_accepts: usize,
    rejected_lenses: usize,
    procedural_failures: usize,
    required_coverage: &'a ReviewCoverageRequirement,
    lens_verdicts: &'a [AggregatedReviewLensVerdict],
}

impl ReviewLensAggregate {
    pub fn authority(&self) -> ReviewLensAggregateAuthority {
        self.authority
    }

    fn wire(&self) -> ReviewLensAggregateWireRef<'_> {
        ReviewLensAggregateWireRef {
            version: self.version,
            policy: &self.policy,
            decision: &self.decision,
            required_accepts: self.required_accepts,
            validated_accepts: self.validated_accepts,
            rejected_lenses: self.rejected_lenses,
            procedural_failures: self.procedural_failures,
            required_coverage: &self.required_coverage,
            lens_verdicts: &self.lens_verdicts,
        }
    }
}

impl<'de> Deserialize<'de> for ReviewLensAggregate {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = ReviewLensAggregateWire::deserialize(deserializer)?;
        Ok(Self {
            version: wire.version,
            policy: wire.policy,
            decision: wire.decision,
            required_accepts: wire.required_accepts,
            validated_accepts: wire.validated_accepts,
            rejected_lenses: wire.rejected_lenses,
            procedural_failures: wire.procedural_failures,
            required_coverage: wire.required_coverage,
            lens_verdicts: wire.lens_verdicts,
            authority: ReviewLensAggregateAuthority::DeserializedNonAuthoritative,
        })
    }
}

impl Serialize for ReviewLensAggregate {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        validate_public_review_lens_aggregate_size(self).map_err(serde::ser::Error::custom)?;
        self.wire().serialize(serializer)
    }
}

pub fn aggregate_review_lenses(
    lenses: &[ReviewLensConfig],
    policy: ReviewAggregationPolicy,
    required_coverage: ReviewCoverageRequirement,
    verdicts: Vec<ReviewLensVerdict>,
) -> Result<ReviewLensAggregate> {
    aggregate_review_lenses_internal(lenses, policy, required_coverage, verdicts, None)
}

pub fn aggregate_review_lenses_against_requests(
    lenses: &[ReviewLensConfig],
    expected_requests: &[ReviewLensRequest],
    policy: ReviewAggregationPolicy,
    required_coverage: ReviewCoverageRequirement,
    verdicts: Vec<ReviewLensVerdict>,
) -> Result<ReviewLensAggregate> {
    validate_review_lens_set(lenses)?;
    if expected_requests.len() != lenses.len() {
        bail!("expected review lens requests must cover every configured lens exactly once");
    }
    let configured = lenses
        .iter()
        .map(|lens| (lens.id.as_str(), lens))
        .collect::<BTreeMap<_, _>>();
    let mut bindings = BTreeMap::new();
    for request in expected_requests {
        let lens = configured.get(request.lens_id.as_str()).with_context(|| {
            format!(
                "expected review lens request references unconfigured lens '{}'",
                request.lens_id
            )
        })?;
        if request.backend_id != lens.backend.backend_id()
            || request.model != lens.backend.model()
            || request.information.scope() != lens.information_scope
        {
            bail!(
                "expected review lens request '{}' does not match its parent configuration",
                request.lens_id
            );
        }
        validate_review_digest_identity(
            &request.request_binding,
            "expected review lens request binding",
        )?;
        if bindings
            .insert(request.lens_id.as_str(), request.request_binding.as_str())
            .is_some()
        {
            bail!("expected review lens requests contain a duplicate lens id");
        }
    }
    aggregate_review_lenses_internal(lenses, policy, required_coverage, verdicts, Some(&bindings))
}

fn aggregate_review_lenses_internal(
    lenses: &[ReviewLensConfig],
    policy: ReviewAggregationPolicy,
    required_coverage: ReviewCoverageRequirement,
    verdicts: Vec<ReviewLensVerdict>,
    expected_request_bindings: Option<&BTreeMap<&str, &str>>,
) -> Result<ReviewLensAggregate> {
    validate_review_lens_set(lenses)?;
    validate_review_coverage_requirement(&required_coverage)?;
    if verdicts.len() > REVIEW_LENS_LIMIT {
        bail!(
            "review lens verdict list exceeds its {} item limit",
            REVIEW_LENS_LIMIT
        );
    }
    let required_accepts = match policy {
        ReviewAggregationPolicy::AllMustAccept => lenses.len(),
        ReviewAggregationPolicy::ValidatedQuorum { minimum_accepts } => {
            if minimum_accepts == 0 || minimum_accepts > lenses.len() {
                bail!("validated review quorum must be between 1 and the configured lens count");
            }
            minimum_accepts
        }
    };

    let mut verdicts_by_id = BTreeMap::new();
    for verdict in verdicts {
        validate_review_lens_id(&verdict.lens_id, "review lens verdict id")?;
        if verdicts_by_id
            .insert(verdict.lens_id.clone(), verdict)
            .is_some()
        {
            bail!("review lens verdicts contain a duplicate lens id");
        }
    }
    let configured_ids = lenses
        .iter()
        .map(|lens| lens.id.as_str())
        .collect::<BTreeSet<_>>();
    if let Some(unknown) = verdicts_by_id
        .keys()
        .find(|lens_id| !configured_ids.contains(lens_id.as_str()))
    {
        bail!("review lens verdict references unconfigured lens '{unknown}'");
    }

    let mut lens_verdicts = Vec::with_capacity(lenses.len());
    for lens in lenses {
        let (reported, mut verdict, mut validation_errors) =
            if let Some(verdict) = verdicts_by_id.remove(&lens.id) {
                let errors = review_lens_verdict_errors(
                    lens,
                    &required_coverage,
                    &verdict,
                    expected_request_bindings
                        .and_then(|bindings| bindings.get(lens.id.as_str()).copied()),
                );
                (true, verdict, errors)
            } else {
                (
                    false,
                    ReviewLensVerdict::missing(lens),
                    vec!["review lens did not report a verdict".to_string()],
                )
            };
        let effective_verdict = if validation_errors.is_empty() {
            verdict.verdict
        } else {
            validation_errors.sort();
            validation_errors.dedup();
            ReviewLensVerdictStatus::ProceduralFailure
        };
        let request_binding = (reported
            && validate_review_digest_identity(
                &verdict.request_binding,
                "review lens request binding",
            )
            .is_ok())
        .then(|| verdict.request_binding.clone());
        let coverage =
            if validate_review_coverage_metadata(&verdict.coverage, "review lens coverage").is_ok()
            {
                verdict.coverage.clone()
            } else {
                ReviewLensCoverage::default()
            };
        let evidence = public_safe_review_lens_evidence(lens, &mut verdict);
        lens_verdicts.push(AggregatedReviewLensVerdict {
            lens: ReviewLensDescriptor::from(lens),
            reported,
            request_binding,
            reported_verdict: verdict.verdict,
            effective_verdict,
            coverage,
            evidence,
            validation_errors,
        });
    }

    let validated_accepts = lens_verdicts
        .iter()
        .filter(|verdict| verdict.effective_verdict == ReviewLensVerdictStatus::Accept)
        .count();
    let rejected_lenses = lens_verdicts
        .iter()
        .filter(|verdict| verdict.effective_verdict == ReviewLensVerdictStatus::Reject)
        .count();
    let procedural_failures = lens_verdicts
        .iter()
        .filter(|verdict| verdict.effective_verdict == ReviewLensVerdictStatus::ProceduralFailure)
        .count();
    let decision = match policy {
        ReviewAggregationPolicy::AllMustAccept => {
            if procedural_failures > 0 {
                ReviewAggregationDecision::ProceduralFailure
            } else if rejected_lenses > 0 {
                ReviewAggregationDecision::Reject
            } else {
                ReviewAggregationDecision::Accept
            }
        }
        ReviewAggregationPolicy::ValidatedQuorum { .. } => {
            if validated_accepts >= required_accepts {
                ReviewAggregationDecision::Accept
            } else if validated_accepts.saturating_add(procedural_failures) >= required_accepts {
                ReviewAggregationDecision::ProceduralFailure
            } else {
                ReviewAggregationDecision::Reject
            }
        }
    };

    let aggregate = ReviewLensAggregate {
        version: REVIEW_SCHEMA_VERSION,
        policy,
        decision,
        required_accepts,
        validated_accepts,
        rejected_lenses,
        procedural_failures,
        required_coverage,
        lens_verdicts,
        authority: ReviewLensAggregateAuthority::ParentComputed,
    };
    validate_public_review_lens_aggregate_size(&aggregate)?;
    Ok(aggregate)
}

struct ReviewLensAggregateSizeWriter {
    bytes_written: usize,
    exceeded: bool,
}

impl Write for ReviewLensAggregateSizeWriter {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        let Some(next_size) = self.bytes_written.checked_add(buffer.len()) else {
            self.exceeded = true;
            return Err(std::io::Error::other("review lens aggregate size overflow"));
        };
        if next_size > REVIEW_LENS_AGGREGATE_LIMIT_BYTES {
            self.exceeded = true;
            return Err(std::io::Error::other(
                "review lens aggregate output limit exceeded",
            ));
        }
        self.bytes_written = next_size;
        Ok(buffer.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn validate_public_review_lens_aggregate_size(aggregate: &ReviewLensAggregate) -> Result<()> {
    let mut writer = ReviewLensAggregateSizeWriter {
        bytes_written: 0,
        exceeded: false,
    };
    let result = serde_json::to_writer(&mut writer, &aggregate.wire());
    if writer.exceeded {
        bail!(
            "public review lens aggregate exceeds its {} byte serialized JSON limit",
            REVIEW_LENS_AGGREGATE_LIMIT_BYTES
        );
    }
    result.context("failed to serialize public review lens aggregate")?;
    Ok(())
}

pub fn validate_review_lens_set(lenses: &[ReviewLensConfig]) -> Result<()> {
    if lenses.is_empty() {
        bail!("review lens list cannot be empty");
    }
    if lenses.len() > REVIEW_LENS_LIMIT {
        bail!(
            "review lens list exceeds its {} item limit",
            REVIEW_LENS_LIMIT
        );
    }
    let mut ids = BTreeSet::new();
    for lens in lenses {
        validate_review_lens_config(lens)?;
        if !ids.insert(lens.id.as_str()) {
            bail!("review lens list contains duplicate stable ids");
        }
    }
    Ok(())
}

fn validate_review_lens_config(lens: &ReviewLensConfig) -> Result<()> {
    validate_review_lens_id(&lens.id, "review lens id")?;
    validate_review_lens_id(lens.backend.backend_id(), "review lens backend id")?;
    validate_bounded_scalar(
        lens.backend.model(),
        "review lens model selection",
        REVIEW_SHORT_TEXT_LIMIT_BYTES,
        false,
    )?;
    if contains_private_key_material(lens.backend.model())
        || Redactor::new()
            .redact(lens.backend.model())
            .summary
            .total_replacements
            > 0
        || contains_external_absolute_path(lens.backend.model())
    {
        bail!("review lens model selection contains unsafe private or external evidence");
    }
    if matches!(lens.backend, ReviewLensBackendConfig::Model { .. }) {
        if let Some(reasoning_effort) = lens.backend.reasoning_effort() {
            validate_bounded_scalar(
                reasoning_effort,
                "review lens reasoning effort",
                REVIEW_SHORT_TEXT_LIMIT_BYTES,
                false,
            )?;
        }
    }
    Ok(())
}

fn validate_review_lens_descriptor(descriptor: &ReviewLensDescriptor, label: &str) -> Result<()> {
    validate_review_lens_id(&descriptor.id, &format!("{label} id"))?;
    validate_review_lens_id(&descriptor.backend_id, &format!("{label} backend id"))?;
    validate_bounded_scalar(
        &descriptor.model,
        &format!("{label} model"),
        REVIEW_SHORT_TEXT_LIMIT_BYTES,
        false,
    )?;
    if contains_private_key_material(&descriptor.model)
        || Redactor::new()
            .redact(&descriptor.model)
            .summary
            .total_replacements
            > 0
        || contains_external_absolute_path(&descriptor.model)
    {
        bail!("{label} model contains unsafe private or external evidence");
    }
    if let Some(reasoning_effort) = &descriptor.reasoning_effort {
        validate_bounded_scalar(
            reasoning_effort,
            &format!("{label} reasoning effort"),
            REVIEW_SHORT_TEXT_LIMIT_BYTES,
            false,
        )?;
    }
    Ok(())
}

fn review_lens_backend_configuration_id(backend: &ReviewLensBackendConfig) -> Result<String> {
    let payload = serde_json::to_vec(backend)
        .context("failed to serialize review lens backend configuration identity")?;
    Ok(domain_sha256(REVIEW_LENS_BACKEND_CONFIG_DOMAIN, &payload))
}

fn validate_review_digest_identity(value: &str, label: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        bail!("{label} must be a lowercase SHA-256 content identity");
    }
    Ok(())
}

fn review_lens_evidence_content_identity(content: &str) -> Result<String> {
    if content.is_empty() {
        bail!("review lens evidence content cannot be empty");
    }
    if content.len() > REVIEW_LONG_TEXT_LIMIT_BYTES {
        bail!(
            "review lens evidence content exceeds its {} byte limit",
            REVIEW_LONG_TEXT_LIMIT_BYTES
        );
    }
    Ok(format!(
        "{REVIEW_SHA256_IDENTITY_PREFIX}{}",
        domain_sha256(REVIEW_LENS_EVIDENCE_CONTENT_DOMAIN, content.as_bytes())
    ))
}

fn validate_review_evidence_identity(value: &str) -> Result<()> {
    let digest = value
        .strip_prefix(REVIEW_SHA256_IDENTITY_PREFIX)
        .context("review lens evidence binding must use 'sha256:<64 lowercase hex>' form")?;
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        bail!("review lens evidence binding must use 'sha256:<64 lowercase hex>' form");
    }
    Ok(())
}

fn validate_review_lens_id(value: &str, label: &str) -> Result<()> {
    validate_bounded_scalar(value, label, REVIEW_SHORT_TEXT_LIMIT_BYTES, false)?;
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        || !value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
    {
        bail!("{label} must use stable ASCII identifier form");
    }
    Ok(())
}

fn validate_review_coverage_requirement(requirement: &ReviewCoverageRequirement) -> Result<()> {
    validate_review_coverage_metadata(
        &ReviewLensCoverage {
            worker_ids: requirement.worker_ids.clone(),
            paths: requirement.paths.clone(),
        },
        "required review coverage",
    )
    .map(|_| ())
}

fn validate_review_coverage_metadata(
    coverage: &ReviewLensCoverage,
    label: &str,
) -> Result<(BTreeSet<String>, BTreeSet<PathBuf>)> {
    if coverage.worker_ids.len() > REVIEW_LENS_LIMIT {
        bail!("{label} worker_ids exceeds its item limit");
    }
    if coverage.paths.len() > REVIEW_CHANGED_PATH_LIMIT {
        bail!("{label} paths exceeds its item limit");
    }
    let mut worker_ids = BTreeSet::new();
    for worker_id in &coverage.worker_ids {
        validate_review_lens_id(worker_id, &format!("{label} worker id"))?;
        if !worker_ids.insert(worker_id.clone()) {
            bail!("{label} contains a duplicate worker id");
        }
    }
    let mut paths = BTreeSet::new();
    for path in &coverage.paths {
        validate_repo_relative_path(path, &format!("{label} path"))?;
        if !paths.insert(path.clone()) {
            bail!("{label} contains a duplicate path");
        }
    }
    Ok((worker_ids, paths))
}

fn review_lens_verdict_errors(
    lens: &ReviewLensConfig,
    required: &ReviewCoverageRequirement,
    verdict: &ReviewLensVerdict,
    expected_request_binding: Option<&str>,
) -> Vec<String> {
    let mut errors = Vec::new();
    let expected_lens = ReviewLensDescriptor::from(lens);
    if let Err(error) = validate_review_lens_descriptor(&verdict.lens, "review lens verdict") {
        errors.push(error.to_string());
    }
    if verdict.lens_id != lens.id {
        errors.push("review lens verdict routing id does not match configuration".to_string());
    }
    if verdict.lens.id != expected_lens.id {
        errors.push("review lens verdict id does not match configuration".to_string());
    }
    if verdict.lens.backend_id != expected_lens.backend_id {
        errors.push("review lens verdict backend id does not match configuration".to_string());
    }
    if verdict.lens.model != expected_lens.model {
        errors.push("review lens verdict model does not match configuration".to_string());
    }
    if verdict.lens.reasoning_effort != expected_lens.reasoning_effort {
        errors
            .push("review lens verdict reasoning effort does not match configuration".to_string());
    }
    if verdict.lens.information_scope != expected_lens.information_scope {
        errors
            .push("review lens verdict information scope does not match configuration".to_string());
    }
    if verdict.lens.expected_evidence_kind != expected_lens.expected_evidence_kind {
        errors.push(
            "review lens verdict expected evidence kind does not match configuration".to_string(),
        );
    }
    if let Err(error) =
        validate_review_digest_identity(&verdict.request_binding, "review lens request binding")
    {
        errors.push(error.to_string());
    }
    if expected_request_binding.is_some_and(|expected| verdict.request_binding.as_str() != expected)
    {
        errors.push(
            "review lens verdict request identity does not match the parent-built request"
                .to_string(),
        );
    }
    let coverage =
        match validate_review_coverage_metadata(&verdict.coverage, "review lens coverage") {
            Ok(coverage) => Some(coverage),
            Err(error) => {
                errors.push(error.to_string());
                None
            }
        };
    if verdict.evidence.len() > REVIEW_FINDING_LIMIT {
        errors.push(format!(
            "review lens evidence exceeds its {} item limit",
            REVIEW_FINDING_LIMIT
        ));
    }
    let expected_backend_configuration_id =
        match review_lens_backend_configuration_id(&lens.backend) {
            Ok(identity) => Some(identity),
            Err(error) => {
                errors.push(error.to_string());
                None
            }
        };
    let mut valid_evidence_kinds = BTreeSet::new();
    for evidence in verdict.evidence.iter().take(REVIEW_FINDING_LIMIT) {
        if let Err(error) = validate_review_evidence(evidence) {
            errors.push(error.to_string());
            continue;
        }
        let mut metadata_matches = true;
        if evidence.lens.id != expected_lens.id {
            errors.push("review lens evidence lens id does not match configuration".to_string());
            metadata_matches = false;
        }
        if evidence.lens.backend_id != expected_lens.backend_id {
            errors.push("review lens evidence backend id does not match configuration".to_string());
            metadata_matches = false;
        }
        if evidence.lens.model != expected_lens.model {
            errors.push("review lens evidence model does not match configuration".to_string());
            metadata_matches = false;
        }
        if evidence.lens.reasoning_effort != expected_lens.reasoning_effort {
            errors.push(
                "review lens evidence reasoning effort does not match configuration".to_string(),
            );
            metadata_matches = false;
        }
        if evidence.lens.information_scope != expected_lens.information_scope {
            errors.push(
                "review lens evidence information scope does not match configuration".to_string(),
            );
            metadata_matches = false;
        }
        if evidence.lens.expected_evidence_kind != expected_lens.expected_evidence_kind {
            errors.push(
                "review lens evidence expected kind does not match configuration".to_string(),
            );
            metadata_matches = false;
        }
        if expected_backend_configuration_id
            .as_ref()
            .is_none_or(|identity| evidence.backend_configuration_id != identity.as_str())
        {
            errors.push(
                "review lens evidence backend configuration identity does not match configuration"
                    .to_string(),
            );
            metadata_matches = false;
        }
        if evidence.request_binding != verdict.request_binding {
            errors.push(
                "review lens evidence request identity does not match verdict request identity"
                    .to_string(),
            );
            metadata_matches = false;
        }
        if expected_request_binding
            .is_some_and(|expected| evidence.request_binding.as_str() != expected)
        {
            errors.push(
                "review lens evidence request identity does not match the parent-built request"
                    .to_string(),
            );
            metadata_matches = false;
        }
        if evidence.coverage != verdict.coverage {
            errors
                .push("review lens evidence coverage does not match verdict coverage".to_string());
            metadata_matches = false;
        }
        if metadata_matches {
            valid_evidence_kinds.insert(evidence.kind);
        }
    }

    if verdict.verdict != ReviewLensVerdictStatus::ProceduralFailure
        && !valid_evidence_kinds.contains(&lens.backend.expected_evidence_kind())
    {
        errors.push(format!(
            "review lens verdict lacks bound {:?} evidence",
            lens.backend.expected_evidence_kind()
        ));
    }
    if verdict.verdict == ReviewLensVerdictStatus::Accept {
        if let Some((worker_ids, paths)) = coverage {
            for worker_id in &required.worker_ids {
                if !worker_ids.contains(worker_id) {
                    errors.push(format!(
                        "accepted review lens omitted required worker coverage '{worker_id}'"
                    ));
                }
            }
            for path in &required.paths {
                if !paths.contains(path) {
                    errors.push(format!(
                        "accepted review lens omitted required path coverage '{}'",
                        path.display()
                    ));
                }
            }
        }
    }
    errors
}

fn public_safe_review_lens_evidence(
    lens: &ReviewLensConfig,
    verdict: &mut ReviewLensVerdict,
) -> Vec<ReviewLensEvidence> {
    let expected_lens = ReviewLensDescriptor::from(lens);
    let Ok(expected_backend_configuration_id) = review_lens_backend_configuration_id(&lens.backend)
    else {
        return Vec::new();
    };
    std::mem::take(&mut verdict.evidence)
        .into_iter()
        .take(REVIEW_FINDING_LIMIT)
        .filter(|evidence| {
            validate_review_evidence(evidence).is_ok()
                && evidence.lens == expected_lens
                && evidence.backend_configuration_id == expected_backend_configuration_id
                && evidence.request_binding == verdict.request_binding
                && evidence.coverage == verdict.coverage
        })
        .collect()
}

fn validate_review_evidence(evidence: &ReviewLensEvidence) -> Result<()> {
    validate_review_evidence_identity(&evidence.binding)?;
    validate_review_lens_descriptor(&evidence.lens, "review lens evidence")?;
    validate_review_digest_identity(
        &evidence.backend_configuration_id,
        "review lens backend configuration identity",
    )?;
    validate_review_digest_identity(
        &evidence.request_binding,
        "review lens evidence request binding",
    )?;
    validate_review_coverage_metadata(&evidence.coverage, "review lens evidence coverage")?;
    Ok(())
}

pub fn review_pr(options: ReviewPrOptions) -> Result<ReviewReport> {
    validate_review_options(&options)?;
    match options.reviewer.mode {
        ReviewerMode::Fake => Ok(fake_review(options)),
        ReviewerMode::ExternalCommand => external_review(options),
    }
}

pub(crate) fn review_pr_for_publication(
    options: ReviewPrOptions,
) -> Result<PublicationReviewResult> {
    let external_authority = options.reviewer.mode == ReviewerMode::ExternalCommand;
    let report = review_pr(options.clone())?;
    let authority =
        external_authority.then(|| BoundExternalReviewAuthority::from_verified(&options, &report));
    Ok(PublicationReviewResult { report, authority })
}

fn validate_review_options(options: &ReviewPrOptions) -> Result<()> {
    validate_bounded_scalar(
        &options.target,
        "review target",
        REVIEW_TARGET_LIMIT_BYTES,
        false,
    )?;
    if contains_private_key_material(&options.target)
        || Redactor::new()
            .redact(&options.target)
            .summary
            .total_replacements
            > 0
        || contains_external_absolute_path(&options.target)
    {
        bail!("review target contains unsafe private or external evidence");
    }
    if options.attempt == 0 || options.attempt > REVIEW_ATTEMPT_LIMIT {
        bail!(
            "review attempt must be between 1 and {}",
            REVIEW_ATTEMPT_LIMIT
        );
    }
    if options.changed_paths.len() > REVIEW_CHANGED_PATH_LIMIT {
        bail!(
            "review changed_paths exceeds its {} item limit",
            REVIEW_CHANGED_PATH_LIMIT
        );
    }
    let mut unique_paths = BTreeSet::new();
    for path in &options.changed_paths {
        validate_repo_relative_path(path, "review changed path")?;
        if !unique_paths.insert(path.clone()) {
            bail!("review changed_paths contains a duplicate path");
        }
    }
    if let Some(diff_summary) = &options.diff_summary {
        validate_bounded_scalar(
            diff_summary,
            "review diff summary",
            REVIEW_LONG_TEXT_LIMIT_BYTES,
            true,
        )?;
        if contains_private_key_material(diff_summary)
            || Redactor::new()
                .redact(diff_summary)
                .summary
                .total_replacements
                > 0
            || contains_external_absolute_path(diff_summary)
        {
            bail!("review diff summary contains unsafe private or external evidence");
        }
    }

    let serialized = serde_json::to_vec(&options.reviewer)
        .context("failed to serialize reviewer config for validation")?;
    if serialized.len() > REVIEW_CONFIG_LIMIT_BYTES {
        bail!(
            "reviewer config exceeds its {} byte serialized limit",
            REVIEW_CONFIG_LIMIT_BYTES
        );
    }
    if options.reviewer.blocking_attempts > REVIEW_BLOCKING_ATTEMPTS_LIMIT {
        bail!(
            "reviewer blocking_attempts exceeds its {} attempt limit",
            REVIEW_BLOCKING_ATTEMPTS_LIMIT
        );
    }

    match options.reviewer.mode {
        ReviewerMode::Fake => {
            if options.reviewer.program.is_some()
                || !options.reviewer.args.is_empty()
                || options.reviewer.command.is_some()
                || options.reviewer.timeout_seconds.is_some()
            {
                bail!("fake reviewer mode must not set program, args, command, or timeout_seconds");
            }
            if let Some(finding) = &options.reviewer.finding {
                validate_fake_finding_template(finding)?;
            }
        }
        ReviewerMode::ExternalCommand => {
            if options.reviewer.blocking_attempts != 0 || options.reviewer.finding.is_some() {
                bail!(
                    "external reviewer mode must not set fake blocking_attempts or finding fields"
                );
            }
            if options.reviewer.command.is_some() {
                bail!(
                    "legacy reviewer shell commands are non-authoritative; use direct program and args"
                );
            }
            let program = options
                .reviewer
                .program
                .as_deref()
                .context("external reviewer mode requires a direct program")?;
            validate_reviewer_program_path(program)?;
            if options.reviewer.args.len() > REVIEW_ARG_LIMIT {
                bail!("external reviewer args exceed their item limit");
            }
            let mut total_arg_bytes = 0usize;
            for arg in &options.reviewer.args {
                validate_bounded_scalar(
                    arg,
                    "external reviewer arg",
                    REVIEW_ARG_LIMIT_BYTES,
                    true,
                )?;
                total_arg_bytes = total_arg_bytes
                    .checked_add(arg.len())
                    .context("external reviewer arg byte total overflow")?;
                if total_arg_bytes > REVIEW_COMMAND_LIMIT_BYTES {
                    bail!("external reviewer args exceed their total byte limit");
                }
            }
            if is_shell_program(program) && shell_args_request_command(&options.reviewer.args) {
                bail!("shell -c reviewer authority is unsupported");
            }
            if let Some(timeout_seconds) = options.reviewer.timeout_seconds {
                if timeout_seconds == 0 || timeout_seconds > REVIEW_TIMEOUT_LIMIT_SECONDS {
                    bail!(
                        "external reviewer timeout_seconds must be between 1 and {}",
                        REVIEW_TIMEOUT_LIMIT_SECONDS
                    );
                }
            }
        }
    }
    Ok(())
}

fn validate_fake_finding_template(finding: &FakeReviewFindingTemplate) -> Result<()> {
    validate_bounded_scalar(
        &finding.severity,
        "fake review severity",
        REVIEW_SHORT_TEXT_LIMIT_BYTES,
        false,
    )?;
    validate_review_severity(&finding.severity)?;
    validate_bounded_scalar(
        &finding.summary,
        "fake review summary",
        REVIEW_LONG_TEXT_LIMIT_BYTES,
        false,
    )?;
    validate_bounded_scalar(
        &finding.suggested_fix,
        "fake review suggested_fix",
        REVIEW_LONG_TEXT_LIMIT_BYTES,
        false,
    )?;
    if let Some(path) = &finding.path {
        validate_repo_relative_path(path, "fake review finding path")?;
    }
    for value in [
        finding.severity.as_str(),
        finding.summary.as_str(),
        finding.suggested_fix.as_str(),
    ] {
        if contains_private_key_material(value)
            || Redactor::new().redact(value).summary.total_replacements > 0
            || contains_external_absolute_path(value)
        {
            bail!("fake review finding contains unsafe private or external evidence");
        }
    }
    Ok(())
}

fn validate_review_severity(severity: &str) -> Result<bool> {
    match severity {
        "info" | "warning" => Ok(false),
        "error" | "critical" => Ok(true),
        _ => bail!("review finding severity is not canonical"),
    }
}

fn validate_bounded_scalar(
    value: &str,
    label: &str,
    max_bytes: usize,
    allow_newlines: bool,
) -> Result<()> {
    if value.is_empty() {
        bail!("{label} cannot be empty");
    }
    if value.len() > max_bytes {
        bail!("{label} exceeds its {max_bytes} byte limit");
    }
    if value.chars().any(|character| {
        character.is_control() && !(allow_newlines && matches!(character, '\n' | '\r' | '\t'))
    }) {
        bail!("{label} contains an unsupported control character");
    }
    Ok(())
}

fn validate_repo_relative_path(path: &Path, label: &str) -> Result<()> {
    if path.as_os_str().is_empty() || path.is_absolute() {
        bail!("{label} must be a non-empty repository-relative path");
    }
    let encoded = path
        .to_str()
        .context("review public path must be valid UTF-8")?;
    if encoded.len() > REVIEW_PATH_LIMIT_BYTES {
        bail!("{label} exceeds its {} byte limit", REVIEW_PATH_LIMIT_BYTES);
    }
    if encoded.chars().any(char::is_control) {
        bail!("{label} contains an unsupported control character");
    }
    if encoded
        .split('/')
        .any(|component| component.is_empty() || matches!(component, "." | ".."))
    {
        bail!("{label} is not canonical repository-relative form");
    }
    let mut normal_components = 0usize;
    for component in path.components() {
        match component {
            std::path::Component::Normal(_) => {
                normal_components = normal_components.saturating_add(1)
            }
            std::path::Component::CurDir
            | std::path::Component::ParentDir
            | std::path::Component::RootDir
            | std::path::Component::Prefix(_) => {
                bail!("{label} is not canonical repository-relative form")
            }
        }
    }
    if normal_components == 0 {
        bail!("{label} must contain a normal path component");
    }
    Ok(())
}

fn fake_review(options: ReviewPrOptions) -> ReviewReport {
    let request_binding = fake_review_request_binding(&options);
    let should_block = options.reviewer.blocking_attempts > 0
        && options.attempt <= options.reviewer.blocking_attempts;
    let findings = if should_block {
        vec![fake_finding(&options)]
    } else {
        Vec::new()
    };
    let blocking_finding_count = findings.iter().filter(|finding| finding.blocking).count();
    let status = if blocking_finding_count == 0 {
        ReviewReportStatus::Passed
    } else {
        ReviewReportStatus::Blocked
    };
    ReviewReport {
        version: REVIEW_SCHEMA_VERSION,
        status,
        success: status == ReviewReportStatus::Passed,
        target: options.target,
        reviewer: ReviewerIdentity {
            mode: ReviewerMode::Fake,
            reviewer_id: "autopilot-fake-reviewer".to_string(),
            model: "deterministic-local-reviewer".to_string(),
        },
        attempt: options.attempt,
        request_binding,
        findings,
        blocking_finding_count,
        changed_paths: options.changed_paths,
        diff_source: if options.diff_summary.is_some() {
            "sanitized_merge_candidate_summary".to_string()
        } else {
            "pr_target_only".to_string()
        },
        ci_reaction_supported: false,
        ci_reaction: "unsupported".to_string(),
        diagnostics: None,
        next_action: if status == ReviewReportStatus::Passed {
            "human reviews the pull request and merges manually".to_string()
        } else {
            "repair blocking review findings before requesting another human review".to_string()
        },
    }
}

fn external_review(options: ReviewPrOptions) -> Result<ReviewReport> {
    external_review_runtime(options, ReviewExecutionRuntime::Verified)
}

#[cfg(test)]
fn external_review_simulation(options: ReviewPrOptions) -> Result<ReviewReport> {
    external_review_runtime(options, ReviewExecutionRuntime::NonpublishableSimulation)
}

fn external_review_runtime(
    options: ReviewPrOptions,
    runtime: ReviewExecutionRuntime,
) -> Result<ReviewReport> {
    let program = options
        .reviewer
        .program
        .as_deref()
        .context("external reviewer mode requires a direct program")?;
    let repository = ReviewRepositoryBinding::bind(&options.repo)?;
    let source_program = BoundReviewerProgram::bind(&repository, program)?;
    if runtime == ReviewExecutionRuntime::Verified {
        validate_verified_reviewer_program(&repository, &source_program, &options.reviewer.args)?;
        validate_sanitized_changed_paths(&options.changed_paths)?;
    }
    let materialized_program = MaterializedReviewerProgram::create(source_program)?;
    let before = repository.snapshot()?;
    let sanitized_view = match runtime {
        ReviewExecutionRuntime::Verified => Some(SanitizedReviewerView::create(&repository)?),
        #[cfg(test)]
        ReviewExecutionRuntime::NonpublishableSimulation => None,
    };
    materialized_program.verify(&repository)?;
    if let Some(view) = &sanitized_view {
        view.verify(&repository)?;
        if repository.snapshot()? != before {
            bail!("review repository changed while constructing the sanitized view");
        }
    }
    let effective_timeout_seconds = options
        .reviewer
        .timeout_seconds
        .unwrap_or(REVIEW_DEFAULT_TIMEOUT_SECONDS);
    let reviewer_identity =
        bound_external_reviewer_identity(&materialized_program.binding, &options.reviewer.args)?;
    let request_binding = external_review_request_binding(
        &options,
        &before,
        &reviewer_identity,
        &materialized_program.binding,
        sanitized_view.as_ref().map(SanitizedReviewerView::binding),
        effective_timeout_seconds,
    )?;
    let input = serde_json::to_vec(&ExternalReviewInput {
        version: REVIEW_SCHEMA_VERSION,
        target: &options.target,
        attempt: options.attempt,
        changed_paths: &options.changed_paths,
        diff_summary: options.diff_summary.as_deref(),
        reviewer: &reviewer_identity,
        request_binding: &request_binding,
    })
    .context("failed to serialize external review input")?;
    if input.len() > REVIEW_INPUT_LIMIT_BYTES {
        bail!(
            "external review input exceeds its {} byte limit",
            REVIEW_INPUT_LIMIT_BYTES
        );
    }
    let timeout = Some(Duration::from_secs(effective_timeout_seconds));
    let execution_root = sanitized_view
        .as_ref()
        .map(SanitizedReviewerView::path)
        .unwrap_or_else(|| repository.worktree_root.path().to_path_buf());
    let confinement = sanitized_view
        .as_ref()
        .map(|view| {
            repository
                .sanitized_confinement_profile(&view.path(), &materialized_program.directory_path())
        })
        .transpose()?;
    let mut process_spec = ProcessSpec::direct(
        "external reviewer program",
        &materialized_program.execution_path,
        options.reviewer.args.clone(),
        &execution_root,
        REVIEW_CAPTURE_LIMIT_BYTES,
    )
    .with_environment(EnvironmentMode::ClearAndSet(sandbox_environment()))
    .with_stdin(StdinMode::Bytes(input))
    .with_timeout(timeout);
    if runtime == ReviewExecutionRuntime::Verified {
        let pinned = PinnedDirectExecutable::capture(&materialized_program.execution_path)
            .context("failed to bind the materialized reviewer executable")?;
        process_spec = process_spec
            .with_pinned_direct_executable(pinned)
            .context("failed to attach the bound reviewer executable")?;
    }
    let output = run_process(match runtime {
        ReviewExecutionRuntime::Verified => process_spec
            .with_private_runtime_home(true)
            .with_side_effect_confinement(SideEffectConfinementProfile::StrictOfflineWorkspace(
                confinement.context("verified reviewer omitted sanitized confinement")?,
            )),
        #[cfg(test)]
        ReviewExecutionRuntime::NonpublishableSimulation => process_spec
            .with_containment(crate::process_runner::ContainmentPolicy::TrustedBestEffort),
    })
    .context("failed to run external reviewer program")?;
    repository.verify()?;
    materialized_program.verify(&repository)?;
    if let Some(view) = &sanitized_view {
        view.verify(&repository)?;
    }
    let after = repository.snapshot()?;
    if let Some(error) = &output.stdin_error {
        bail!(error.clone());
    }
    let diagnostics =
        diagnostics_from_output(&options.repo, &output, Some(effective_timeout_seconds));
    let diagnostics_contain_unsafe_evidence =
        review_diagnostic_contains_unsafe_evidence(&options.repo, output.stderr.as_bytes())
            || output.process_error.as_deref().is_some_and(|error| {
                review_diagnostic_contains_unsafe_evidence(&options.repo, error.as_bytes())
            });
    if after != before {
        return Ok(failed_external_review(
            &reviewer_identity,
            options,
            &request_binding,
            "external reviewer changed repository state despite its read-only contract",
            diagnostics,
        ));
    }
    if output.timed_out {
        return Ok(failed_external_review(
            &reviewer_identity,
            options,
            &request_binding,
            "external reviewer command timed out",
            diagnostics,
        ));
    }
    let command_succeeded = match runtime {
        ReviewExecutionRuntime::Verified => output.safety_sensitive_succeeded(),
        #[cfg(test)]
        ReviewExecutionRuntime::NonpublishableSimulation => {
            output.status.is_some_and(|status| status.success())
                && !output.timed_out
                && output.stdin_error.is_none()
                && output.process_error.is_none()
        }
    };
    if !command_succeeded {
        return Ok(failed_external_review(
            &reviewer_identity,
            options,
            &request_binding,
            "external reviewer command failed",
            diagnostics,
        ));
    }
    if output.stdout.is_truncated() || output.stderr.is_truncated() {
        bail!(
            "external reviewer command output exceeded the {} byte capture limit on stdout or stderr",
            REVIEW_CAPTURE_LIMIT_BYTES
        );
    }
    if diagnostics_contain_unsafe_evidence {
        return Ok(failed_external_review(
            &reviewer_identity,
            options,
            &request_binding,
            "external reviewer diagnostics contained unsafe evidence",
            redact_untrusted_report_diagnostics(diagnostics),
        ));
    }
    match parse_external_review_report(
        output.stdout.as_bytes(),
        &options,
        &reviewer_identity,
        &request_binding,
    )? {
        ParsedExternalReview::Accepted(mut report) => {
            // External diagnostics are parsed and bounded but are never
            // accepted as authorization evidence. Process-owned diagnostics
            // are the only diagnostics that can cross this boundary.
            report.diagnostics = Some(accepted_external_diagnostics(diagnostics));
            Ok(*report)
        }
        ParsedExternalReview::RejectedSensitive => Ok(failed_external_review(
            &reviewer_identity,
            options,
            &request_binding,
            "external reviewer report contained unsafe authorization evidence",
            redact_untrusted_report_diagnostics(diagnostics),
        )),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct ReviewRepoSnapshot {
    head: Option<String>,
    head_name: Option<String>,
    head_symbolic_target: Option<String>,
    head_admin_sha256: String,
    head_ref_sha256: Option<String>,
    packed_refs_sha256: Option<String>,
    index_sha256: Option<String>,
    status_sha256: String,
    worktree_sha256: String,
    entry_count: usize,
    total_content_bytes: u64,
    worktree_identity: FileIdentity,
    git_dir_identity: FileIdentity,
    common_dir_identity: FileIdentity,
    git_backlink: GitBacklinkSnapshot,
    state_identity: Option<FileIdentity>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct BoundReviewerProgram {
    path: PathBuf,
    file: BoundReviewerProgramFile,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct BoundReviewerProgramFile {
    mode: u32,
    length: u64,
    sha256: [u8; 32],
    identity: FileIdentity,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
    #[serde(skip)]
    bytes: Vec<u8>,
}

impl BoundReviewerProgram {
    fn bind(repository: &ReviewRepositoryBinding, path: &Path) -> Result<Self> {
        validate_reviewer_program_path(path)?;
        let file = if path.is_absolute() {
            read_absolute_reviewer_program(path)?
        } else {
            read_worktree_reviewer_program(repository, path)?
        };
        Ok(Self {
            path: path.to_path_buf(),
            file,
        })
    }

    fn verify(&self, repository: &ReviewRepositoryBinding) -> Result<()> {
        let observed = if self.path.is_absolute() {
            read_absolute_reviewer_program(&self.path)?
        } else {
            read_worktree_reviewer_program(repository, &self.path)?
        };
        if observed != self.file {
            bail!("external reviewer program identity or content changed");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct MaterializedReviewerBinding {
    source: BoundReviewerProgram,
    program_copy: MaterializedReviewerFile,
    interpreter_source: Option<BoundReviewerProgram>,
    interpreter_copy: Option<MaterializedReviewerFile>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct MaterializedReviewerFile {
    mode: u32,
    length: u64,
    sha256: [u8; 32],
    identity: FileIdentity,
}

#[derive(Debug)]
struct MaterializedReviewerProgram {
    root: SafeRoot,
    directory_name: OsString,
    directory_identity: FileIdentity,
    execution_path: PathBuf,
    interpreter_path: Option<PathBuf>,
    binding: MaterializedReviewerBinding,
}

impl MaterializedReviewerProgram {
    fn create(source: BoundReviewerProgram) -> Result<Self> {
        #[cfg(target_os = "linux")]
        {
            let runtime_root = trusted_linux_runtime_root()
                .context("external reviewer requires an owner-private runtime root")?;
            let root = SafeRoot::open_existing(runtime_root)
                .map_err(|_| anyhow::anyhow!("external reviewer runtime root is unsafe"))?;
            let reserved = root.reserve_random_direct_child_directory("maco-review-program")?;
            let directory_name = reserved
                .path()
                .file_name()
                .context("external reviewer runtime directory has no name")?
                .to_os_string();
            let directory_identity = reserved.identity().clone();
            let execution_path = reserved.path().join("reviewer-program");

            let (program_bytes, interpreter_source, interpreter_path, interpreter_copy) =
                if let Some(interpreter) = reviewer_script_interpreter(&source.file.bytes)? {
                    let interpreter_source =
                        BoundReviewerProgram::bind_absolute_canonical(&interpreter)?;
                    if reviewer_script_interpreter(&interpreter_source.file.bytes)?.is_some() {
                        bail!("nested script reviewer interpreters are unsupported");
                    }
                    let interpreter_path = reserved.path().join("reviewer-interpreter");
                    let interpreter_copy = materialize_reviewer_file(
                        &interpreter_path,
                        &interpreter_source.file.bytes,
                    )?;
                    let program_bytes =
                        rewrite_reviewer_shebang(&source.file.bytes, &interpreter_path)?;
                    (
                        program_bytes,
                        Some(interpreter_source),
                        Some(interpreter_path),
                        Some(interpreter_copy),
                    )
                } else {
                    (source.file.bytes.clone(), None, None, None)
                };
            let program_copy = materialize_reviewer_file(&execution_path, &program_bytes)?;
            reserved.verify(&root)?;
            Ok(Self {
                root,
                directory_name,
                directory_identity,
                execution_path,
                interpreter_path,
                binding: MaterializedReviewerBinding {
                    source,
                    program_copy,
                    interpreter_source,
                    interpreter_copy,
                },
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = source;
            bail!("external reviewer materialization is unsupported on this platform")
        }
    }

    fn verify(&self, repository: &ReviewRepositoryBinding) -> Result<()> {
        self.root
            .verify()
            .map_err(|_| anyhow::anyhow!("external reviewer runtime root changed"))?;
        let reserved = self
            .root
            .bind_existing_direct_child_directory(&self.directory_name)?;
        if reserved.identity() != &self.directory_identity {
            bail!("external reviewer runtime directory identity changed");
        }
        self.binding.source.verify(repository)?;
        if let Some(interpreter) = &self.binding.interpreter_source {
            interpreter.verify(repository)?;
        }
        if materialized_reviewer_file(&self.execution_path)? != self.binding.program_copy {
            bail!("materialized reviewer program changed");
        }
        match (&self.interpreter_path, &self.binding.interpreter_copy) {
            (Some(path), Some(expected)) if materialized_reviewer_file(path)? == *expected => {}
            (None, None) => {}
            _ => bail!("materialized reviewer interpreter changed"),
        }
        Ok(())
    }

    fn directory_path(&self) -> PathBuf {
        self.root.path().join(&self.directory_name)
    }
}

impl Drop for MaterializedReviewerProgram {
    fn drop(&mut self) {
        let _ = remove_direct_child_tree(
            &self.root,
            &self.directory_name,
            Some(&self.directory_identity),
            TreeLinkPolicy::RejectLinksAndSpecialFiles,
        );
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct SanitizedViewOrigin {
    tracked: bool,
    untracked: bool,
    skip_worktree: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SanitizedViewSelection {
    entries: BTreeMap<PathBuf, SanitizedViewOrigin>,
}

#[derive(Debug)]
struct SanitizedReviewerView {
    root: SafeRoot,
    directory_name: OsString,
    directory_identity: FileIdentity,
    selection: SanitizedViewSelection,
    source_directories: BTreeMap<PathBuf, BoundReviewDirectory>,
    source_entries: BTreeMap<PathBuf, SnapshotTreeEntry>,
    binding: String,
}

impl SanitizedReviewerView {
    fn create(repository: &ReviewRepositoryBinding) -> Result<Self> {
        #[cfg(target_os = "linux")]
        {
            let selection = collect_sanitized_view_selection(repository)?;
            validate_sanitized_view_paths(&selection)?;
            let reader = ReviewTreeReader::bind(&repository.worktree_root)?;
            let mut source_entries = BTreeMap::new();
            let mut regular_contents = BTreeMap::new();
            let mut total_content_bytes = 0u64;
            for (path, origin) in &selection.entries {
                let before = reader.snapshot_entry(path, &mut total_content_bytes)?;
                if matches!(before, SnapshotTreeEntry::Missing) && origin.skip_worktree {
                    bail!("sanitized reviewer view refuses sparse-missing tracked entries");
                }
                validate_sanitized_view_entry_mode(&before)?;
                if let SnapshotTreeEntry::Regular { length, sha256, .. } = &before {
                    let bytes = BoundedRegularReader::read_relative(
                        repository.worktree_root.path(),
                        path,
                        REVIEW_SNAPSHOT_FILE_LIMIT_BYTES,
                    )
                    .map_err(|_| anyhow::anyhow!("sanitized reviewer source read was refused"))?;
                    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) != *length
                        || sha256_bytes(&bytes) != *sha256
                    {
                        bail!("sanitized reviewer source changed during bounded copy");
                    }
                    let mut verify_total = 0u64;
                    if reader.snapshot_entry(path, &mut verify_total)? != before {
                        bail!("sanitized reviewer source changed during bounded copy");
                    }
                    regular_contents.insert(path.clone(), bytes);
                }
                source_entries.insert(path.clone(), before);
            }
            let directory_paths = sanitized_view_parent_directories(&source_entries)?;
            let mut source_directories = BTreeMap::new();
            for path in directory_paths {
                let directory = reader.snapshot_directory(&path)?;
                if directory.mode & 0o7000 != 0 {
                    bail!("sanitized reviewer source directory has unsafe special mode bits");
                }
                source_directories.insert(path.clone(), directory);
            }
            validate_sanitized_view_symlinks(&source_entries, &source_directories)?;
            reader.verify(&repository.worktree_root)?;

            let runtime_root = trusted_linux_runtime_root()
                .context("sanitized reviewer view requires an owner-private runtime root")?;
            let root = SafeRoot::open_existing(runtime_root)
                .map_err(|_| anyhow::anyhow!("sanitized reviewer runtime root is unsafe"))?;
            let reserved = root.reserve_random_direct_child_directory("maco-review-view")?;
            let directory_name = reserved
                .path()
                .file_name()
                .context("sanitized reviewer view has no directory name")?
                .to_os_string();
            let directory_identity = reserved.identity().clone();
            let binding = sanitized_view_binding(&selection, &source_directories, &source_entries)?;
            let view = Self {
                root,
                directory_name,
                directory_identity,
                selection,
                source_directories,
                source_entries,
                binding,
            };
            let writer = SanitizedViewWriter::open(view.path(), &view.directory_identity)?;
            for (path, directory) in &view.source_directories {
                writer.create_directory(path, directory.mode)?;
            }
            for (path, entry) in &view.source_entries {
                match entry {
                    SnapshotTreeEntry::Missing => {}
                    SnapshotTreeEntry::Regular { mode, .. } => writer.create_regular(
                        path,
                        regular_contents
                            .get(path)
                            .context("sanitized reviewer copy omitted regular contents")?,
                        *mode,
                    )?,
                    SnapshotTreeEntry::Symlink { target, .. } => {
                        writer.create_symlink(path, target)?
                    }
                }
            }
            for (path, directory) in view.source_directories.iter().rev() {
                writer.set_directory_mode(path, directory.mode)?;
            }
            view.verify(repository)?;
            Ok(view)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = repository;
            bail!("sanitized reviewer views are unsupported on this platform")
        }
    }

    fn path(&self) -> PathBuf {
        self.root.path().join(&self.directory_name)
    }

    fn binding(&self) -> &str {
        &self.binding
    }

    fn verify(&self, repository: &ReviewRepositoryBinding) -> Result<()> {
        self.root
            .verify()
            .map_err(|_| anyhow::anyhow!("sanitized reviewer runtime root changed"))?;
        let reserved = self
            .root
            .bind_existing_direct_child_directory(&self.directory_name)?;
        if reserved.identity() != &self.directory_identity {
            bail!("sanitized reviewer view directory identity changed");
        }
        if collect_sanitized_view_selection(repository)? != self.selection {
            bail!("sanitized reviewer index or worktree selection changed");
        }
        let source = ReviewTreeReader::bind(&repository.worktree_root)?;
        for (path, expected) in &self.source_directories {
            if source.snapshot_directory(path)? != *expected {
                bail!("sanitized reviewer source directory changed");
            }
        }
        let mut source_total = 0u64;
        for (path, expected) in &self.source_entries {
            if source.snapshot_entry(path, &mut source_total)? != *expected {
                bail!("sanitized reviewer source entry changed");
            }
        }
        source.verify(&repository.worktree_root)?;

        let view_root = SafeRoot::open_existing(self.path())
            .map_err(|_| anyhow::anyhow!("sanitized reviewer view root is unsafe"))?;
        let observed_paths = collect_sanitized_view_paths(&view_root)?;
        let expected_paths = self
            .source_directories
            .keys()
            .cloned()
            .chain(self.source_entries.iter().filter_map(|(path, entry)| {
                (!matches!(entry, SnapshotTreeEntry::Missing)).then_some(path.clone())
            }))
            .collect::<BTreeSet<_>>();
        if observed_paths != expected_paths {
            bail!("sanitized reviewer view contained missing or extra paths");
        }
        let view = ReviewTreeReader::bind(&view_root)?;
        for (path, expected) in &self.source_directories {
            let observed = view.snapshot_directory(path)?;
            if observed.mode & 0o777 != expected.mode & 0o777 {
                bail!("sanitized reviewer directory mode changed");
            }
        }
        let mut view_total = 0u64;
        for (path, expected) in &self.source_entries {
            if matches!(expected, SnapshotTreeEntry::Missing) {
                continue;
            }
            let observed = view.snapshot_entry(path, &mut view_total)?;
            if !sanitized_view_content_matches(expected, &observed) {
                bail!("sanitized reviewer view content or mode changed");
            }
        }
        view.verify(&view_root)?;
        Ok(())
    }
}

impl Drop for SanitizedReviewerView {
    fn drop(&mut self) {
        let _ = remove_direct_child_tree(
            &self.root,
            &self.directory_name,
            Some(&self.directory_identity),
            TreeLinkPolicy::UnlinkLinks,
        );
    }
}

#[cfg(target_os = "linux")]
struct SanitizedViewWriter {
    root: File,
}

#[cfg(target_os = "linux")]
impl SanitizedViewWriter {
    fn open(path: PathBuf, expected: &FileIdentity) -> Result<Self> {
        let mut options = std::fs::OpenOptions::new();
        options
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC);
        let root = options
            .open(path)
            .context("failed to bind sanitized reviewer view")?;
        if file_identity_from_metadata(&root.metadata()?) != *expected {
            bail!("sanitized reviewer view binding changed");
        }
        Ok(Self { root })
    }

    fn create_directory(&self, path: &Path, _mode: u32) -> Result<()> {
        let (parent, name) = self.open_parent(path)?;
        let name = c_string(&name)?;
        if unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) } != 0 {
            return Err(std::io::Error::last_os_error())
                .context("failed to create sanitized reviewer directory");
        }
        Ok(())
    }

    fn create_regular(&self, path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
        let (parent, name) = self.open_parent(path)?;
        let name = c_string(&name)?;
        let fd = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error())
                .context("failed to create sanitized reviewer file");
        }
        let mut file = unsafe { File::from_raw_fd(fd) };
        file.write_all(bytes)
            .context("failed to write sanitized reviewer file")?;
        if unsafe { libc::fchmod(file.as_raw_fd(), mode & 0o777) } != 0 {
            return Err(std::io::Error::last_os_error())
                .context("failed to set sanitized reviewer file mode");
        }
        file.sync_all()
            .context("failed to flush sanitized reviewer file")?;
        Ok(())
    }

    fn create_symlink(&self, path: &Path, target: &[u8]) -> Result<()> {
        let (parent, name) = self.open_parent(path)?;
        let name = c_string(&name)?;
        let target = std::ffi::CString::new(target)
            .context("sanitized reviewer symlink target contained NUL")?;
        if unsafe { libc::symlinkat(target.as_ptr(), parent.as_raw_fd(), name.as_ptr()) } != 0 {
            return Err(std::io::Error::last_os_error())
                .context("failed to create sanitized reviewer symlink");
        }
        Ok(())
    }

    fn set_directory_mode(&self, path: &Path, mode: u32) -> Result<()> {
        let directory = self.open_directory(path)?;
        if unsafe { libc::fchmod(directory.as_raw_fd(), mode & 0o777) } != 0 {
            return Err(std::io::Error::last_os_error())
                .context("failed to set sanitized reviewer directory mode");
        }
        Ok(())
    }

    fn open_parent(&self, path: &Path) -> Result<(File, OsString)> {
        validate_snapshot_relative_path(path)?;
        let name = path
            .file_name()
            .context("sanitized reviewer path has no filename")?
            .to_os_string();
        let parent = path.parent().unwrap_or_else(|| Path::new(""));
        Ok((self.open_directory(parent)?, name))
    }

    fn open_directory(&self, path: &Path) -> Result<File> {
        let duplicated = unsafe { libc::dup(self.root.as_raw_fd()) };
        if duplicated < 0 {
            return Err(std::io::Error::last_os_error())
                .context("failed to duplicate sanitized reviewer root");
        }
        let mut directory = unsafe { File::from_raw_fd(duplicated) };
        for component in path.components() {
            let std::path::Component::Normal(component) = component else {
                bail!("sanitized reviewer directory path is not canonical");
            };
            let component = c_string(component)?;
            let fd = unsafe {
                libc::openat(
                    directory.as_raw_fd(),
                    component.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if fd < 0 {
                return Err(std::io::Error::last_os_error())
                    .context("failed to traverse sanitized reviewer directory");
            }
            directory = unsafe { File::from_raw_fd(fd) };
        }
        Ok(directory)
    }
}

fn collect_sanitized_view_selection(
    repository: &ReviewRepositoryBinding,
) -> Result<SanitizedViewSelection> {
    repository.verify()?;
    let git = crate::git_repository::open(repository.worktree_root.path())
        .context("failed to enumerate sanitized reviewer selection")?;
    let index = git
        .index()
        .context("failed to read sanitized reviewer index")?;
    let mut entries = BTreeMap::<PathBuf, SanitizedViewOrigin>::new();
    for entry in index.iter() {
        if entry.mode & 0o170000 == 0o160000 {
            bail!("sanitized reviewer view refuses gitlinks/submodules");
        }
        if entry.mode & 0o170000 == 0o040000 || entry.flags & 0x3000 != 0 {
            bail!("sanitized reviewer view refuses sparse or unmerged index entries");
        }
        let path = path_from_git_bytes(&entry.path)?;
        validate_snapshot_relative_path(&path)?;
        if sanitized_view_excludes_path(&path) {
            bail!("sanitized reviewer view refuses tracked .maco runtime paths");
        }
        let flags = git2::IndexEntryExtendedFlag::from_bits_truncate(entry.flags_extended);
        let origin = entries.entry(path).or_default();
        origin.tracked = true;
        origin.skip_worktree |= flags.is_skip_worktree();
        if entries.len() > REVIEW_SNAPSHOT_ENTRY_LIMIT {
            bail!("sanitized reviewer view exceeds its entry limit");
        }
    }
    let mut status_options = git2::StatusOptions::new();
    status_options
        .include_untracked(true)
        .recurse_untracked_dirs(true)
        .include_ignored(false)
        .recurse_ignored_dirs(false);
    let statuses = git
        .statuses(Some(&mut status_options))
        .context("failed to enumerate sanitized reviewer worktree")?;
    if statuses.len() > REVIEW_SNAPSHOT_ENTRY_LIMIT {
        bail!("sanitized reviewer status exceeds its entry limit");
    }
    for status in statuses.iter() {
        if !status.status().contains(git2::Status::WT_NEW)
            || status.status().contains(git2::Status::IGNORED)
        {
            continue;
        }
        let path = path_from_git_bytes(status.path_bytes())?;
        validate_snapshot_relative_path(&path)?;
        if sanitized_view_excludes_path(&path) {
            continue;
        }
        entries.entry(path).or_default().untracked = true;
        if entries.len() > REVIEW_SNAPSHOT_ENTRY_LIMIT {
            bail!("sanitized reviewer view exceeds its entry limit");
        }
    }
    repository.verify()?;
    Ok(SanitizedViewSelection { entries })
}

fn sanitized_view_excludes_path(path: &Path) -> bool {
    path.components().next().is_some_and(|component| {
        matches!(component, std::path::Component::Normal(value) if value == OsStr::new(".maco"))
    })
}

fn validate_sanitized_changed_paths(paths: &[PathBuf]) -> Result<()> {
    if paths.iter().any(|path| sanitized_view_excludes_path(path)) {
        bail!("verified external review refuses changed .maco runtime paths");
    }
    Ok(())
}

fn validate_sanitized_view_paths(selection: &SanitizedViewSelection) -> Result<()> {
    let mut folded = BTreeMap::<Vec<u8>, PathBuf>::new();
    let mut materialized = BTreeSet::<PathBuf>::new();
    for path in selection.entries.keys() {
        let depth = path.components().count();
        if depth == 0 || depth > REVIEW_PREWALK_MAX_DEPTH {
            bail!("sanitized reviewer path exceeds its depth limit");
        }
        materialized.insert(path.clone());
        let mut parent = path.parent();
        while let Some(path) = parent.filter(|path| !path.as_os_str().is_empty()) {
            materialized.insert(path.to_path_buf());
            parent = path.parent();
        }
    }
    if materialized.len() > REVIEW_SNAPSHOT_ENTRY_LIMIT {
        bail!("sanitized reviewer materialization exceeds its entry limit");
    }
    for path in &materialized {
        let key = path_bytes(path)
            .into_iter()
            .map(|byte| byte.to_ascii_lowercase())
            .collect::<Vec<_>>();
        if let Some(existing) = folded.insert(key, path.clone()) {
            if existing != *path {
                bail!("sanitized reviewer path set contains a case collision");
            }
        }
    }
    for path in selection.entries.keys() {
        let mut parent = path.parent();
        while let Some(candidate) = parent.filter(|value| !value.as_os_str().is_empty()) {
            if selection.entries.contains_key(candidate) {
                bail!("sanitized reviewer path set contains a file/directory collision");
            }
            parent = candidate.parent();
        }
    }
    Ok(())
}

fn sanitized_view_parent_directories(
    entries: &BTreeMap<PathBuf, SnapshotTreeEntry>,
) -> Result<Vec<PathBuf>> {
    let mut directories = BTreeSet::new();
    for (path, entry) in entries {
        if matches!(entry, SnapshotTreeEntry::Missing) {
            continue;
        }
        let mut parent = path.parent();
        while let Some(path) = parent.filter(|path| !path.as_os_str().is_empty()) {
            directories.insert(path.to_path_buf());
            parent = path.parent();
        }
    }
    if directories.len().saturating_add(entries.len()) > REVIEW_SNAPSHOT_ENTRY_LIMIT {
        bail!("sanitized reviewer view exceeds its materialized path limit");
    }
    let mut directories = directories.into_iter().collect::<Vec<_>>();
    directories.sort_by_key(|path| path.components().count());
    Ok(directories)
}

#[cfg(target_os = "linux")]
fn validate_sanitized_view_symlinks(
    entries: &BTreeMap<PathBuf, SnapshotTreeEntry>,
    directories: &BTreeMap<PathBuf, BoundReviewDirectory>,
) -> Result<()> {
    for (path, entry) in entries {
        let SnapshotTreeEntry::Symlink { target, .. } = entry else {
            continue;
        };
        let resolved = resolve_internal_symlink_target(path, target)?;
        if sanitized_view_excludes_path(&resolved) {
            bail!("sanitized reviewer symlink targets excluded runtime state");
        }
        let targets_regular = matches!(
            entries.get(&resolved),
            Some(SnapshotTreeEntry::Regular { .. })
        );
        if !targets_regular && !directories.contains_key(&resolved) {
            bail!("sanitized reviewer symlink must target a selected regular file or directory");
        }
    }
    Ok(())
}

fn sanitized_view_content_matches(
    expected: &SnapshotTreeEntry,
    observed: &SnapshotTreeEntry,
) -> bool {
    match (expected, observed) {
        (
            SnapshotTreeEntry::Regular {
                mode: expected_mode,
                length: expected_length,
                sha256: expected_sha256,
                ..
            },
            SnapshotTreeEntry::Regular {
                mode: observed_mode,
                length: observed_length,
                sha256: observed_sha256,
                ..
            },
        ) => {
            expected_mode & 0o777 == observed_mode & 0o777
                && expected_length == observed_length
                && expected_sha256 == observed_sha256
        }
        (
            SnapshotTreeEntry::Symlink {
                mode: expected_mode,
                target: expected_target,
                ..
            },
            SnapshotTreeEntry::Symlink {
                mode: observed_mode,
                target: observed_target,
                ..
            },
        ) => expected_mode == observed_mode && expected_target == observed_target,
        _ => false,
    }
}

fn sanitized_view_binding(
    selection: &SanitizedViewSelection,
    directories: &BTreeMap<PathBuf, BoundReviewDirectory>,
    entries: &BTreeMap<PathBuf, SnapshotTreeEntry>,
) -> Result<String> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(
        &u64::try_from(selection.entries.len())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    for (path, origin) in &selection.entries {
        append_snapshot_bytes(&mut bytes, &path_bytes(path))?;
        bytes.extend_from_slice(&[
            u8::from(origin.tracked),
            u8::from(origin.untracked),
            u8::from(origin.skip_worktree),
        ]);
        match entries
            .get(path)
            .context("sanitized view binding omitted source entry")?
        {
            SnapshotTreeEntry::Missing => bytes.push(0),
            SnapshotTreeEntry::Regular {
                mode,
                length,
                sha256,
                ..
            } => {
                bytes.push(1);
                bytes.extend_from_slice(&(mode & 0o777).to_be_bytes());
                bytes.extend_from_slice(&length.to_be_bytes());
                bytes.extend_from_slice(sha256);
            }
            SnapshotTreeEntry::Symlink { mode, target, .. } => {
                bytes.push(2);
                bytes.extend_from_slice(&(mode & 0o777).to_be_bytes());
                append_snapshot_bytes(&mut bytes, target)?;
            }
        }
    }
    bytes.extend_from_slice(
        &u64::try_from(directories.len())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    for (path, directory) in directories {
        append_snapshot_bytes(&mut bytes, &path_bytes(path))?;
        bytes.extend_from_slice(&(directory.mode & 0o777).to_be_bytes());
    }
    Ok(domain_sha256(SANITIZED_REVIEW_VIEW_DOMAIN, &bytes))
}

fn validate_sanitized_view_entry_mode(entry: &SnapshotTreeEntry) -> Result<()> {
    let mode = match entry {
        SnapshotTreeEntry::Missing => return Ok(()),
        SnapshotTreeEntry::Regular { mode, .. } | SnapshotTreeEntry::Symlink { mode, .. } => *mode,
    };
    if mode & 0o7000 != 0 {
        bail!("sanitized reviewer source entry has unsafe special mode bits");
    }
    Ok(())
}

fn collect_sanitized_view_paths(root: &SafeRoot) -> Result<BTreeSet<PathBuf>> {
    let reader = ReviewTreeReader::bind(root)?;
    #[cfg(target_os = "linux")]
    {
        let deadline = Instant::now()
            .checked_add(REVIEW_PREWALK_TIMEOUT)
            .context("sanitized reviewer view deadline overflow")?;
        let mut paths = BTreeSet::new();
        collect_sanitized_view_directory(&reader.root, Path::new(""), 0, deadline, &mut paths)?;
        reader.verify(root)?;
        Ok(paths)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = reader;
        bail!("sanitized reviewer view enumeration is unsupported on this platform")
    }
}

#[cfg(target_os = "linux")]
fn collect_sanitized_view_directory(
    directory: &File,
    relative: &Path,
    depth: usize,
    deadline: Instant,
    paths: &mut BTreeSet<PathBuf>,
) -> Result<()> {
    if depth > REVIEW_PREWALK_MAX_DEPTH || Instant::now() > deadline {
        bail!("sanitized reviewer view enumeration exceeded its bounds");
    }
    for name in review_directory_entries(directory, deadline)? {
        let path = relative.join(&name);
        validate_snapshot_relative_path(&path)?;
        if !paths.insert(path.clone()) || paths.len() > REVIEW_SNAPSHOT_ENTRY_LIMIT {
            bail!("sanitized reviewer view enumeration exceeded its entry limit");
        }
        let name = c_string(&name)?;
        let stat = stat_at_nofollow(directory, &name)?;
        match stat.st_mode & libc::S_IFMT {
            libc::S_IFDIR => {
                let fd = unsafe {
                    libc::openat(
                        directory.as_raw_fd(),
                        name.as_ptr(),
                        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    )
                };
                if fd < 0 {
                    return Err(std::io::Error::last_os_error())
                        .context("failed to bind sanitized reviewer directory");
                }
                let child = unsafe { File::from_raw_fd(fd) };
                collect_sanitized_view_directory(
                    &child,
                    &path,
                    depth.saturating_add(1),
                    deadline,
                    paths,
                )?;
            }
            libc::S_IFREG | libc::S_IFLNK => {}
            _ => bail!("sanitized reviewer view contains a special file"),
        }
    }
    Ok(())
}

impl BoundReviewerProgram {
    fn bind_absolute_canonical(path: &Path) -> Result<Self> {
        validate_reviewer_program_path(path)?;
        if !path.is_absolute() {
            bail!("reviewer interpreter must resolve to a canonical absolute path");
        }
        Ok(Self {
            path: path.to_path_buf(),
            file: read_absolute_reviewer_program(path)?,
        })
    }
}

fn reviewer_script_interpreter(bytes: &[u8]) -> Result<Option<PathBuf>> {
    if !bytes.starts_with(b"#!") {
        return Ok(None);
    }
    let first_line = bytes
        .split(|byte| *byte == b'\n')
        .next()
        .context("reviewer script shebang is missing")?;
    let shebang = std::str::from_utf8(&first_line[2..])
        .context("reviewer script shebang is not valid UTF-8")?
        .trim();
    if shebang.is_empty() || shebang.chars().any(char::is_whitespace) {
        bail!("reviewer script shebang arguments are unsupported");
    }
    let requested = Path::new(shebang);
    if !requested.is_absolute() {
        bail!("reviewer script shebang must use an absolute interpreter");
    }
    let canonical = requested
        .canonicalize()
        .context("reviewer script interpreter could not be resolved")?;
    validate_reviewer_program_path(&canonical)?;
    if is_native_dispatcher_program(requested) || is_native_dispatcher_program(&canonical) {
        bail!("reviewer script shebang command dispatchers are unsupported");
    }
    Ok(Some(canonical))
}

fn validate_verified_reviewer_program(
    repository: &ReviewRepositoryBinding,
    program: &BoundReviewerProgram,
    args: &[String],
) -> Result<()> {
    let configured = if program.path.is_absolute() {
        program.path.clone()
    } else {
        repository.worktree_root.path().join(&program.path)
    };
    let canonical = configured
        .canonicalize()
        .context("verified reviewer program could not be resolved")?;
    validate_reviewer_program_path(&canonical)?;
    verify_canonical_reviewer_identity(&canonical, &program.file.identity)?;
    validate_verified_reviewer_image(&program.path, &canonical, args, &program.file.bytes)
}

fn validate_verified_reviewer_image(
    configured: &Path,
    canonical: &Path,
    _args: &[String],
    bytes: &[u8],
) -> Result<()> {
    if reviewer_script_interpreter(bytes)?.is_some() {
        return Ok(());
    }
    if is_native_interpreter_or_dispatcher_program(configured)
        || is_native_interpreter_or_dispatcher_program(canonical)
    {
        bail!(
            "verified external reviewer direct program cannot be a shell, language interpreter, or command dispatcher; use a dedicated compiled reviewer or an executable reviewer script with a direct absolute shebang"
        );
    }
    Ok(())
}

fn verify_canonical_reviewer_identity(path: &Path, expected: &FileIdentity) -> Result<()> {
    #[cfg(unix)]
    {
        let metadata = std::fs::symlink_metadata(path)
            .context("verified reviewer canonical identity could not be inspected")?;
        if !metadata.is_file()
            || metadata.dev() != expected.device
            || metadata.ino() != expected.file
        {
            bail!("verified reviewer canonical identity changed during binding");
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = (path, expected);
        bail!("verified reviewer canonical identity is unsupported on this platform")
    }
}

fn is_native_interpreter_or_dispatcher_program(path: &Path) -> bool {
    let Some(name) = normalized_program_basename(path) else {
        return true;
    };
    const EXACT_NAMES: &[&str] = &[
        "ash",
        "awk",
        "bash",
        "bun",
        "busybox",
        "chroot",
        "coreutils",
        "csh",
        "dash",
        "deno",
        "dotnet",
        "env",
        "fish",
        "gawk",
        "groovy",
        "irb",
        "java",
        "js",
        "jshell",
        "ksh",
        "kotlin",
        "luajit",
        "mawk",
        "mksh",
        "mono",
        "nawk",
        "nice",
        "node",
        "nodejs",
        "nohup",
        "nu",
        "pdksh",
        "php",
        "pwsh",
        "qjs",
        "r",
        "rscript",
        "runuser",
        "setsid",
        "sh",
        "stdbuf",
        "su",
        "sudo",
        "tcsh",
        "timeout",
        "wish",
        "xargs",
        "yash",
        "zsh",
    ];
    EXACT_NAMES.contains(&name.as_str())
        || ["lua", "perl", "pypy", "python", "ruby", "tclsh"]
            .iter()
            .any(|prefix| is_versioned_program_name(&name, prefix))
}

fn is_native_dispatcher_program(path: &Path) -> bool {
    let Some(name) = normalized_program_basename(path) else {
        return true;
    };
    matches!(
        name.as_str(),
        "busybox"
            | "chroot"
            | "coreutils"
            | "env"
            | "nice"
            | "nohup"
            | "runuser"
            | "setsid"
            | "stdbuf"
            | "su"
            | "sudo"
            | "timeout"
            | "xargs"
    )
}

fn normalized_program_basename(path: &Path) -> Option<String> {
    let name = path.file_name()?.to_str()?.to_ascii_lowercase();
    Some(name.strip_suffix(".exe").unwrap_or(&name).to_string())
}

fn is_versioned_program_name(name: &str, prefix: &str) -> bool {
    if name == prefix {
        return true;
    }
    name.strip_prefix(prefix).is_some_and(|suffix| {
        !suffix.is_empty()
            && suffix
                .bytes()
                .all(|byte| byte.is_ascii_digit() || byte == b'.' || byte == b'-')
    })
}

fn rewrite_reviewer_shebang(bytes: &[u8], interpreter: &Path) -> Result<Vec<u8>> {
    let newline = bytes
        .iter()
        .position(|byte| *byte == b'\n')
        .unwrap_or(bytes.len());
    let rest = if newline < bytes.len() {
        &bytes[newline.saturating_add(1)..]
    } else {
        &[]
    };
    let interpreter = interpreter
        .to_str()
        .context("materialized reviewer interpreter path is not valid UTF-8")?;
    let mut rewritten = format!("#!{interpreter}\n").into_bytes();
    rewritten.extend_from_slice(rest);
    if rewritten.len() > usize::try_from(REVIEW_SNAPSHOT_FILE_LIMIT_BYTES).unwrap_or(usize::MAX) {
        bail!("materialized reviewer script exceeds its bounded size");
    }
    Ok(rewritten)
}

fn materialize_reviewer_file(path: &Path, bytes: &[u8]) -> Result<MaterializedReviewerFile> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mut options = std::fs::OpenOptions::new();
        options
            .write(true)
            .create_new(true)
            .mode(0o500)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        let mut file = options
            .open(path)
            .context("failed to create materialized reviewer file")?;
        file.write_all(bytes)
            .context("failed to write materialized reviewer file")?;
        file.sync_all()
            .context("failed to flush materialized reviewer file")?;
        file.set_permissions(std::fs::Permissions::from_mode(0o500))?;
        file.sync_all()
            .context("failed to flush materialized reviewer file mode")?;
        drop(file);
        File::open(
            path.parent()
                .context("materialized reviewer file has no parent")?,
        )?
        .sync_all()?;
        materialized_reviewer_file(path)
    }
    #[cfg(not(unix))]
    {
        let _ = (path, bytes);
        bail!("reviewer file materialization is unsupported on this platform")
    }
}

fn materialized_reviewer_file(path: &Path) -> Result<MaterializedReviewerFile> {
    #[cfg(unix)]
    {
        let mut options = std::fs::OpenOptions::new();
        options
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
        let mut file = options
            .open(path)
            .context("failed to open materialized reviewer file")?;
        let before = fstat_file(&file)?;
        if before.st_mode & libc::S_IFMT != libc::S_IFREG
            || before.st_nlink != 1
            || before.st_uid != unsafe { libc::geteuid() }
            || before.st_mode & 0o777 != 0o500
        {
            bail!("materialized reviewer file metadata is unsafe");
        }
        let length = u64::try_from(before.st_size)
            .context("materialized reviewer file has a negative length")?;
        if length == 0 || length > REVIEW_SNAPSHOT_FILE_LIMIT_BYTES {
            bail!("materialized reviewer file is empty or oversized");
        }
        let mut contents = Vec::with_capacity(
            usize::try_from(length).context("materialized reviewer file length does not fit")?,
        );
        (&mut file)
            .take(REVIEW_SNAPSHOT_FILE_LIMIT_BYTES.saturating_add(1))
            .read_to_end(&mut contents)?;
        let after = fstat_file(&file)?;
        if u64::try_from(contents.len()).unwrap_or(u64::MAX) != length
            || !same_stat_generation(&before, &after)
        {
            bail!("materialized reviewer file changed during verification");
        }
        Ok(MaterializedReviewerFile {
            mode: unsigned_to_u32(before.st_mode),
            length,
            sha256: sha256_bytes(&contents),
            identity: file_identity_from_stat(&before),
        })
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        bail!("materialized reviewer verification is unsupported on this platform")
    }
}

fn validate_reviewer_program_path(path: &Path) -> Result<()> {
    if !path.is_absolute() {
        return validate_repo_relative_path(path, "external reviewer program");
    }
    let encoded = path
        .to_str()
        .context("external reviewer program path must be valid UTF-8")?;
    if encoded.len() > REVIEW_PATH_LIMIT_BYTES || encoded.chars().any(char::is_control) {
        bail!("external reviewer program path is invalid or out of bounds");
    }
    if encoded.contains("//") || encoded.ends_with('/') {
        bail!("external reviewer program path is not canonical absolute form");
    }
    for component in path.components() {
        if !matches!(
            component,
            std::path::Component::RootDir | std::path::Component::Normal(_)
        ) {
            bail!("external reviewer program path is not canonical absolute form");
        }
    }
    Ok(())
}

fn is_shell_program(path: &Path) -> bool {
    path.file_name()
        .and_then(OsStr::to_str)
        .is_some_and(|name| matches!(name, "sh" | "bash" | "dash" | "zsh" | "ksh" | "fish"))
}

fn shell_args_request_command(args: &[String]) -> bool {
    args.iter()
        .take_while(|arg| arg.as_str() != "--")
        .any(|arg| {
            arg == "--command"
                || arg.starts_with("--command=")
                || arg
                    .strip_prefix('-')
                    .filter(|option| !option.starts_with('-'))
                    .is_some_and(|option| option.bytes().any(|byte| byte == b'c'))
        })
}

fn read_worktree_reviewer_program(
    repository: &ReviewRepositoryBinding,
    path: &Path,
) -> Result<BoundReviewerProgramFile> {
    let reader = ReviewTreeReader::bind(&repository.worktree_root)?;
    let mut total_content_bytes = 0u64;
    let entry = reader.snapshot_entry(path, &mut total_content_bytes)?;
    reader.verify(&repository.worktree_root)?;
    let bytes = BoundedRegularReader::read_relative(
        repository.worktree_root.path(),
        path,
        REVIEW_SNAPSHOT_FILE_LIMIT_BYTES,
    )
    .map_err(|_| anyhow::anyhow!("external reviewer program bounded read was refused"))?;
    let mut verify_total = 0u64;
    let verified_entry = reader.snapshot_entry(path, &mut verify_total)?;
    reader.verify(&repository.worktree_root)?;
    if entry != verified_entry {
        bail!("external reviewer program changed during binding");
    }
    match entry {
        SnapshotTreeEntry::Regular {
            mode,
            length,
            sha256,
            identity,
            modified_seconds,
            modified_nanoseconds,
            changed_seconds,
            changed_nanoseconds,
        } if length > 0
            && mode & 0o111 != 0
            && u64::try_from(bytes.len()).unwrap_or(u64::MAX) == length
            && sha256_bytes(&bytes) == sha256 =>
        {
            Ok(BoundReviewerProgramFile {
                mode,
                length,
                sha256,
                identity,
                modified_seconds,
                modified_nanoseconds,
                changed_seconds,
                changed_nanoseconds,
                bytes,
            })
        }
        SnapshotTreeEntry::Regular { .. } => {
            bail!("external reviewer program must be a non-empty executable regular file")
        }
        SnapshotTreeEntry::Missing | SnapshotTreeEntry::Symlink { .. } => {
            bail!("external reviewer program must be a bound no-follow regular file")
        }
    }
}

fn read_absolute_reviewer_program(path: &Path) -> Result<BoundReviewerProgramFile> {
    #[cfg(unix)]
    {
        let mut options = std::fs::OpenOptions::new();
        options
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
        let mut file = options
            .open(path)
            .context("failed to open absolute reviewer program without following links")?;
        let before = fstat_file(&file)?;
        if before.st_mode & libc::S_IFMT != libc::S_IFREG || before.st_mode & 0o111 == 0 {
            bail!("absolute reviewer program must be an executable regular file");
        }
        let length = u64::try_from(before.st_size)
            .context("absolute reviewer program has a negative length")?;
        if length == 0 || length > REVIEW_SNAPSHOT_FILE_LIMIT_BYTES {
            bail!("absolute reviewer program is empty or exceeds its bounded size");
        }
        let mut contents = Vec::with_capacity(
            usize::try_from(length).context("absolute reviewer program length does not fit")?,
        );
        (&mut file)
            .take(REVIEW_SNAPSHOT_FILE_LIMIT_BYTES.saturating_add(1))
            .read_to_end(&mut contents)
            .context("failed to read absolute reviewer program")?;
        let after = fstat_file(&file)?;
        if u64::try_from(contents.len()).unwrap_or(u64::MAX) != length
            || !same_stat_generation(&before, &after)
        {
            bail!("absolute reviewer program changed during bounded read");
        }
        Ok(BoundReviewerProgramFile {
            mode: unsigned_to_u32(before.st_mode),
            length,
            sha256: sha256_bytes(&contents),
            identity: file_identity_from_stat(&before),
            modified_seconds: before.st_mtime,
            modified_nanoseconds: stat_modified_nanoseconds(&before),
            changed_seconds: before.st_ctime,
            changed_nanoseconds: stat_changed_nanoseconds(&before),
            bytes: contents,
        })
    }
    #[cfg(not(unix))]
    bail!("absolute no-follow reviewer programs are unsupported on this platform")
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct GitBacklinkSnapshot {
    kind: String,
    mode: u32,
    identity: FileIdentity,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
    content_sha256: Option<String>,
}

#[derive(Debug)]
struct ReviewRepositoryBinding {
    worktree_root: SafeRoot,
    git_dir_root: SafeRoot,
    common_dir_root: SafeRoot,
    state: ReviewStateBinding,
}

#[derive(Debug)]
enum ReviewStateBinding {
    MissingMaco,
    MissingState {
        maco_root: SafeRoot,
    },
    Bound {
        maco_root: SafeRoot,
        state_root: SafeRoot,
    },
}

impl ReviewRepositoryBinding {
    fn bind(path: &Path) -> Result<Self> {
        let repository =
            crate::git_repository::open(path).context("failed to bind review repository")?;
        let worktree = repository
            .workdir()
            .context("review requires a non-bare repository")?;
        let worktree_root = SafeRoot::open_existing(worktree)
            .map_err(|_| anyhow::anyhow!("review worktree binding is unsafe"))?;
        let git_dir_root = SafeRoot::open_existing(repository.path())
            .map_err(|_| anyhow::anyhow!("review Git directory binding is unsafe"))?;
        let common_dir_root = SafeRoot::open_existing(repository.commondir())
            .map_err(|_| anyhow::anyhow!("review Git common directory binding is unsafe"))?;
        let state = bind_review_state(&common_dir_root)?;
        let binding = Self {
            worktree_root,
            git_dir_root,
            common_dir_root,
            state,
        };
        binding.verify()?;
        Ok(binding)
    }

    fn verify(&self) -> Result<()> {
        self.worktree_root
            .verify()
            .map_err(|_| anyhow::anyhow!("review worktree identity changed"))?;
        self.git_dir_root
            .verify()
            .map_err(|_| anyhow::anyhow!("review Git directory identity changed"))?;
        self.common_dir_root
            .verify()
            .map_err(|_| anyhow::anyhow!("review Git common directory identity changed"))?;
        self.state.verify(&self.common_dir_root)?;

        let rebound = crate::git_repository::open(self.worktree_root.path())
            .context("review repository could not be rebound")?;
        let rebound_git = SafeRoot::open_existing(rebound.path())
            .map_err(|_| anyhow::anyhow!("review Git directory rebound is unsafe"))?;
        let rebound_common = SafeRoot::open_existing(rebound.commondir())
            .map_err(|_| anyhow::anyhow!("review Git common directory rebound is unsafe"))?;
        if rebound_git.identity() != self.git_dir_root.identity()
            || rebound_common.identity() != self.common_dir_root.identity()
        {
            bail!("review Git administrative binding changed");
        }
        Ok(())
    }

    #[cfg(test)]
    fn confinement_profile(&self) -> Result<StrictOfflineWorkspaceProfile> {
        self.verify()?;
        let profile = StrictOfflineWorkspaceProfile::read_only(self.worktree_root.path());
        Ok(match &self.state {
            ReviewStateBinding::Bound { state_root, .. } => {
                profile.with_hidden_root(state_root.path())
            }
            ReviewStateBinding::MissingMaco | ReviewStateBinding::MissingState { .. } => profile,
        })
    }

    fn sanitized_confinement_profile(
        &self,
        view_root: &Path,
        materialized_reviewer_root: &Path,
    ) -> Result<StrictOfflineWorkspaceProfile> {
        self.verify()?;
        let mut hidden = BTreeSet::new();
        for root in [
            self.worktree_root.path(),
            self.git_dir_root.path(),
            self.common_dir_root.path(),
        ] {
            hidden.insert(root.to_path_buf());
            if let Some(parent) = root.parent().filter(|path| *path != Path::new("/")) {
                hidden.insert(parent.to_path_buf());
            }
        }
        if let ReviewStateBinding::Bound { state_root, .. } = &self.state {
            hidden.insert(state_root.path().to_path_buf());
        }
        let hidden = minimal_sanitized_hidden_roots(hidden);
        let mut profile = StrictOfflineWorkspaceProfile::read_only(view_root)
            .with_visible_read_only_root("/nix/store")
            .with_visible_read_only_root(materialized_reviewer_root)
            .with_isolated_host_view();
        for root in hidden {
            profile = profile.with_hidden_root(root);
        }
        Ok(profile)
    }

    fn snapshot(&self) -> Result<ReviewRepoSnapshot> {
        self.verify()?;
        let repository = crate::git_repository::open(self.worktree_root.path())
            .context("failed to open bound review repository")?;
        let (head, head_name) = match repository.head() {
            Ok(head) => {
                let name = head
                    .name()
                    .map(ToOwned::to_owned)
                    .context("review HEAD name is not valid UTF-8")?;
                (head.target().map(|oid| oid.to_string()), Some(name))
            }
            Err(error) if error.code() == git2::ErrorCode::UnbornBranch => (None, None),
            Err(error) => return Err(error).context("failed to read review HEAD"),
        };
        let head_symbolic_target = match repository.find_reference("HEAD") {
            Ok(reference) => reference
                .symbolic_target()
                .context("review HEAD symbolic target is not valid UTF-8")?
                .map(ToOwned::to_owned),
            Err(error) if error.code() == git2::ErrorCode::NotFound => None,
            Err(error) => return Err(error).context("failed to read review HEAD backlink"),
        };
        let git_admin_reader = ReviewTreeReader::bind(&self.git_dir_root)?;
        let common_admin_reader = ReviewTreeReader::bind(&self.common_dir_root)?;
        let mut admin_content_bytes = 0u64;
        let head_admin_sha256 = snapshot_regular_entry_digest(
            &git_admin_reader,
            Path::new("HEAD"),
            &mut admin_content_bytes,
            REVIEW_PATH_LIMIT_BYTES as u64,
            true,
            "review HEAD state",
        )?
        .context("review HEAD state is missing")?;
        let current_ref_name = head_symbolic_target.as_deref().or(head_name.as_deref());
        let head_ref_sha256 = if let Some(reference) = current_ref_name {
            validate_git_reference_path(reference)?;
            snapshot_regular_entry_digest(
                &common_admin_reader,
                Path::new(reference),
                &mut admin_content_bytes,
                REVIEW_PATH_LIMIT_BYTES as u64,
                false,
                "review HEAD reference",
            )?
        } else {
            None
        };
        let packed_refs_sha256 = snapshot_regular_entry_digest(
            &common_admin_reader,
            Path::new("packed-refs"),
            &mut admin_content_bytes,
            REVIEW_SNAPSHOT_FILE_LIMIT_BYTES,
            false,
            "review packed-refs",
        )?;
        let index_sha256 = snapshot_regular_entry_digest(
            &git_admin_reader,
            Path::new("index"),
            &mut admin_content_bytes,
            REVIEW_SNAPSHOT_FILE_LIMIT_BYTES,
            false,
            "review index",
        )?;
        git_admin_reader.verify(&self.git_dir_root)?;
        common_admin_reader.verify(&self.common_dir_root)?;

        let prewalk_reader = ReviewTreeReader::bind(&self.worktree_root)?;
        prewalk_reader.prewalk()?;
        prewalk_reader.verify(&self.worktree_root)?;

        let mut origins = BTreeMap::<PathBuf, SnapshotPathOrigin>::new();
        let index = repository.index().context("failed to read review index")?;
        for entry in index.iter() {
            if entry.mode & 0o170000 == 0o160000 {
                bail!(
                    "review repository contains a gitlink/submodule; exact submodule snapshots are unsupported"
                );
            }
            let path = path_from_git_bytes(&entry.path)?;
            validate_snapshot_relative_path(&path)?;
            origins.entry(path).or_default().tracked = true;
            if origins.len() > REVIEW_SNAPSHOT_ENTRY_LIMIT {
                bail!(
                    "review repository exceeds its {} entry snapshot limit",
                    REVIEW_SNAPSHOT_ENTRY_LIMIT
                );
            }
        }

        let mut status_options = git2::StatusOptions::new();
        status_options
            .include_untracked(true)
            .recurse_untracked_dirs(true)
            .include_ignored(true)
            .recurse_ignored_dirs(true);
        let statuses = repository
            .statuses(Some(&mut status_options))
            .context("failed to enumerate review repository status")?;
        if statuses.len() > REVIEW_SNAPSHOT_ENTRY_LIMIT {
            bail!(
                "review status exceeds its {} entry limit",
                REVIEW_SNAPSHOT_ENTRY_LIMIT
            );
        }
        let mut status_material = Vec::new();
        for entry in statuses.iter() {
            let path = path_from_git_bytes(entry.path_bytes())?;
            validate_snapshot_relative_path(&path)?;
            append_snapshot_bytes(&mut status_material, &path_bytes(&path))?;
            status_material.extend_from_slice(&entry.status().bits().to_be_bytes());
            if entry.status().contains(git2::Status::WT_NEW) {
                origins.entry(path).or_default().untracked = true;
                if origins.len() > REVIEW_SNAPSHOT_ENTRY_LIMIT {
                    bail!(
                        "review repository exceeds its {} entry snapshot limit",
                        REVIEW_SNAPSHOT_ENTRY_LIMIT
                    );
                }
            } else if entry.status().contains(git2::Status::IGNORED) {
                origins.entry(path).or_default().ignored = true;
                if origins.len() > REVIEW_SNAPSHOT_ENTRY_LIMIT {
                    bail!(
                        "review repository exceeds its {} entry snapshot limit",
                        REVIEW_SNAPSHOT_ENTRY_LIMIT
                    );
                }
            }
        }

        let reader = ReviewTreeReader::bind(&self.worktree_root)?;
        let mut worktree_material = Vec::new();
        let mut total_content_bytes = 0u64;
        for (path, origin) in &origins {
            append_snapshot_bytes(&mut worktree_material, &path_bytes(path))?;
            worktree_material.push(u8::from(origin.tracked));
            worktree_material.push(u8::from(origin.untracked));
            worktree_material.push(u8::from(origin.ignored));
            let entry = reader.snapshot_entry(path, &mut total_content_bytes)?;
            entry.append_canonical(&mut worktree_material);
        }
        reader.verify(&self.worktree_root)?;
        let git_backlink = reader.snapshot_git_backlink()?;
        self.verify()?;

        Ok(ReviewRepoSnapshot {
            head,
            head_name,
            head_symbolic_target,
            head_admin_sha256,
            head_ref_sha256,
            packed_refs_sha256,
            index_sha256,
            status_sha256: sha256_hex(&status_material),
            worktree_sha256: sha256_hex(&worktree_material),
            entry_count: origins.len(),
            total_content_bytes,
            worktree_identity: self.worktree_root.identity().clone(),
            git_dir_identity: self.git_dir_root.identity().clone(),
            common_dir_identity: self.common_dir_root.identity().clone(),
            git_backlink,
            state_identity: self.state.identity(),
        })
    }
}

include!("review/part2.rs");

#[cfg(test)]
mod tests;
