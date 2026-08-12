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
            Self::FullChildTranscript { .. } => ReviewInformationScope::FullChildTranscript,
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
    let git = git2::Repository::open(repository.worktree_root.path())
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
            git2::Repository::open(path).context("failed to bind review repository")?;
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

        let rebound = git2::Repository::open(self.worktree_root.path())
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
        let repository = git2::Repository::open(self.worktree_root.path())
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

impl ReviewStateBinding {
    fn verify(&self, common_root: &SafeRoot) -> Result<()> {
        match self {
            Self::MissingMaco => {
                if common_root.direct_child_exists("maco")? {
                    bail!("review Git state root appeared during review");
                }
            }
            Self::MissingState { maco_root } => {
                maco_root
                    .verify()
                    .map_err(|_| anyhow::anyhow!("review Git state parent changed"))?;
                if maco_root.direct_child_exists("state")? {
                    bail!("review Git state root appeared during review");
                }
            }
            Self::Bound {
                maco_root,
                state_root,
            } => {
                maco_root
                    .verify()
                    .map_err(|_| anyhow::anyhow!("review Git state parent changed"))?;
                state_root
                    .verify()
                    .map_err(|_| anyhow::anyhow!("review Git state root changed"))?;
            }
        }
        Ok(())
    }

    fn identity(&self) -> Option<FileIdentity> {
        match self {
            Self::Bound { state_root, .. } => Some(state_root.identity().clone()),
            Self::MissingMaco | Self::MissingState { .. } => None,
        }
    }
}

fn minimal_sanitized_hidden_roots(roots: BTreeSet<PathBuf>) -> Vec<PathBuf> {
    let mut roots = roots.into_iter().collect::<Vec<_>>();
    roots.sort_by(|left, right| {
        left.components()
            .count()
            .cmp(&right.components().count())
            .then_with(|| left.cmp(right))
    });
    let mut minimal = Vec::<PathBuf>::new();
    for root in roots {
        if minimal.iter().any(|ancestor| root.starts_with(ancestor)) {
            continue;
        }
        minimal.push(root);
    }
    minimal
}

fn bind_review_state(common_root: &SafeRoot) -> Result<ReviewStateBinding> {
    if !common_root.direct_child_exists("maco")? {
        return Ok(ReviewStateBinding::MissingMaco);
    }
    let maco = common_root
        .bind_existing_managed_direct_child_directory("maco")
        .map_err(|_| anyhow::anyhow!("review Git state parent is unsafe"))?;
    let maco_root = SafeRoot::open_existing(maco.path())
        .map_err(|_| anyhow::anyhow!("review Git state parent binding is unsafe"))?;
    if !maco_root.direct_child_exists("state")? {
        return Ok(ReviewStateBinding::MissingState { maco_root });
    }
    let state = maco_root
        .bind_existing_managed_direct_child_directory("state")
        .map_err(|_| anyhow::anyhow!("review Git state root is unsafe"))?;
    let state_root = SafeRoot::open_existing(state.path())
        .map_err(|_| anyhow::anyhow!("review Git state root binding is unsafe"))?;
    Ok(ReviewStateBinding::Bound {
        maco_root,
        state_root,
    })
}

#[derive(Debug, Default, Clone, Copy)]
struct SnapshotPathOrigin {
    tracked: bool,
    untracked: bool,
    ignored: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
enum SnapshotTreeEntry {
    Missing,
    Regular {
        mode: u32,
        length: u64,
        sha256: [u8; 32],
        identity: FileIdentity,
        modified_seconds: i64,
        modified_nanoseconds: i64,
        changed_seconds: i64,
        changed_nanoseconds: i64,
    },
    Symlink {
        mode: u32,
        target: Vec<u8>,
        identity: FileIdentity,
        modified_seconds: i64,
        modified_nanoseconds: i64,
        changed_seconds: i64,
        changed_nanoseconds: i64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BoundReviewDirectory {
    mode: u32,
    identity: FileIdentity,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

impl SnapshotTreeEntry {
    fn append_canonical(&self, output: &mut Vec<u8>) {
        match self {
            Self::Missing => output.push(0),
            Self::Regular {
                mode,
                length,
                sha256,
                identity,
                modified_seconds,
                modified_nanoseconds,
                changed_seconds,
                changed_nanoseconds,
            } => {
                output.push(1);
                output.extend_from_slice(&mode.to_be_bytes());
                output.extend_from_slice(&length.to_be_bytes());
                output.extend_from_slice(sha256);
                append_file_generation(
                    output,
                    identity,
                    *modified_seconds,
                    *modified_nanoseconds,
                    *changed_seconds,
                    *changed_nanoseconds,
                );
            }
            Self::Symlink {
                mode,
                target,
                identity,
                modified_seconds,
                modified_nanoseconds,
                changed_seconds,
                changed_nanoseconds,
            } => {
                output.push(2);
                output.extend_from_slice(&mode.to_be_bytes());
                output.extend_from_slice(
                    &u64::try_from(target.len())
                        .unwrap_or(u64::MAX)
                        .to_be_bytes(),
                );
                output.extend_from_slice(target);
                append_file_generation(
                    output,
                    identity,
                    *modified_seconds,
                    *modified_nanoseconds,
                    *changed_seconds,
                    *changed_nanoseconds,
                );
            }
        }
    }
}

fn append_file_generation(
    output: &mut Vec<u8>,
    identity: &FileIdentity,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
) {
    output.extend_from_slice(&identity.device.to_be_bytes());
    output.extend_from_slice(&identity.file.to_be_bytes());
    output.extend_from_slice(&modified_seconds.to_be_bytes());
    output.extend_from_slice(&modified_nanoseconds.to_be_bytes());
    output.extend_from_slice(&changed_seconds.to_be_bytes());
    output.extend_from_slice(&changed_nanoseconds.to_be_bytes());
}

#[derive(Debug)]
struct ReviewTreeReader {
    #[cfg(unix)]
    root: File,
    identity: FileIdentity,
}

impl ReviewTreeReader {
    fn bind(root: &SafeRoot) -> Result<Self> {
        root.verify()
            .map_err(|_| anyhow::anyhow!("review worktree root is unsafe"))?;
        #[cfg(unix)]
        {
            let mut options = std::fs::OpenOptions::new();
            options
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC);
            let file = options
                .open(root.path())
                .context("failed to open bound review worktree")?;
            let metadata = file
                .metadata()
                .context("failed to inspect bound review worktree")?;
            let identity = file_identity_from_metadata(&metadata);
            if &identity != root.identity() {
                bail!("review worktree descriptor does not match its safe root");
            }
            Ok(Self {
                root: file,
                identity,
            })
        }
        #[cfg(not(unix))]
        {
            let _ = root;
            bail!("exact no-follow review snapshots are unsupported on this platform")
        }
    }

    fn verify(&self, root: &SafeRoot) -> Result<()> {
        root.verify()
            .map_err(|_| anyhow::anyhow!("review worktree root changed"))?;
        if &self.identity != root.identity() {
            bail!("review worktree root identity changed");
        }
        #[cfg(unix)]
        {
            let metadata = self
                .root
                .metadata()
                .context("failed to revalidate review worktree descriptor")?;
            if file_identity_from_metadata(&metadata) != self.identity {
                bail!("review worktree descriptor identity changed");
            }
            Ok(())
        }
        #[cfg(not(unix))]
        bail!("exact no-follow review snapshots are unsupported on this platform")
    }

    fn snapshot_directory(&self, path: &Path) -> Result<BoundReviewDirectory> {
        validate_snapshot_relative_path(path)?;
        #[cfg(unix)]
        {
            let (parent, name) = self
                .open_parent(path)?
                .context("review directory parent is missing or unsafe")?;
            let name_c = c_string(&name)?;
            let before =
                stat_at_nofollow(&parent, &name_c).context("failed to inspect review directory")?;
            if before.st_uid != unsafe { libc::geteuid() }
                || before.st_mode & libc::S_IFMT != libc::S_IFDIR
            {
                bail!("review directory identity or ownership is unsafe");
            }
            let fd = unsafe {
                libc::openat(
                    parent.as_raw_fd(),
                    name_c.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if fd < 0 {
                return Err(std::io::Error::last_os_error())
                    .context("failed to bind review directory without following links");
            }
            let directory = unsafe { File::from_raw_fd(fd) };
            let opened = fstat_file(&directory)?;
            if !same_stat_generation(&before, &opened) {
                bail!("review directory changed during binding");
            }
            Ok(BoundReviewDirectory {
                mode: unsigned_to_u32(opened.st_mode),
                identity: file_identity_from_stat(&opened),
                modified_seconds: opened.st_mtime,
                modified_nanoseconds: stat_modified_nanoseconds(&opened),
                changed_seconds: opened.st_ctime,
                changed_nanoseconds: stat_changed_nanoseconds(&opened),
            })
        }
        #[cfg(not(unix))]
        bail!("exact no-follow review directories are unsupported on this platform")
    }

    fn prewalk(&self) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            let deadline = Instant::now()
                .checked_add(REVIEW_PREWALK_TIMEOUT)
                .context("review prewalk deadline overflow")?;
            let root_stat = fstat_file(&self.root)?;
            let mut entry_count = 0usize;
            let mut total_bytes = 0u64;
            prewalk_review_directory(
                &self.root,
                Path::new(""),
                root_stat.st_dev,
                0,
                &mut entry_count,
                &mut total_bytes,
                deadline,
            )
        }
        #[cfg(not(target_os = "linux"))]
        bail!("bounded descriptor review prewalk is unsupported on this platform")
    }

    fn snapshot_entry(
        &self,
        path: &Path,
        total_content_bytes: &mut u64,
    ) -> Result<SnapshotTreeEntry> {
        validate_snapshot_relative_path(path)?;
        #[cfg(unix)]
        {
            let Some((parent, name)) = self.open_parent(path)? else {
                return Ok(SnapshotTreeEntry::Missing);
            };
            let name_c = c_string(&name)?;
            let before = match stat_at_nofollow(&parent, &name_c) {
                Ok(stat) => stat,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    return Ok(SnapshotTreeEntry::Missing)
                }
                Err(error) => return Err(error).context("failed to inspect review worktree entry"),
            };
            validate_snapshot_entry_owner_and_links(&before)?;
            let file_type = before.st_mode & libc::S_IFMT;
            let mode = unsigned_to_u32(before.st_mode);
            if file_type == libc::S_IFREG {
                let length = u64::try_from(before.st_size)
                    .context("review worktree file has a negative length")?;
                if length > REVIEW_SNAPSHOT_FILE_LIMIT_BYTES {
                    bail!(
                        "review worktree file exceeds its {} byte limit",
                        REVIEW_SNAPSHOT_FILE_LIMIT_BYTES
                    );
                }
                let next_total = total_content_bytes
                    .checked_add(length)
                    .context("review snapshot content-byte total overflow")?;
                if next_total > REVIEW_SNAPSHOT_TOTAL_LIMIT_BYTES {
                    bail!(
                        "review worktree exceeds its {} byte total snapshot limit",
                        REVIEW_SNAPSHOT_TOTAL_LIMIT_BYTES
                    );
                }
                let fd = unsafe {
                    libc::openat(
                        parent.as_raw_fd(),
                        name_c.as_ptr(),
                        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
                    )
                };
                if fd < 0 {
                    return Err(std::io::Error::last_os_error())
                        .context("failed to open review worktree file without following links");
                }
                let mut file = unsafe { File::from_raw_fd(fd) };
                let opened = fstat_file(&file)?;
                if !same_stat_generation(&before, &opened) {
                    bail!("review worktree file changed before bounded read");
                }
                let capacity = usize::try_from(length)
                    .context("review worktree file length does not fit memory")?;
                let mut contents = Vec::with_capacity(capacity);
                (&mut file)
                    .take(REVIEW_SNAPSHOT_FILE_LIMIT_BYTES.saturating_add(1))
                    .read_to_end(&mut contents)
                    .context("failed to read review worktree file")?;
                if u64::try_from(contents.len()).unwrap_or(u64::MAX) != length {
                    bail!("review worktree file changed during bounded read");
                }
                let after = fstat_file(&file)?;
                if !same_stat_generation(&opened, &after) {
                    bail!("review worktree file changed during bounded read");
                }
                *total_content_bytes = next_total;
                Ok(SnapshotTreeEntry::Regular {
                    mode,
                    length,
                    sha256: sha256_bytes(&contents),
                    identity: file_identity_from_stat(&opened),
                    modified_seconds: opened.st_mtime,
                    modified_nanoseconds: stat_modified_nanoseconds(&opened),
                    changed_seconds: opened.st_ctime,
                    changed_nanoseconds: stat_changed_nanoseconds(&opened),
                })
            } else if file_type == libc::S_IFLNK {
                let mut target = vec![0u8; REVIEW_SYMLINK_LIMIT_BYTES.saturating_add(1)];
                let read = unsafe {
                    libc::readlinkat(
                        parent.as_raw_fd(),
                        name_c.as_ptr(),
                        target.as_mut_ptr().cast(),
                        target.len(),
                    )
                };
                if read < 0 {
                    return Err(std::io::Error::last_os_error())
                        .context("failed to read review worktree symlink without following it");
                }
                let read = usize::try_from(read).context("review symlink length overflow")?;
                if read > REVIEW_SYMLINK_LIMIT_BYTES {
                    bail!(
                        "review worktree symlink exceeds its {} byte target limit",
                        REVIEW_SYMLINK_LIMIT_BYTES
                    );
                }
                target.truncate(read);
                let after = stat_at_nofollow(&parent, &name_c)
                    .context("failed to revalidate review worktree symlink")?;
                if !same_stat_generation(&before, &after) {
                    bail!("review worktree symlink changed during snapshot");
                }
                validate_internal_symlink_target(path, &target)?;
                Ok(SnapshotTreeEntry::Symlink {
                    mode,
                    target,
                    identity: file_identity_from_stat(&before),
                    modified_seconds: before.st_mtime,
                    modified_nanoseconds: stat_modified_nanoseconds(&before),
                    changed_seconds: before.st_ctime,
                    changed_nanoseconds: stat_changed_nanoseconds(&before),
                })
            } else {
                bail!("review worktree contains an unsupported special or directory entry");
            }
        }
        #[cfg(not(unix))]
        {
            let _ = total_content_bytes;
            bail!("exact no-follow review snapshots are unsupported on this platform")
        }
    }

    fn snapshot_git_backlink(&self) -> Result<GitBacklinkSnapshot> {
        #[cfg(unix)]
        {
            let name = c_string(OsStr::new(".git"))?;
            let before = stat_at_nofollow(&self.root, &name)
                .context("review worktree Git backlink is missing or unsafe")?;
            if before.st_uid != unsafe { libc::geteuid() } {
                bail!("review worktree Git backlink ownership is unsafe");
            }
            let identity = file_identity_from_stat(&before);
            let file_type = before.st_mode & libc::S_IFMT;
            if file_type == libc::S_IFDIR {
                return Ok(GitBacklinkSnapshot {
                    kind: "directory".to_string(),
                    mode: unsigned_to_u32(before.st_mode),
                    identity,
                    modified_seconds: before.st_mtime,
                    modified_nanoseconds: stat_modified_nanoseconds(&before),
                    changed_seconds: before.st_ctime,
                    changed_nanoseconds: stat_changed_nanoseconds(&before),
                    content_sha256: None,
                });
            }
            if file_type != libc::S_IFREG {
                bail!("review worktree Git backlink has an unsupported file type");
            }
            if before.st_nlink != 1 {
                bail!("review worktree Git backlink link count is unsafe");
            }
            let fd = unsafe {
                libc::openat(
                    self.root.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
                )
            };
            if fd < 0 {
                return Err(std::io::Error::last_os_error())
                    .context("failed to open review worktree Git backlink safely");
            }
            let mut file = unsafe { File::from_raw_fd(fd) };
            let opened = fstat_file(&file)?;
            if !same_stat_generation(&before, &opened) {
                bail!("review worktree Git backlink changed before read");
            }
            let length = u64::try_from(opened.st_size)
                .context("review worktree Git backlink has a negative length")?;
            if length > REVIEW_PATH_LIMIT_BYTES as u64 {
                bail!("review worktree Git backlink exceeds its bounded length");
            }
            let mut contents = Vec::with_capacity(usize::try_from(length).unwrap_or_default());
            (&mut file)
                .take((REVIEW_PATH_LIMIT_BYTES as u64).saturating_add(1))
                .read_to_end(&mut contents)
                .context("failed to read review worktree Git backlink")?;
            let after = fstat_file(&file)?;
            if u64::try_from(contents.len()).unwrap_or(u64::MAX) != length
                || !same_stat_generation(&opened, &after)
            {
                bail!("review worktree Git backlink changed during read");
            }
            Ok(GitBacklinkSnapshot {
                kind: "file".to_string(),
                mode: unsigned_to_u32(before.st_mode),
                identity,
                modified_seconds: before.st_mtime,
                modified_nanoseconds: stat_modified_nanoseconds(&before),
                changed_seconds: before.st_ctime,
                changed_nanoseconds: stat_changed_nanoseconds(&before),
                content_sha256: Some(sha256_hex(&contents)),
            })
        }
        #[cfg(not(unix))]
        bail!("exact no-follow review snapshots are unsupported on this platform")
    }

    #[cfg(unix)]
    fn open_parent(&self, path: &Path) -> Result<Option<(File, OsString)>> {
        let components = path
            .components()
            .map(|component| match component {
                std::path::Component::Normal(value) => Ok(value.to_os_string()),
                _ => bail!("review snapshot path is not canonical repository-relative form"),
            })
            .collect::<Result<Vec<_>>>()?;
        let (name, parents) = components
            .split_last()
            .context("review snapshot path has no final component")?;
        let mut directory = self
            .root
            .try_clone()
            .context("failed to clone review worktree descriptor")?;
        for component in parents {
            let component_c = c_string(component)?;
            let fd = unsafe {
                libc::openat(
                    directory.as_raw_fd(),
                    component_c.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if fd < 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() == std::io::ErrorKind::NotFound {
                    return Ok(None);
                }
                return Err(error).context("review snapshot parent component is missing or unsafe");
            }
            directory = unsafe { File::from_raw_fd(fd) };
        }
        Ok(Some((directory, name.clone())))
    }
}

#[cfg(target_os = "linux")]
fn prewalk_review_directory(
    directory: &File,
    relative: &Path,
    device: libc::dev_t,
    depth: usize,
    entry_count: &mut usize,
    total_bytes: &mut u64,
    deadline: Instant,
) -> Result<()> {
    if Instant::now() > deadline {
        bail!("review descriptor prewalk exceeded its bounded deadline");
    }
    if depth > REVIEW_PREWALK_MAX_DEPTH {
        bail!("review descriptor prewalk exceeded its depth limit");
    }
    for name in review_directory_entries(directory, deadline)? {
        if Instant::now() > deadline {
            bail!("review descriptor prewalk exceeded its bounded deadline");
        }
        if relative.as_os_str().is_empty() && name == OsStr::new(".git") {
            continue;
        }
        *entry_count = entry_count.saturating_add(1);
        if *entry_count > REVIEW_SNAPSHOT_ENTRY_LIMIT {
            bail!("review descriptor prewalk exceeded its entry limit");
        }
        let path = relative.join(&name);
        validate_snapshot_relative_path(&path)?;
        let name_c = c_string(&name)?;
        let stat = stat_at_nofollow(directory, &name_c)
            .context("failed to inspect review descriptor prewalk entry")?;
        if stat.st_dev != device || stat.st_uid != unsafe { libc::geteuid() } {
            bail!("review descriptor prewalk crossed an unsafe filesystem or owner boundary");
        }
        match stat.st_mode & libc::S_IFMT {
            libc::S_IFDIR => {
                let fd = unsafe {
                    libc::openat(
                        directory.as_raw_fd(),
                        name_c.as_ptr(),
                        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    )
                };
                if fd < 0 {
                    return Err(std::io::Error::last_os_error())
                        .context("failed to bind review descriptor prewalk directory");
                }
                let child = unsafe { File::from_raw_fd(fd) };
                let opened = fstat_file(&child)?;
                if !same_stat_generation(&stat, &opened) {
                    bail!("review descriptor prewalk directory changed while binding");
                }
                prewalk_review_directory(
                    &child,
                    &path,
                    device,
                    depth.saturating_add(1),
                    entry_count,
                    total_bytes,
                    deadline,
                )?;
            }
            libc::S_IFREG => {
                if stat.st_nlink != 1 {
                    bail!("review descriptor prewalk found an unsafe hard link");
                }
                let length = u64::try_from(stat.st_size)
                    .context("review descriptor prewalk found a negative file length")?;
                if length > REVIEW_SNAPSHOT_FILE_LIMIT_BYTES {
                    bail!("review descriptor prewalk found an oversized file");
                }
                *total_bytes = total_bytes
                    .checked_add(length)
                    .context("review descriptor prewalk byte total overflow")?;
                if *total_bytes > REVIEW_SNAPSHOT_TOTAL_LIMIT_BYTES {
                    bail!("review descriptor prewalk exceeded its total byte limit");
                }
            }
            libc::S_IFLNK => {
                let mut target = vec![0u8; REVIEW_SYMLINK_LIMIT_BYTES.saturating_add(1)];
                let read = unsafe {
                    libc::readlinkat(
                        directory.as_raw_fd(),
                        name_c.as_ptr(),
                        target.as_mut_ptr().cast(),
                        target.len(),
                    )
                };
                if read < 0 {
                    return Err(std::io::Error::last_os_error())
                        .context("failed to read review descriptor prewalk symlink");
                }
                let read = usize::try_from(read).context("review symlink length overflow")?;
                if read > REVIEW_SYMLINK_LIMIT_BYTES {
                    bail!("review descriptor prewalk found an oversized symlink target");
                }
                target.truncate(read);
                let after = stat_at_nofollow(directory, &name_c)
                    .context("failed to revalidate review descriptor prewalk symlink")?;
                if !same_stat_generation(&stat, &after) {
                    bail!("review descriptor prewalk symlink changed during inspection");
                }
                validate_internal_symlink_target(&path, &target)?;
            }
            _ => bail!("review descriptor prewalk found an unsupported special file"),
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn review_directory_entries(directory: &File, deadline: Instant) -> Result<Vec<OsString>> {
    let duplicated = unsafe { libc::dup(directory.as_raw_fd()) };
    if duplicated < 0 {
        return Err(std::io::Error::last_os_error())
            .context("failed to duplicate review directory descriptor");
    }
    let stream = unsafe { libc::fdopendir(duplicated) };
    if stream.is_null() {
        let error = std::io::Error::last_os_error();
        unsafe {
            libc::close(duplicated);
        }
        return Err(error).context("failed to enumerate review directory descriptor");
    }
    let mut names = Vec::new();
    loop {
        if Instant::now() > deadline {
            unsafe {
                libc::closedir(stream);
            }
            bail!("review descriptor prewalk exceeded its bounded deadline");
        }
        unsafe {
            *libc::__errno_location() = 0;
        }
        let entry = unsafe { libc::readdir(stream) };
        if entry.is_null() {
            let error = std::io::Error::last_os_error();
            unsafe {
                libc::closedir(stream);
            }
            if error.raw_os_error().unwrap_or_default() != 0 {
                return Err(error).context("failed during review directory enumeration");
            }
            break;
        }
        let name = unsafe { std::ffi::CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
        if matches!(name, b"." | b"..") {
            continue;
        }
        names.push(OsString::from_vec(name.to_vec()));
        if names.len() > REVIEW_SNAPSHOT_ENTRY_LIMIT {
            unsafe {
                libc::closedir(stream);
            }
            bail!("review descriptor prewalk directory exceeded its entry limit");
        }
    }
    names.sort();
    Ok(names)
}

fn validate_snapshot_relative_path(path: &Path) -> Result<()> {
    if path.as_os_str().is_empty() || path.is_absolute() {
        bail!("review snapshot path is not repository-relative");
    }
    if path_bytes(path).len() > REVIEW_PATH_LIMIT_BYTES {
        bail!(
            "review snapshot path exceeds its {} byte limit",
            REVIEW_PATH_LIMIT_BYTES
        );
    }
    let mut components = path.components();
    let Some(std::path::Component::Normal(first)) = components.next() else {
        bail!("review snapshot path is not canonical");
    };
    if first == OsStr::new(".git") {
        bail!("review snapshot path must not enter Git administrative state");
    }
    for component in components {
        if !matches!(component, std::path::Component::Normal(_)) {
            bail!("review snapshot path is not canonical");
        }
    }
    Ok(())
}

fn validate_git_reference_path(reference: &str) -> Result<()> {
    if reference.len() > REVIEW_PATH_LIMIT_BYTES || !reference.starts_with("refs/") {
        bail!("review HEAD reference path is not canonical");
    }
    validate_snapshot_relative_path(Path::new(reference))
        .context("review HEAD reference path is not canonical")
}

fn snapshot_regular_entry_digest(
    reader: &ReviewTreeReader,
    path: &Path,
    total_content_bytes: &mut u64,
    max_bytes: u64,
    required: bool,
    label: &str,
) -> Result<Option<String>> {
    match reader.snapshot_entry(path, total_content_bytes)? {
        SnapshotTreeEntry::Missing if required => bail!("{label} is missing"),
        SnapshotTreeEntry::Missing => Ok(None),
        entry @ SnapshotTreeEntry::Regular { length, .. } => {
            if length > max_bytes {
                bail!("{label} exceeds its bounded size");
            }
            let mut canonical = Vec::new();
            entry.append_canonical(&mut canonical);
            Ok(Some(sha256_hex(&canonical)))
        }
        SnapshotTreeEntry::Symlink { .. } => {
            bail!("{label} must be a regular no-follow file")
        }
    }
}

fn append_snapshot_bytes(output: &mut Vec<u8>, bytes: &[u8]) -> Result<()> {
    let length = u32::try_from(bytes.len()).context("review snapshot field length overflow")?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(bytes);
    Ok(())
}

#[cfg(unix)]
fn path_from_git_bytes(bytes: &[u8]) -> Result<PathBuf> {
    if bytes.contains(&0) {
        bail!("review Git path contains a NUL byte");
    }
    Ok(PathBuf::from(OsString::from_vec(bytes.to_vec())))
}

#[cfg(not(unix))]
fn path_from_git_bytes(bytes: &[u8]) -> Result<PathBuf> {
    let path = std::str::from_utf8(bytes).context("review Git path is not valid UTF-8")?;
    Ok(PathBuf::from(path))
}

#[cfg(unix)]
fn path_bytes(path: &Path) -> Vec<u8> {
    path.as_os_str().as_bytes().to_vec()
}

#[cfg(not(unix))]
fn path_bytes(path: &Path) -> Vec<u8> {
    match path.to_str() {
        Some(value) => value.as_bytes().to_vec(),
        None => Vec::new(),
    }
}

#[cfg(unix)]
fn c_string(value: &OsStr) -> Result<std::ffi::CString> {
    std::ffi::CString::new(value.as_bytes()).context("review path contains a NUL byte")
}

#[cfg(unix)]
fn stat_at_nofollow(directory: &File, name: &std::ffi::CStr) -> std::io::Result<libc::stat> {
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe {
        libc::fstatat(
            directory.as_raw_fd(),
            name.as_ptr(),
            &mut stat,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error());
    }
    Ok(stat)
}

#[cfg(unix)]
fn fstat_file(file: &File) -> Result<libc::stat> {
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(file.as_raw_fd(), &mut stat) } != 0 {
        return Err(std::io::Error::last_os_error())
            .context("failed to inspect review snapshot file descriptor");
    }
    Ok(stat)
}

#[cfg(unix)]
fn file_identity_from_stat(stat: &libc::stat) -> FileIdentity {
    FileIdentity {
        device: device_id_to_u64(stat.st_dev),
        file: unsigned_to_u64(stat.st_ino),
    }
}

#[cfg(unix)]
fn file_identity_from_metadata(metadata: &std::fs::Metadata) -> FileIdentity {
    FileIdentity {
        device: metadata.dev(),
        file: metadata.ino(),
    }
}

#[cfg(unix)]
fn same_stat_generation(left: &libc::stat, right: &libc::stat) -> bool {
    left.st_dev == right.st_dev
        && left.st_ino == right.st_ino
        && left.st_mode == right.st_mode
        && left.st_nlink == right.st_nlink
        && left.st_uid == right.st_uid
        && left.st_size == right.st_size
        && left.st_mtime == right.st_mtime
        && stat_modified_nanoseconds(left) == stat_modified_nanoseconds(right)
        && left.st_ctime == right.st_ctime
        && stat_changed_nanoseconds(left) == stat_changed_nanoseconds(right)
}

#[cfg(target_os = "linux")]
fn stat_modified_nanoseconds(stat: &libc::stat) -> i64 {
    stat.st_mtime_nsec
}

#[cfg(all(unix, not(target_os = "linux")))]
fn stat_modified_nanoseconds(_stat: &libc::stat) -> i64 {
    0
}

#[cfg(target_os = "linux")]
fn stat_changed_nanoseconds(stat: &libc::stat) -> i64 {
    stat.st_ctime_nsec
}

#[cfg(all(unix, not(target_os = "linux")))]
fn stat_changed_nanoseconds(_stat: &libc::stat) -> i64 {
    0
}

#[cfg(unix)]
fn validate_snapshot_entry_owner_and_links(stat: &libc::stat) -> Result<()> {
    if stat.st_uid != unsafe { libc::geteuid() } {
        bail!("review worktree entry is not owned by the current user");
    }
    if stat.st_nlink != 1 {
        bail!("review worktree entry must have exactly one hard link");
    }
    Ok(())
}

#[cfg(unix)]
fn validate_internal_symlink_target(path: &Path, target: &[u8]) -> Result<()> {
    resolve_internal_symlink_target(path, target).map(|_| ())
}

#[cfg(unix)]
fn resolve_internal_symlink_target(path: &Path, target: &[u8]) -> Result<PathBuf> {
    if target.is_empty() {
        bail!("review worktree symlink target cannot be empty");
    }
    let target_path = PathBuf::from(OsString::from_vec(target.to_vec()));
    if target_path.is_absolute() {
        bail!("review worktree symlink must not target an external absolute path");
    }
    let mut resolved = Vec::new();
    for component in path.parent().unwrap_or_else(|| Path::new("")).components() {
        let std::path::Component::Normal(value) = component else {
            bail!("review worktree symlink parent is not canonical");
        };
        resolved.push(value.to_os_string());
    }
    for component in target_path.components() {
        match component {
            std::path::Component::Normal(value) => resolved.push(value.to_os_string()),
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                if resolved.pop().is_none() {
                    bail!("review worktree symlink escapes the repository root");
                }
            }
            std::path::Component::RootDir | std::path::Component::Prefix(_) => {
                bail!("review worktree symlink escapes the repository root")
            }
        }
    }
    if resolved
        .first()
        .is_some_and(|component| component == ".git")
    {
        bail!("review worktree symlink must not enter Git administrative state");
    }
    Ok(resolved.into_iter().collect())
}

enum ParsedExternalReview {
    Accepted(Box<ReviewReport>),
    RejectedSensitive,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExternalReviewReportWire {
    version: u32,
    status: ReviewReportStatus,
    success: bool,
    target: String,
    reviewer: ExternalReviewerIdentityWire,
    attempt: usize,
    request_binding: String,
    findings: Vec<ExternalReviewFindingWire>,
    blocking_finding_count: usize,
    changed_paths: Vec<PathBuf>,
    diff_source: String,
    ci_reaction_supported: bool,
    ci_reaction: String,
    #[serde(default)]
    diagnostics: Option<ExternalReviewDiagnosticsWire>,
    next_action: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExternalReviewerIdentityWire {
    mode: String,
    reviewer_id: String,
    model: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExternalReviewFindingWire {
    severity: String,
    #[serde(default)]
    path: Option<PathBuf>,
    summary: String,
    suggested_fix: String,
    blocking: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExternalReviewDiagnosticsWire {
    timed_out: bool,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    exit_code: Option<i32>,
    stdout: ExternalReviewOutputWire,
    stderr: ExternalReviewOutputWire,
    #[serde(default)]
    process_error: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExternalReviewOutputWire {
    text: String,
    truncated: bool,
}

fn parse_external_review_report(
    bytes: &[u8],
    options: &ReviewPrOptions,
    expected_reviewer: &ReviewerIdentity,
    expected_request_binding: &str,
) -> Result<ParsedExternalReview> {
    if bytes.len() > REVIEW_JSON_LIMIT_BYTES {
        bail!(
            "external reviewer JSON exceeds its {} byte limit",
            REVIEW_JSON_LIMIT_BYTES
        );
    }
    let text = std::str::from_utf8(bytes)
        .context("external reviewer command output must be strict UTF-8 JSON")?;
    let wire: ExternalReviewReportWire = serde_json::from_str(text)
        .context("external reviewer command must emit a strict review report JSON object")?;

    if wire.version != REVIEW_SCHEMA_VERSION {
        bail!("external reviewer report version is unsupported");
    }
    if wire.target != options.target {
        bail!("external reviewer report target does not match the requested target");
    }
    if wire.attempt != options.attempt {
        bail!("external reviewer report attempt does not match the requested attempt");
    }
    if wire.changed_paths != options.changed_paths {
        bail!("external reviewer report changed_paths do not exactly match the review input");
    }
    if wire.changed_paths.len() > REVIEW_CHANGED_PATH_LIMIT {
        bail!("external reviewer report changed_paths exceeds its item limit");
    }
    for path in &wire.changed_paths {
        validate_repo_relative_path(path, "external reviewer changed path")?;
    }
    if wire.findings.len() > REVIEW_FINDING_LIMIT {
        bail!(
            "external reviewer report exceeds its {} finding limit",
            REVIEW_FINDING_LIMIT
        );
    }
    if wire.request_binding != expected_request_binding {
        bail!("external reviewer request_binding does not match the bound review request");
    }
    if wire.reviewer.mode != "external_command"
        || wire.reviewer.reviewer_id != expected_reviewer.reviewer_id
        || wire.reviewer.model != expected_reviewer.model
    {
        bail!("external reviewer identity does not match the parent-bound reviewer");
    }
    if wire.ci_reaction_supported || wire.ci_reaction != "unsupported" {
        bail!("external reviewer report must preserve unsupported CI reaction semantics");
    }
    let expected_diff_source = if options.diff_summary.is_some() {
        "sanitized_merge_candidate_summary"
    } else {
        "pr_target_only"
    };
    if wire.diff_source != expected_diff_source {
        bail!("external reviewer report diff_source does not match the review input");
    }

    let mut sensitive = false;
    sensitive |= external_text_is_sensitive(
        &wire.reviewer.reviewer_id,
        "external reviewer id",
        REVIEW_SHORT_TEXT_LIMIT_BYTES,
        false,
    )?;
    sensitive |= external_text_is_sensitive(
        &wire.reviewer.model,
        "external reviewer model",
        REVIEW_SHORT_TEXT_LIMIT_BYTES,
        false,
    )?;
    sensitive |= external_text_is_sensitive(
        &wire.diff_source,
        "external reviewer diff_source",
        REVIEW_SHORT_TEXT_LIMIT_BYTES,
        false,
    )?;
    sensitive |= external_text_is_sensitive(
        &wire.ci_reaction,
        "external reviewer ci_reaction",
        REVIEW_SHORT_TEXT_LIMIT_BYTES,
        false,
    )?;
    sensitive |= external_text_is_sensitive(
        &wire.next_action,
        "external reviewer next_action",
        REVIEW_LONG_TEXT_LIMIT_BYTES,
        false,
    )?;

    let mut findings = Vec::with_capacity(wire.findings.len());
    for finding in wire.findings {
        if let Some(path) = &finding.path {
            if validate_repo_relative_path(path, "external reviewer finding path").is_err() {
                sensitive = true;
            }
        }
        sensitive |= external_text_is_sensitive(
            &finding.severity,
            "external reviewer finding severity",
            REVIEW_SHORT_TEXT_LIMIT_BYTES,
            false,
        )?;
        let severity_requires_blocking = validate_review_severity(&finding.severity)?;
        if severity_requires_blocking && !finding.blocking {
            bail!("external reviewer finding severity and blocking flag are inconsistent");
        }
        sensitive |= external_text_is_sensitive(
            &finding.summary,
            "external reviewer finding summary",
            REVIEW_LONG_TEXT_LIMIT_BYTES,
            false,
        )?;
        sensitive |= external_text_is_sensitive(
            &finding.suggested_fix,
            "external reviewer finding suggested_fix",
            REVIEW_LONG_TEXT_LIMIT_BYTES,
            false,
        )?;
        findings.push(ReviewFinding {
            severity: finding.severity,
            path: finding.path,
            summary: finding.summary,
            suggested_fix: finding.suggested_fix,
            blocking: finding.blocking,
        });
    }
    if let Some(diagnostics) = &wire.diagnostics {
        if diagnostics
            .timeout_seconds
            .is_some_and(|timeout| timeout == 0 || timeout > REVIEW_TIMEOUT_LIMIT_SECONDS)
        {
            bail!("external reviewer diagnostics timeout_seconds is out of bounds");
        }
        sensitive |= external_text_is_sensitive(
            &diagnostics.stdout.text,
            "external reviewer diagnostics stdout",
            REVIEW_OUTPUT_LIMIT,
            true,
        )?;
        sensitive |= external_text_is_sensitive(
            &diagnostics.stderr.text,
            "external reviewer diagnostics stderr",
            REVIEW_OUTPUT_LIMIT,
            true,
        )?;
        if let Some(process_error) = &diagnostics.process_error {
            sensitive |= external_text_is_sensitive(
                process_error,
                "external reviewer diagnostics process_error",
                REVIEW_LONG_TEXT_LIMIT_BYTES,
                true,
            )?;
        }
        let _ = (
            diagnostics.timed_out,
            diagnostics.exit_code,
            diagnostics.stdout.truncated,
            diagnostics.stderr.truncated,
        );
    }

    let blocking_count = findings.iter().filter(|finding| finding.blocking).count();
    if wire.blocking_finding_count != blocking_count {
        bail!("external reviewer blocking_finding_count is inconsistent with findings");
    }
    match wire.status {
        ReviewReportStatus::Passed if wire.success && blocking_count == 0 => {}
        ReviewReportStatus::Blocked | ReviewReportStatus::Failed
            if !wire.success && blocking_count > 0 => {}
        _ => bail!("external reviewer status, success, and blocking findings are inconsistent"),
    }

    if sensitive {
        return Ok(ParsedExternalReview::RejectedSensitive);
    }
    Ok(ParsedExternalReview::Accepted(Box::new(ReviewReport {
        version: wire.version,
        status: wire.status,
        success: wire.success,
        target: wire.target,
        reviewer: ReviewerIdentity {
            mode: ReviewerMode::ExternalCommand,
            reviewer_id: wire.reviewer.reviewer_id,
            model: wire.reviewer.model,
        },
        attempt: wire.attempt,
        request_binding: wire.request_binding,
        findings,
        blocking_finding_count: wire.blocking_finding_count,
        changed_paths: wire.changed_paths,
        diff_source: wire.diff_source,
        ci_reaction_supported: wire.ci_reaction_supported,
        ci_reaction: wire.ci_reaction,
        diagnostics: None,
        next_action: wire.next_action,
    })))
}

fn external_text_is_sensitive(
    value: &str,
    label: &str,
    max_bytes: usize,
    allow_newlines: bool,
) -> Result<bool> {
    if value.len() > max_bytes {
        bail!("{label} exceeds its {max_bytes} byte limit");
    }
    if value.is_empty() && !label.contains("diagnostics") {
        bail!("{label} cannot be empty");
    }
    let contains_control = value.chars().any(|character| {
        character.is_control() && !(allow_newlines && matches!(character, '\n' | '\r' | '\t'))
    });
    Ok(contains_control
        || contains_private_key_material(value)
        || Redactor::new().redact(value).summary.total_replacements > 0
        || contains_external_absolute_path(value))
}

fn contains_private_key_material(text: &str) -> bool {
    let upper = text.to_ascii_uppercase();
    upper.contains("PRIVATE KEY") && (upper.contains("-----BEGIN") || upper.contains("BEGIN "))
}

fn contains_external_absolute_path(text: &str) -> bool {
    text.split(|character: char| {
        character.is_whitespace()
            || character == char::from(96)
            || matches!(
                character,
                '"' | '\'' | ',' | ';' | '(' | ')' | '[' | ']' | '{' | '}'
            )
    })
    .map(|token| token.trim_end_matches([':', '.']))
    .filter(|token| !token.is_empty())
    .any(|token| {
        token.starts_with('/')
            || token.starts_with("\\\\")
            || token
                .as_bytes()
                .get(1)
                .is_some_and(|separator| *separator == b':')
                && token
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphabetic)
    })
}

fn accepted_external_diagnostics(
    mut diagnostics: ReviewCommandDiagnostics,
) -> ReviewCommandDiagnostics {
    diagnostics.stdout = ReviewOutputSummary {
        text: "<validated:external-review-report>".to_string(),
        truncated: false,
    };
    diagnostics
}

fn redact_untrusted_report_diagnostics(
    mut diagnostics: ReviewCommandDiagnostics,
) -> ReviewCommandDiagnostics {
    diagnostics.stdout = ReviewOutputSummary {
        text: "<redacted:unsafe-external-review-report>".to_string(),
        truncated: true,
    };
    diagnostics.stderr = ReviewOutputSummary {
        text: "<redacted:unsafe-external-review-diagnostics>".to_string(),
        truncated: true,
    };
    if diagnostics.process_error.is_some() {
        diagnostics.process_error = Some("<redacted:unsafe-process-diagnostic>".to_string());
    }
    diagnostics
}

fn sandbox_environment() -> BTreeMap<String, String> {
    BTreeMap::from([
        (
            "PATH".to_string(),
            "/run/current-system/sw/bin:/usr/bin:/bin".to_string(),
        ),
        ("LANG".to_string(), "C.UTF-8".to_string()),
        ("LC_ALL".to_string(), "C.UTF-8".to_string()),
        ("TERM".to_string(), "dumb".to_string()),
    ])
}

fn failed_external_review(
    reviewer: &ReviewerIdentity,
    options: ReviewPrOptions,
    request_binding: &str,
    reason: &str,
    diagnostics: ReviewCommandDiagnostics,
) -> ReviewReport {
    ReviewReport {
        version: REVIEW_SCHEMA_VERSION,
        status: ReviewReportStatus::Failed,
        success: false,
        target: options.target,
        reviewer: reviewer.clone(),
        attempt: options.attempt,
        request_binding: request_binding.to_string(),
        findings: vec![ReviewFinding {
            severity: "error".to_string(),
            path: options.changed_paths.first().cloned(),
            summary: reason.to_string(),
            suggested_fix: "inspect reviewer diagnostics and rerun after fixing the command"
                .to_string(),
            blocking: true,
        }],
        blocking_finding_count: 1,
        changed_paths: options.changed_paths,
        diff_source: if options.diff_summary.is_some() {
            "sanitized_merge_candidate_summary".to_string()
        } else {
            "pr_target_only".to_string()
        },
        ci_reaction_supported: false,
        ci_reaction: "unsupported".to_string(),
        diagnostics: Some(diagnostics),
        next_action: "repair or rerun the external reviewer command before proceeding".to_string(),
    }
}

fn diagnostics_from_output(
    repo: &Path,
    output: &ProcessOutput,
    timeout_seconds: Option<u64>,
) -> ReviewCommandDiagnostics {
    ReviewCommandDiagnostics {
        timed_out: output.timed_out,
        timeout_seconds,
        exit_code: output.status.and_then(|status| status.code()),
        stdout: sanitize_review_output(repo, output.stdout.as_bytes()),
        stderr: sanitize_review_output(repo, output.stderr.as_bytes()),
        process_error: output
            .process_error
            .as_deref()
            .map(|error| sanitize_review_output(repo, error.as_bytes()).text),
    }
}

fn sanitize_review_output(repo: &Path, output: &[u8]) -> ReviewOutputSummary {
    let text = String::from_utf8_lossy(output);
    if contains_private_key_material(&text) {
        return ReviewOutputSummary {
            text: "<redacted:private-key-material>".to_string(),
            truncated: true,
        };
    }
    if text
        .chars()
        .any(|character| character.is_control() && !matches!(character, '\n' | '\r' | '\t'))
    {
        return ReviewOutputSummary {
            text: "<redacted:control-character-diagnostic>".to_string(),
            truncated: true,
        };
    }
    let mut sanitized = Redactor::new().redact(&text).text;
    redact_known_repository_paths(repo, &mut sanitized);
    if contains_external_absolute_path(&sanitized) {
        sanitized = "<redacted:absolute-path-diagnostic>".to_string();
    }
    summarize_review_text(&redact_token_like_words(&sanitized), REVIEW_OUTPUT_LIMIT)
}

fn review_diagnostic_contains_unsafe_evidence(repo: &Path, output: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(output) else {
        return true;
    };
    if contains_private_key_material(text)
        || text
            .chars()
            .any(|character| character.is_control() && !matches!(character, '\n' | '\r' | '\t'))
        || Redactor::new().redact(text).summary.total_replacements > 0
    {
        return true;
    }
    let mut sanitized = text.to_string();
    redact_known_repository_paths(repo, &mut sanitized);
    contains_external_absolute_path(&sanitized) || contains_token_like_word(&sanitized)
}

fn redact_known_repository_paths(repo: &Path, text: &mut String) {
    if let Ok(canonical_repo) = repo.canonicalize() {
        replace_nonempty_path(text, &canonical_repo, ".");
        if let Some(parent) = canonical_repo.parent() {
            replace_nonempty_path(text, parent, "<repo-parent>");
        }
    }
    replace_nonempty_path(text, repo, ".");
    if let Some(parent) = repo.parent() {
        replace_nonempty_path(text, parent, "<repo-parent>");
    }
}

fn replace_nonempty_path(text: &mut String, path: &Path, replacement: &str) {
    let path = path.display().to_string();
    if !path.is_empty() {
        *text = text.replace(&path, replacement);
    }
}

fn summarize_review_text(text: &str, limit: usize) -> ReviewOutputSummary {
    let mut chars = text.chars();
    let value = chars.by_ref().take(limit).collect::<String>();
    ReviewOutputSummary {
        text: value,
        truncated: chars.next().is_some(),
    }
}

fn redact_token_like_words(text: &str) -> String {
    let mut output = String::new();
    let mut token = String::new();
    for character in text.chars() {
        if character.is_ascii_alphanumeric() || matches!(character, '_' | '-' | '.') {
            token.push(character);
        } else {
            push_redacted_token(&mut output, &token);
            token.clear();
            output.push(character);
        }
    }
    push_redacted_token(&mut output, &token);
    output
}

fn contains_token_like_word(text: &str) -> bool {
    text.split(|character: char| {
        !(character.is_ascii_alphanumeric() || matches!(character, '_' | '-' | '.'))
    })
    .any(|token| {
        token.len() >= 32
            && token
                .chars()
                .any(|character| character.is_ascii_alphabetic())
            && token.chars().any(|character| character.is_ascii_digit())
    })
}

fn push_redacted_token(output: &mut String, token: &str) {
    if token.len() >= 32
        && token.chars().any(|c| c.is_ascii_alphabetic())
        && token.chars().any(|c| c.is_ascii_digit())
    {
        output.push_str("<redacted:token>");
    } else {
        output.push_str(token);
    }
}

fn fake_finding(options: &ReviewPrOptions) -> ReviewFinding {
    if let Some(template) = &options.reviewer.finding {
        return ReviewFinding {
            severity: template.severity.clone(),
            path: template
                .path
                .clone()
                .or_else(|| options.changed_paths.first().cloned()),
            summary: template.summary.clone(),
            suggested_fix: template.suggested_fix.clone(),
            blocking: true,
        };
    }
    ReviewFinding {
        severity: "error".to_string(),
        path: options.changed_paths.first().cloned(),
        summary: format!(
            "deterministic fake blocker for review attempt {}",
            options.attempt
        ),
        suggested_fix: "rerun the worker with the review finding as repair context".to_string(),
        blocking: true,
    }
}

#[derive(Serialize)]
struct ExternalReviewInput<'a> {
    version: u32,
    target: &'a str,
    attempt: usize,
    changed_paths: &'a [PathBuf],
    #[serde(skip_serializing_if = "Option::is_none")]
    diff_summary: Option<&'a str>,
    reviewer: &'a ReviewerIdentity,
    request_binding: &'a str,
}

#[derive(Serialize)]
struct ExternalReviewRequestBindingPayload<'a> {
    version: u32,
    target: &'a str,
    attempt: usize,
    changed_paths: &'a [PathBuf],
    diff_summary: Option<&'a str>,
    reviewer: &'a ReviewerIdentity,
    program: &'a MaterializedReviewerBinding,
    args: &'a [String],
    #[serde(skip_serializing_if = "Option::is_none")]
    sanitized_view_binding: Option<&'a str>,
    effective_timeout_seconds: u64,
    sandbox_policy_version: u32,
    repository_snapshot: &'a ReviewRepoSnapshot,
}

#[derive(Serialize)]
struct ExternalReviewerLaunchBinding<'a> {
    version: u32,
    program: &'a MaterializedReviewerBinding,
    args: &'a [String],
}

fn bound_external_reviewer_identity(
    program: &MaterializedReviewerBinding,
    args: &[String],
) -> Result<ReviewerIdentity> {
    let launch = serde_json::to_vec(&ExternalReviewerLaunchBinding {
        version: REVIEW_SCHEMA_VERSION,
        program,
        args,
    })
    .context("failed to serialize external reviewer launch identity")?;
    let command_binding = domain_sha256(EXTERNAL_REVIEWER_BINDING_DOMAIN, &launch);
    Ok(ReviewerIdentity {
        mode: ReviewerMode::ExternalCommand,
        reviewer_id: format!("external-program-{}", &command_binding[..32]),
        model: "parent-bound-direct-program-v1".to_string(),
    })
}

fn external_review_request_binding(
    options: &ReviewPrOptions,
    snapshot: &ReviewRepoSnapshot,
    reviewer: &ReviewerIdentity,
    program: &MaterializedReviewerBinding,
    sanitized_view_binding: Option<&str>,
    effective_timeout_seconds: u64,
) -> Result<String> {
    let payload = serde_json::to_vec(&ExternalReviewRequestBindingPayload {
        version: REVIEW_SCHEMA_VERSION,
        target: &options.target,
        attempt: options.attempt,
        changed_paths: &options.changed_paths,
        diff_summary: options.diff_summary.as_deref(),
        reviewer,
        program,
        args: &options.reviewer.args,
        sanitized_view_binding,
        effective_timeout_seconds,
        sandbox_policy_version: REVIEW_SANDBOX_POLICY_VERSION,
        repository_snapshot: snapshot,
    })
    .context("failed to serialize external review request binding")?;
    Ok(domain_sha256(EXTERNAL_REVIEW_REQUEST_DOMAIN, &payload))
}

fn fake_review_request_binding(options: &ReviewPrOptions) -> String {
    let mut payload = Vec::new();
    payload.push(REVIEW_SCHEMA_VERSION as u8);
    payload.push(1);
    payload.extend_from_slice(
        &u64::try_from(options.attempt)
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    payload.push(2);
    append_binding_field(&mut payload, options.target.as_bytes());
    payload.push(3);
    payload.extend_from_slice(
        &u64::try_from(options.changed_paths.len())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    for path in &options.changed_paths {
        payload.push(4);
        append_binding_field(&mut payload, &path_bytes(path));
    }
    match &options.diff_summary {
        Some(diff_summary) => {
            payload.push(5);
            append_binding_field(&mut payload, diff_summary.as_bytes());
        }
        None => payload.push(6),
    }
    payload.push(7);
    payload.extend_from_slice(
        &u64::try_from(options.reviewer.blocking_attempts)
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    match &options.reviewer.finding {
        Some(finding) => {
            payload.push(8);
            append_binding_field(&mut payload, finding.severity.as_bytes());
            match &finding.path {
                Some(path) => {
                    payload.push(9);
                    append_binding_field(&mut payload, &path_bytes(path));
                }
                None => payload.push(10),
            }
            append_binding_field(&mut payload, finding.summary.as_bytes());
            append_binding_field(&mut payload, finding.suggested_fix.as_bytes());
        }
        None => payload.push(11),
    }
    domain_sha256(FAKE_REVIEW_REQUEST_DOMAIN, &payload)
}

fn append_binding_field(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(&u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
    output.extend_from_slice(value);
}

fn domain_sha256(domain: &[u8], payload: &[u8]) -> String {
    let mut input = Vec::with_capacity(domain.len().saturating_add(payload.len()));
    input.extend_from_slice(domain);
    input.extend_from_slice(payload);
    sha256_hex(&input)
}

fn review_schema_version() -> u32 {
    REVIEW_SCHEMA_VERSION
}

fn deserialize_review_schema_version<'de, D>(deserializer: D) -> std::result::Result<u32, D::Error>
where
    D: Deserializer<'de>,
{
    let version = u32::deserialize(deserializer)?;
    if version != REVIEW_SCHEMA_VERSION {
        return Err(D::Error::custom(
            "review wire version is unsupported; expected version 1",
        ));
    }
    Ok(version)
}

fn sha256_hex(input: &[u8]) -> String {
    let mut output = String::with_capacity(64);
    for byte in sha256_bytes(input) {
        use std::fmt::Write as _;
        let _ = write!(&mut output, "{byte:02x}");
    }
    output
}

fn sha256_bytes(input: &[u8]) -> [u8; 32] {
    const INITIAL: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    const ROUND: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let bit_len = u64::try_from(input.len())
        .unwrap_or(u64::MAX)
        .wrapping_mul(8);
    let mut message = input.to_vec();
    message.push(0x80);
    while message.len() % 64 != 56 {
        message.push(0);
    }
    message.extend_from_slice(&bit_len.to_be_bytes());
    let mut hash = INITIAL;
    for chunk in message.chunks_exact(64) {
        let mut words = [0u32; 64];
        for (index, bytes) in chunk.chunks_exact(4).enumerate() {
            words[index] = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        }
        for index in 16..64 {
            let small_zero = words[index - 15].rotate_right(7)
                ^ words[index - 15].rotate_right(18)
                ^ (words[index - 15] >> 3);
            let small_one = words[index - 2].rotate_right(17)
                ^ words[index - 2].rotate_right(19)
                ^ (words[index - 2] >> 10);
            words[index] = words[index - 16]
                .wrapping_add(small_zero)
                .wrapping_add(words[index - 7])
                .wrapping_add(small_one);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = hash;
        for index in 0..64 {
            let sum_one = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let choice = (e & f) ^ ((!e) & g);
            let temp_one = h
                .wrapping_add(sum_one)
                .wrapping_add(choice)
                .wrapping_add(ROUND[index])
                .wrapping_add(words[index]);
            let sum_zero = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let majority = (a & b) ^ (a & c) ^ (b & c);
            let temp_two = sum_zero.wrapping_add(majority);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp_one);
            d = c;
            c = b;
            b = a;
            a = temp_one.wrapping_add(temp_two);
        }
        hash[0] = hash[0].wrapping_add(a);
        hash[1] = hash[1].wrapping_add(b);
        hash[2] = hash[2].wrapping_add(c);
        hash[3] = hash[3].wrapping_add(d);
        hash[4] = hash[4].wrapping_add(e);
        hash[5] = hash[5].wrapping_add(f);
        hash[6] = hash[6].wrapping_add(g);
        hash[7] = hash[7].wrapping_add(h);
    }
    let mut output = [0u8; 32];
    for (index, word) in hash.iter().enumerate() {
        let offset = index.saturating_mul(4);
        output[offset..offset + 4].copy_from_slice(&word.to_be_bytes());
    }
    output
}

fn default_review_severity() -> String {
    "error".to_string()
}

fn default_review_summary() -> String {
    "deterministic fake blocker".to_string()
}

fn default_suggested_fix() -> String {
    "repair the reported issue".to_string()
}

pub fn target_label(target: &str) -> String {
    let target = target.trim();
    if target.is_empty() {
        "unknown".to_string()
    } else {
        target.to_string()
    }
}

pub fn target_from_pr_arg(arg: &str) -> Result<String> {
    let target = arg.trim();
    if target.is_empty() {
        bail!("pull request target cannot be empty");
    }
    if target.chars().all(|c| c.is_ascii_digit()) {
        return Ok(format!("#{target}"));
    }
    Ok(target.to_string())
}

pub fn diff_summary_from_text(text: impl AsRef<str>) -> Option<String> {
    let text = text.as_ref().trim();
    if text.is_empty() {
        None
    } else {
        Some(text.chars().take(32 * 1024).collect())
    }
}

pub fn normalize_changed_paths(paths: impl IntoIterator<Item = PathBuf>) -> Vec<PathBuf> {
    let mut paths = paths.into_iter().collect::<Vec<_>>();
    paths.sort();
    paths.dedup();
    paths
}

pub fn repo_path_for_review(repo: impl AsRef<Path>) -> PathBuf {
    repo.as_ref().to_path_buf()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn model_review_lens(
        id: &str,
        backend_id: &str,
        model: &str,
        information_scope: ReviewInformationScope,
    ) -> ReviewLensConfig {
        ReviewLensConfig {
            id: id.to_string(),
            backend: ReviewLensBackendConfig::Model {
                backend_id: backend_id.to_string(),
                model: model.to_string(),
                reasoning_effort: None,
            },
            information_scope,
        }
    }

    fn bound_lens_verdict(
        lens: &ReviewLensConfig,
        verdict: ReviewLensVerdictStatus,
        binding: &str,
    ) -> ReviewLensVerdict {
        let coverage = ReviewLensCoverage {
            worker_ids: vec!["worker-a".to_string()],
            paths: vec![PathBuf::from("src/review.rs")],
        };
        let request_binding = sha256_hex(format!("request-{binding}").as_bytes());
        ReviewLensVerdict::for_lens(
            lens,
            request_binding,
            verdict,
            coverage,
            vec![(ReviewLensEvidenceKind::ModelReview, binding.to_string())],
        )
        .expect("test lens verdict must serialize")
    }

    #[cfg(unix)]
    #[test]
    fn review_snapshot_fails_closed_on_non_utf8_head_target() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let repository = git2::Repository::init(temp.path())?;
        let binding = ReviewRepositoryBinding::bind(temp.path())?;
        binding.snapshot()?;
        std::fs::write(repository.path().join("HEAD"), b"ref: refs/heads/non\xff\n")?;

        let error = binding.snapshot().expect_err("non-UTF-8 HEAD must fail");
        assert!(error
            .to_string()
            .contains("review HEAD symbolic target is not valid UTF-8"));
        Ok(())
    }

    #[test]
    fn review_lens_scoped_requests_exclude_disallowed_information() -> Result<()> {
        let sources = ReviewLensRequestSources {
            child_transcript: "TRANSCRIPT-ONLY-MARKER",
            diff: "DIFF-ONLY-MARKER",
            output_report: "REPORT-ONLY-MARKER",
        };
        let diff_lens = model_review_lens(
            "diff-lens",
            "backend-a",
            "model-a",
            ReviewInformationScope::DiffOnly,
        );
        let diff_request = build_review_lens_request(&diff_lens, sources)?;
        let diff_json = serde_json::to_string(&diff_request)?;
        assert!(diff_json.contains("DIFF-ONLY-MARKER"));
        assert!(!diff_json.contains("TRANSCRIPT-ONLY-MARKER"));
        assert!(!diff_json.contains("REPORT-ONLY-MARKER"));
        assert!(!diff_json.contains("child_transcript"));
        assert!(!diff_json.contains("output_report"));
        assert_eq!(diff_request.backend_id, "backend-a");
        assert_eq!(diff_request.model, "model-a");

        let output_lens = model_review_lens(
            "output-lens",
            "backend-b",
            "model-b",
            ReviewInformationScope::OutputReportOnly,
        );
        let output_request = build_review_lens_request(&output_lens, sources)?;
        let output_json = serde_json::to_string(&output_request)?;
        assert!(output_json.contains("REPORT-ONLY-MARKER"));
        assert!(!output_json.contains("TRANSCRIPT-ONLY-MARKER"));
        assert!(!output_json.contains("DIFF-ONLY-MARKER"));
        assert!(!output_json.contains("child_transcript"));
        assert!(!output_json.contains("\"diff\""));
        assert_eq!(output_request.backend_id, "backend-b");
        assert_eq!(output_request.model, "model-b");

        let full_lens = model_review_lens(
            "full-lens",
            "backend-c",
            "model-c",
            ReviewInformationScope::FullChildTranscript,
        );
        let full_json = serde_json::to_string(&build_review_lens_request(&full_lens, sources)?)?;
        assert!(full_json.contains("TRANSCRIPT-ONLY-MARKER"));
        assert!(full_json.contains("DIFF-ONLY-MARKER"));
        assert!(full_json.contains("REPORT-ONLY-MARKER"));
        Ok(())
    }

    #[test]
    fn review_lens_scoped_request_bounds_only_included_information() -> Result<()> {
        let lens = model_review_lens(
            "bounded-diff-lens",
            "bounded-backend",
            "bounded-model",
            ReviewInformationScope::DiffOnly,
        );
        let oversized_excluded = "t".repeat(REVIEW_INPUT_LIMIT_BYTES + 1);
        let request = build_review_lens_request(
            &lens,
            ReviewLensRequestSources {
                child_transcript: &oversized_excluded,
                diff: "small included diff",
                output_report: &oversized_excluded,
            },
        )?;
        assert!(matches!(
            request.information,
            ReviewLensScopedInformation::DiffOnly { .. }
        ));

        let oversized_included = "d".repeat(REVIEW_INPUT_LIMIT_BYTES + 1);
        let error = build_review_lens_request(
            &lens,
            ReviewLensRequestSources {
                child_transcript: "excluded",
                diff: &oversized_included,
                output_report: "excluded",
            },
        )
        .expect_err("oversized included diff must fail before cloning");
        assert!(error.to_string().contains("scoped input exceeds"));
        Ok(())
    }

    #[test]
    fn review_lens_versioned_wires_reject_unsupported_versions() -> Result<()> {
        let lens = model_review_lens(
            "version-lens",
            "version-backend",
            "version-model",
            ReviewInformationScope::DiffOnly,
        );
        let request = build_review_lens_request(
            &lens,
            ReviewLensRequestSources {
                child_transcript: "transcript",
                diff: "diff",
                output_report: "report",
            },
        )?;
        let mut request_value = serde_json::to_value(request)?;
        request_value["version"] = serde_json::json!(REVIEW_SCHEMA_VERSION + 1);
        assert!(serde_json::from_value::<ReviewLensRequest>(request_value)
            .expect_err("unsupported request version must fail")
            .to_string()
            .contains("version is unsupported"));

        let aggregate = aggregate_review_lenses(
            std::slice::from_ref(&lens),
            ReviewAggregationPolicy::AllMustAccept,
            ReviewCoverageRequirement {
                worker_ids: vec!["worker-a".to_string()],
                paths: vec![PathBuf::from("src/review.rs")],
            },
            vec![bound_lens_verdict(
                &lens,
                ReviewLensVerdictStatus::Accept,
                "version-binding",
            )],
        )?;
        let mut aggregate_value = serde_json::to_value(aggregate)?;
        aggregate_value["version"] = serde_json::json!(REVIEW_SCHEMA_VERSION + 1);
        assert!(
            serde_json::from_value::<ReviewLensAggregate>(aggregate_value)
                .expect_err("unsupported aggregate version must fail")
                .to_string()
                .contains("version is unsupported")
        );
        Ok(())
    }

    #[test]
    fn review_lens_deserialized_aggregate_is_explicitly_non_authoritative() -> Result<()> {
        let lens = model_review_lens(
            "aggregate-authority-lens",
            "aggregate-authority-backend",
            "aggregate-authority-model",
            ReviewInformationScope::DiffOnly,
        );
        let aggregate = aggregate_review_lenses(
            std::slice::from_ref(&lens),
            ReviewAggregationPolicy::AllMustAccept,
            ReviewCoverageRequirement::default(),
            vec![bound_lens_verdict(
                &lens,
                ReviewLensVerdictStatus::Accept,
                "aggregate-authority-binding",
            )],
        )?;
        assert_eq!(
            aggregate.authority(),
            ReviewLensAggregateAuthority::ParentComputed
        );

        let mut wire = serde_json::to_value(&aggregate)?;
        assert!(wire.get("authority").is_none());
        wire["decision"] = serde_json::json!("reject");
        wire["required_accepts"] = serde_json::json!(99);
        wire["validated_accepts"] = serde_json::json!(98);
        wire["rejected_lenses"] = serde_json::json!(97);
        wire["procedural_failures"] = serde_json::json!(96);
        wire["required_coverage"] = serde_json::json!({
            "worker_ids": ["unverified-worker"],
            "paths": ["unverified/path.rs"]
        });

        let deserialized: ReviewLensAggregate = serde_json::from_value(wire.clone())?;
        assert_eq!(
            deserialized.authority(),
            ReviewLensAggregateAuthority::DeserializedNonAuthoritative
        );
        assert_eq!(deserialized.required_accepts, 99);
        assert_eq!(deserialized.validated_accepts, 98);

        wire["authority"] = serde_json::json!("parent_computed");
        assert!(serde_json::from_value::<ReviewLensAggregate>(wire).is_err());
        Ok(())
    }

    #[test]
    fn review_lens_tagged_wires_reject_unknown_fields() {
        assert!(
            serde_json::from_value::<ReviewLensBackendConfig>(serde_json::json!({
                "kind": "model",
                "backend_id": "backend-a",
                "model": "model-a",
                "reviewer": {"mode": "fake"},
                "unknown": true
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<ReviewLensScopedInformation>(serde_json::json!({
                "scope": "diff_only",
                "diff": "bounded",
                "unknown": true
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<ReviewAggregationPolicy>(serde_json::json!({
                "kind": "validated_quorum",
                "minimum_accepts": 1,
                "unknown": true
            }))
            .is_err()
        );
    }

    #[test]
    fn review_lens_public_constructors_bind_safe_identity() -> Result<()> {
        let lens = model_review_lens(
            "constructor-lens",
            "constructor-backend",
            "constructor-model",
            ReviewInformationScope::OutputReportOnly,
        );
        let descriptor = ReviewLensDescriptor::from(&lens);
        assert_eq!(descriptor.id, lens.id);
        assert_eq!(descriptor.backend_id, "constructor-backend");
        assert_eq!(descriptor.model, "constructor-model");
        assert_eq!(
            descriptor.information_scope,
            ReviewInformationScope::OutputReportOnly
        );
        assert_eq!(
            descriptor.expected_evidence_kind,
            ReviewLensEvidenceKind::ModelReview
        );

        let request_binding = sha256_hex(b"constructor-request");
        let coverage = ReviewLensCoverage {
            worker_ids: vec!["worker-a".to_string()],
            paths: vec![PathBuf::from("src/review.rs")],
        };
        let verdict = ReviewLensVerdict::for_lens(
            &lens,
            request_binding.clone(),
            ReviewLensVerdictStatus::Accept,
            coverage.clone(),
            vec![(
                ReviewLensEvidenceKind::ModelReview,
                "ordinary confidential transcript sentence".to_string(),
            )],
        )?;
        assert_eq!(verdict.lens, descriptor);
        assert_eq!(verdict.request_binding, request_binding);
        assert_eq!(verdict.evidence[0].lens, verdict.lens);
        assert_eq!(verdict.evidence[0].coverage, coverage);
        assert_eq!(verdict.evidence[0].request_binding, verdict.request_binding);
        assert_eq!(
            verdict.evidence[0].binding,
            review_lens_evidence_content_identity("ordinary confidential transcript sentence")?
        );
        assert!(verdict.evidence[0].binding.starts_with("sha256:"));
        assert_eq!(verdict.evidence[0].binding.len(), 71);
        assert!(
            !serde_json::to_string(&verdict)?.contains("ordinary confidential transcript sentence")
        );
        Ok(())
    }

    #[test]
    fn review_lens_malformed_evidence_digest_identities_fail_closed() -> Result<()> {
        let lens = model_review_lens(
            "malformed-evidence-lens",
            "malformed-evidence-backend",
            "malformed-evidence-model",
            ReviewInformationScope::DiffOnly,
        );
        let required = ReviewCoverageRequirement {
            worker_ids: vec!["worker-a".to_string()],
            paths: vec![PathBuf::from("src/review.rs")],
        };
        let base = bound_lens_verdict(
            &lens,
            ReviewLensVerdictStatus::Accept,
            "valid-evidence-content",
        );
        let valid_evidence_wire = serde_json::to_value(&base.evidence[0])?;
        let malformed = [
            "0".repeat(64),
            format!("sha256:{}", "0".repeat(63)),
            format!("sha256:{}", "A".repeat(64)),
            format!("SHA256:{}", "0".repeat(64)),
        ];

        for binding in malformed {
            let mut verdict = base.clone();
            verdict.evidence[0].binding = binding;
            let serialization_error = serde_json::to_string(&verdict.evidence[0])
                .expect_err("malformed public evidence must not serialize");
            assert!(serialization_error
                .to_string()
                .contains("sha256:<64 lowercase hex>"));
            let mut malformed_wire = valid_evidence_wire.clone();
            malformed_wire["binding"] =
                serde_json::Value::String(verdict.evidence[0].binding.clone());
            assert!(serde_json::from_value::<ReviewLensEvidence>(malformed_wire)
                .expect_err("malformed public evidence wire must not deserialize")
                .to_string()
                .contains("sha256:<64 lowercase hex>"));

            let aggregate = aggregate_review_lenses(
                std::slice::from_ref(&lens),
                ReviewAggregationPolicy::AllMustAccept,
                required.clone(),
                vec![verdict],
            )?;
            assert_eq!(
                aggregate.decision,
                ReviewAggregationDecision::ProceduralFailure
            );
            assert!(aggregate.lens_verdicts[0].evidence.is_empty());
            assert!(aggregate.lens_verdicts[0]
                .validation_errors
                .join("\n")
                .contains("sha256:<64 lowercase hex>"));
        }
        Ok(())
    }

    #[test]
    fn review_lens_default_scope_templates_are_stable_cheap_and_local() {
        let lenses = cheap_default_review_lenses();

        assert_eq!(lenses.len(), 2);
        assert_eq!(lenses[0].id, DEFAULT_DIFF_REVIEW_LENS_ID);
        assert_eq!(
            lenses[0].information_scope,
            ReviewInformationScope::DiffOnly
        );
        assert_eq!(lenses[1].id, DEFAULT_OUTPUT_REVIEW_LENS_ID);
        assert_eq!(
            lenses[1].information_scope,
            ReviewInformationScope::OutputReportOnly
        );
        assert!(lenses.iter().all(|lens| {
            lens.information_scope != ReviewInformationScope::FullChildTranscript
                && !lens.backend.backend_id().is_empty()
                && !lens.backend.model().is_empty()
        }));
        assert_eq!(lenses[0].backend, lenses[1].backend);
        assert!(lenses
            .iter()
            .all(|lens| matches!(&lens.backend, ReviewLensBackendConfig::Model { .. })));
    }

    #[test]
    fn review_lens_aggregate_omits_private_backend_configuration() -> Result<()> {
        let lenses = vec![
            ReviewLensConfig {
                id: "fake-private-config".to_string(),
                backend: ReviewLensBackendConfig::Model {
                    backend_id: "fake-local".to_string(),
                    model: "fake-model".to_string(),
                    reasoning_effort: None,
                },
                information_scope: ReviewInformationScope::OutputReportOnly,
            },
            ReviewLensConfig {
                id: "external-private-config".to_string(),
                backend: ReviewLensBackendConfig::Model {
                    backend_id: "external-direct".to_string(),
                    model: "external-model".to_string(),
                    reasoning_effort: None,
                },
                information_scope: ReviewInformationScope::DiffOnly,
            },
        ];
        let aggregate = aggregate_review_lenses(
            &lenses,
            ReviewAggregationPolicy::AllMustAccept,
            ReviewCoverageRequirement {
                worker_ids: vec!["worker-a".to_string()],
                paths: vec![PathBuf::from("src/review.rs")],
            },
            vec![
                bound_lens_verdict(&lenses[0], ReviewLensVerdictStatus::Accept, "private-a"),
                bound_lens_verdict(&lenses[1], ReviewLensVerdictStatus::Accept, "private-b"),
            ],
        )?;
        let serialized = serde_json::to_string(&aggregate)?;

        for marker in [
            "PRIVATE_FAKE_SUMMARY_MARKER",
            "PRIVATE_FAKE_FIX_MARKER",
            "PRIVATE_PROGRAM_MARKER",
            "PRIVATE_ARG_MARKER",
            "\"reviewer\"",
            "\"program\"",
            "\"args\"",
            "\"finding\"",
        ] {
            assert!(
                !serialized.contains(marker),
                "aggregate leaked private backend marker {marker}"
            );
        }
        assert!(serialized.contains("\"backend_id\":\"external-direct\""));
        assert!(serialized.contains("\"model\":\"external-model\""));
        Ok(())
    }

    #[test]
    fn review_lens_model_backend_rejects_inert_reviewer_execution_fields() {
        let config = serde_json::json!({
            "id": "no-inert-dispatch-config",
            "backend": {
                "kind": "model",
                "backend_id": "openai",
                "model": "gpt-5",
                "reasoning_effort": "high",
                "reviewer": {
                    "version": 1,
                    "mode": "external_command",
                    "program": "tools/PRIVATE_PROGRAM_MARKER",
                    "args": ["PRIVATE_ARG_MARKER"],
                    "timeout_seconds": 30
                }
            },
            "information_scope": "diff_only"
        });

        let error = serde_json::from_value::<ReviewLensConfig>(config)
            .expect_err("model lenses must reject unsupported reviewer execution settings");
        assert!(
            error.to_string().contains("unknown field `reviewer`"),
            "unexpected rejection: {error}"
        );
    }

    #[test]
    fn review_lens_all_must_accept_preserves_reject_and_failure_verdicts() -> Result<()> {
        let lenses = vec![
            model_review_lens(
                "lens-a",
                "backend-a",
                "model-a",
                ReviewInformationScope::DiffOnly,
            ),
            model_review_lens(
                "lens-b",
                "backend-b",
                "model-b",
                ReviewInformationScope::OutputReportOnly,
            ),
        ];
        let required = ReviewCoverageRequirement {
            worker_ids: vec!["worker-a".to_string()],
            paths: vec![PathBuf::from("src/review.rs")],
        };
        let accepted = aggregate_review_lenses(
            &lenses,
            ReviewAggregationPolicy::AllMustAccept,
            required.clone(),
            vec![
                bound_lens_verdict(&lenses[0], ReviewLensVerdictStatus::Accept, "binding-a"),
                bound_lens_verdict(&lenses[1], ReviewLensVerdictStatus::Accept, "binding-b"),
            ],
        )?;
        assert_eq!(accepted.decision, ReviewAggregationDecision::Accept);
        assert_eq!(accepted.validated_accepts, 2);

        let rejected = aggregate_review_lenses(
            &lenses,
            ReviewAggregationPolicy::AllMustAccept,
            required.clone(),
            vec![
                bound_lens_verdict(&lenses[0], ReviewLensVerdictStatus::Accept, "binding-a"),
                bound_lens_verdict(&lenses[1], ReviewLensVerdictStatus::Reject, "binding-b"),
            ],
        )?;
        assert_eq!(rejected.decision, ReviewAggregationDecision::Reject);
        assert_eq!(rejected.rejected_lenses, 1);
        assert_eq!(
            rejected.lens_verdicts[1].reported_verdict,
            ReviewLensVerdictStatus::Reject
        );

        let failed = aggregate_review_lenses(
            &lenses,
            ReviewAggregationPolicy::AllMustAccept,
            required,
            vec![bound_lens_verdict(
                &lenses[0],
                ReviewLensVerdictStatus::Accept,
                "binding-a",
            )],
        )?;
        assert_eq!(
            failed.decision,
            ReviewAggregationDecision::ProceduralFailure
        );
        assert_eq!(failed.procedural_failures, 1);
        assert!(!failed.lens_verdicts[1].reported);
        assert_eq!(
            failed.lens_verdicts[1].effective_verdict,
            ReviewLensVerdictStatus::ProceduralFailure
        );
        Ok(())
    }

    #[test]
    fn review_lens_acceptance_requires_coverage_and_bound_evidence() -> Result<()> {
        let lenses = vec![model_review_lens(
            "lens-a",
            "backend-a",
            "model-a",
            ReviewInformationScope::DiffOnly,
        )];
        let aggregate = aggregate_review_lenses(
            &lenses,
            ReviewAggregationPolicy::AllMustAccept,
            ReviewCoverageRequirement {
                worker_ids: vec!["worker-a".to_string()],
                paths: vec![PathBuf::from("src/review.rs")],
            },
            vec![ReviewLensVerdict {
                lens_id: lenses[0].id.clone(),
                lens: ReviewLensDescriptor::from(&lenses[0]),
                request_binding: sha256_hex(b"request-binding-a"),
                verdict: ReviewLensVerdictStatus::Accept,
                coverage: ReviewLensCoverage::default(),
                evidence: Vec::new(),
            }],
        )?;

        assert_eq!(
            aggregate.decision,
            ReviewAggregationDecision::ProceduralFailure
        );
        assert_eq!(
            aggregate.lens_verdicts[0].reported_verdict,
            ReviewLensVerdictStatus::Accept
        );
        assert_eq!(
            aggregate.lens_verdicts[0].effective_verdict,
            ReviewLensVerdictStatus::ProceduralFailure
        );
        let errors = aggregate.lens_verdicts[0].validation_errors.join("\n");
        assert!(errors.contains("lacks bound ModelReview evidence"));
        assert!(errors.contains("omitted required worker coverage"));
        assert!(errors.contains("omitted required path coverage"));
        Ok(())
    }

    #[test]
    fn review_lens_aggregation_binds_verdict_to_parent_built_request() -> Result<()> {
        let lenses = vec![
            model_review_lens(
                "parent-bound-a",
                "provider-a",
                "model-a",
                ReviewInformationScope::DiffOnly,
            ),
            model_review_lens(
                "parent-bound-b",
                "provider-b",
                "model-b",
                ReviewInformationScope::OutputReportOnly,
            ),
        ];
        let sources = ReviewLensRequestSources {
            child_transcript: "private transcript",
            diff: "diff material",
            output_report: "output report material",
        };
        let requests = lenses
            .iter()
            .map(|lens| build_review_lens_request(lens, sources))
            .collect::<Result<Vec<_>>>()?;
        let mismatched = ReviewLensVerdict::for_lens(
            &lenses[0],
            requests[1].request_binding.clone(),
            ReviewLensVerdictStatus::Accept,
            ReviewLensCoverage::default(),
            vec![(
                ReviewLensEvidenceKind::ModelReview,
                "self-bound".to_string(),
            )],
        )?;
        let matching = ReviewLensVerdict::for_lens(
            &lenses[1],
            requests[1].request_binding.clone(),
            ReviewLensVerdictStatus::Accept,
            ReviewLensCoverage::default(),
            vec![(
                ReviewLensEvidenceKind::ModelReview,
                "parent-bound".to_string(),
            )],
        )?;

        let aggregate = aggregate_review_lenses_against_requests(
            &lenses,
            &requests,
            ReviewAggregationPolicy::AllMustAccept,
            ReviewCoverageRequirement::default(),
            vec![mismatched, matching],
        )?;
        assert_eq!(
            aggregate.decision,
            ReviewAggregationDecision::ProceduralFailure
        );
        assert!(aggregate.lens_verdicts[0]
            .validation_errors
            .join("\n")
            .contains("parent-built request"));
        Ok(())
    }

    #[test]
    fn review_lens_aggregation_enforces_verdict_and_evidence_bounds() -> Result<()> {
        let lens = model_review_lens(
            "bounded-verdict-lens",
            "bounded-verdict-backend",
            "bounded-verdict-model",
            ReviewInformationScope::DiffOnly,
        );
        let required = ReviewCoverageRequirement {
            worker_ids: vec!["worker-a".to_string()],
            paths: vec![PathBuf::from("src/review.rs")],
        };
        let base = bound_lens_verdict(
            &lens,
            ReviewLensVerdictStatus::Accept,
            "bounded-verdict-binding",
        );

        let mut oversized_evidence = base.clone();
        oversized_evidence.evidence = vec![base.evidence[0].clone(); REVIEW_FINDING_LIMIT + 1];
        let aggregate = aggregate_review_lenses(
            std::slice::from_ref(&lens),
            ReviewAggregationPolicy::AllMustAccept,
            required.clone(),
            vec![oversized_evidence],
        )?;
        assert_eq!(
            aggregate.decision,
            ReviewAggregationDecision::ProceduralFailure
        );
        assert_eq!(
            aggregate.lens_verdicts[0].evidence.len(),
            REVIEW_FINDING_LIMIT
        );
        assert!(aggregate.lens_verdicts[0]
            .validation_errors
            .join("\n")
            .contains("evidence exceeds"));

        let error = aggregate_review_lenses(
            std::slice::from_ref(&lens),
            ReviewAggregationPolicy::AllMustAccept,
            required,
            vec![base; REVIEW_LENS_LIMIT + 1],
        )
        .expect_err("oversized verdict list must fail before map construction");
        assert!(error.to_string().contains("verdict list exceeds"));
        Ok(())
    }

    #[test]
    fn review_lens_aggregate_retains_all_verdicts_within_public_output_bound() -> Result<()> {
        let lenses = (0..REVIEW_LENS_LIMIT)
            .map(|index| {
                model_review_lens(
                    &format!("bounded-lens-{index}"),
                    &format!("bounded-backend-{index}"),
                    &format!("bounded-model-{index}"),
                    ReviewInformationScope::DiffOnly,
                )
            })
            .collect::<Vec<_>>();
        let verdicts = lenses
            .iter()
            .enumerate()
            .map(|(index, lens)| {
                ReviewLensVerdict::for_lens(
                    lens,
                    sha256_hex(format!("bounded-request-{index}").as_bytes()),
                    ReviewLensVerdictStatus::Accept,
                    ReviewLensCoverage::default(),
                    vec![(
                        ReviewLensEvidenceKind::ModelReview,
                        format!("bounded-evidence-{index}"),
                    )],
                )
            })
            .collect::<Result<Vec<_>>>()?;

        let aggregate = aggregate_review_lenses(
            &lenses,
            ReviewAggregationPolicy::AllMustAccept,
            ReviewCoverageRequirement::default(),
            verdicts,
        )?;
        assert_eq!(aggregate.lens_verdicts.len(), REVIEW_LENS_LIMIT);
        assert!(aggregate
            .lens_verdicts
            .iter()
            .all(|verdict| verdict.reported));
        assert_eq!(aggregate.validated_accepts, aggregate.lens_verdicts.len());
        assert!(serde_json::to_vec(&aggregate)?.len() <= REVIEW_LENS_AGGREGATE_LIMIT_BYTES);
        Ok(())
    }

    #[test]
    fn review_lens_maximal_evidence_aggregate_exceeding_public_bound_is_rejected() -> Result<()> {
        let lenses = (0..REVIEW_LENS_LIMIT)
            .map(|index| {
                model_review_lens(
                    &format!("maximal-lens-{index}"),
                    &format!("maximal-backend-{index}"),
                    &format!("maximal-model-{index}"),
                    ReviewInformationScope::OutputReportOnly,
                )
            })
            .collect::<Vec<_>>();
        let verdicts = lenses
            .iter()
            .enumerate()
            .map(|(lens_index, lens)| {
                let evidence = (0..REVIEW_FINDING_LIMIT)
                    .map(|evidence_index| {
                        (
                            ReviewLensEvidenceKind::ModelReview,
                            format!("maximal-evidence-{lens_index}-{evidence_index}"),
                        )
                    })
                    .collect::<Vec<_>>();
                ReviewLensVerdict::for_lens(
                    lens,
                    sha256_hex(format!("maximal-request-{lens_index}").as_bytes()),
                    ReviewLensVerdictStatus::Accept,
                    ReviewLensCoverage::default(),
                    evidence,
                )
            })
            .collect::<Result<Vec<_>>>()?;

        let error = aggregate_review_lenses(
            &lenses,
            ReviewAggregationPolicy::AllMustAccept,
            ReviewCoverageRequirement::default(),
            verdicts,
        )
        .expect_err("maximal aggregate must exceed the public output bound");
        assert!(error
            .to_string()
            .contains("exceeds its 262144 byte serialized JSON limit"));
        Ok(())
    }

    #[test]
    fn review_lens_procedural_aggregate_omits_rejected_unsafe_metadata() -> Result<()> {
        let lens = model_review_lens(
            "sanitized-aggregate-lens",
            "sanitized-aggregate-backend",
            "sanitized-aggregate-model",
            ReviewInformationScope::DiffOnly,
        );
        let mut verdict = bound_lens_verdict(
            &lens,
            ReviewLensVerdictStatus::Accept,
            "initial-safe-binding",
        );
        verdict.request_binding = "PRIVATE_REQUEST_MARKER".to_string();
        verdict.coverage = ReviewLensCoverage {
            worker_ids: vec!["PRIVATE COVERAGE MARKER".to_string()],
            paths: vec![PathBuf::from("/private/ABSOLUTE_COVERAGE_MARKER")],
        };
        let mut secret_evidence = verdict.evidence[0].clone();
        secret_evidence.binding = "API_TOKEN=PRIVATE_SECRET_EVIDENCE_MARKER".to_string();
        secret_evidence.request_binding = verdict.request_binding.clone();
        secret_evidence.coverage = verdict.coverage.clone();
        let mut absolute_evidence = secret_evidence.clone();
        absolute_evidence.binding = "/private/ABSOLUTE_EVIDENCE_MARKER".to_string();
        let mut ordinary_evidence = secret_evidence.clone();
        ordinary_evidence.binding = "ORDINARY CONFIDENTIAL TRANSCRIPT EVIDENCE MARKER".to_string();
        verdict.evidence = vec![secret_evidence, absolute_evidence, ordinary_evidence];

        let aggregate = aggregate_review_lenses(
            std::slice::from_ref(&lens),
            ReviewAggregationPolicy::AllMustAccept,
            ReviewCoverageRequirement {
                worker_ids: vec!["worker-a".to_string()],
                paths: vec![PathBuf::from("src/review.rs")],
            },
            vec![verdict],
        )?;
        assert_eq!(
            aggregate.decision,
            ReviewAggregationDecision::ProceduralFailure
        );
        assert!(aggregate.lens_verdicts[0].request_binding.is_none());
        assert_eq!(
            aggregate.lens_verdicts[0].coverage,
            ReviewLensCoverage::default()
        );
        assert!(aggregate.lens_verdicts[0].evidence.is_empty());
        let serialized = serde_json::to_string(&aggregate)?;
        for marker in [
            "PRIVATE_REQUEST_MARKER",
            "PRIVATE COVERAGE MARKER",
            "ABSOLUTE_COVERAGE_MARKER",
            "PRIVATE_SECRET_EVIDENCE_MARKER",
            "ABSOLUTE_EVIDENCE_MARKER",
            "ORDINARY CONFIDENTIAL TRANSCRIPT EVIDENCE MARKER",
        ] {
            assert!(
                !serialized.contains(marker),
                "procedural aggregate leaked rejected marker {marker}"
            );
        }
        Ok(())
    }

    #[test]
    fn review_lens_mismatched_evidence_metadata_fails_procedurally() -> Result<()> {
        let lens = model_review_lens(
            "metadata-lens",
            "metadata-backend",
            "metadata-model",
            ReviewInformationScope::DiffOnly,
        );
        let required = ReviewCoverageRequirement {
            worker_ids: vec!["worker-a".to_string()],
            paths: vec![PathBuf::from("src/review.rs")],
        };
        let base = bound_lens_verdict(&lens, ReviewLensVerdictStatus::Accept, "metadata-binding");
        let mut cases = Vec::new();

        let mut lens_id = base.clone();
        lens_id.evidence[0].lens.id = "other-lens".to_string();
        cases.push((lens_id, "evidence lens id"));

        let mut backend = base.clone();
        backend.evidence[0].lens.backend_id = "other-backend".to_string();
        cases.push((backend, "evidence backend id"));

        let mut model = base.clone();
        model.evidence[0].lens.model = "other-model".to_string();
        cases.push((model, "evidence model"));

        let mut scope = base.clone();
        scope.evidence[0].lens.information_scope = ReviewInformationScope::OutputReportOnly;
        cases.push((scope, "evidence information scope"));

        let mut coverage = base.clone();
        coverage.evidence[0].coverage = ReviewLensCoverage::default();
        cases.push((coverage, "evidence coverage"));

        let mut backend_configuration = base.clone();
        backend_configuration.evidence[0].backend_configuration_id =
            sha256_hex(b"other-backend-configuration");
        cases.push((backend_configuration, "backend configuration identity"));

        let mut request = base.clone();
        request.evidence[0].request_binding = sha256_hex(b"other-request");
        cases.push((request, "evidence request identity"));

        for (verdict, expected_error) in cases {
            let aggregate = aggregate_review_lenses(
                std::slice::from_ref(&lens),
                ReviewAggregationPolicy::AllMustAccept,
                required.clone(),
                vec![verdict],
            )?;
            assert_eq!(
                aggregate.decision,
                ReviewAggregationDecision::ProceduralFailure
            );
            assert_eq!(
                aggregate.lens_verdicts[0].reported_verdict,
                ReviewLensVerdictStatus::Accept
            );
            assert_eq!(
                aggregate.lens_verdicts[0].effective_verdict,
                ReviewLensVerdictStatus::ProceduralFailure
            );
            assert!(
                aggregate.lens_verdicts[0]
                    .validation_errors
                    .join("\n")
                    .contains(expected_error),
                "missing validation error for {expected_error}"
            );
        }
        Ok(())
    }

    #[test]
    fn review_lens_mismatched_verdict_identity_fails_procedurally() -> Result<()> {
        let lens = model_review_lens(
            "verdict-metadata-lens",
            "verdict-backend",
            "verdict-model",
            ReviewInformationScope::OutputReportOnly,
        );
        let required = ReviewCoverageRequirement {
            worker_ids: vec!["worker-a".to_string()],
            paths: vec![PathBuf::from("src/review.rs")],
        };
        let base = bound_lens_verdict(&lens, ReviewLensVerdictStatus::Accept, "verdict-binding");
        let mut cases = Vec::new();

        let mut id = base.clone();
        id.lens.id = "wrong-verdict-lens".to_string();
        cases.push((id, "verdict id"));

        let mut backend = base.clone();
        backend.lens.backend_id = "wrong-verdict-backend".to_string();
        cases.push((backend, "verdict backend id"));

        let mut model = base.clone();
        model.lens.model = "wrong-verdict-model".to_string();
        cases.push((model, "verdict model"));

        let mut scope = base.clone();
        scope.lens.information_scope = ReviewInformationScope::DiffOnly;
        cases.push((scope, "verdict information scope"));

        let mut request = base;
        request.request_binding = sha256_hex(b"wrong-verdict-request");
        cases.push((request, "evidence request identity"));

        for (verdict, expected_error) in cases {
            let aggregate = aggregate_review_lenses(
                std::slice::from_ref(&lens),
                ReviewAggregationPolicy::AllMustAccept,
                required.clone(),
                vec![verdict],
            )?;
            assert_eq!(
                aggregate.decision,
                ReviewAggregationDecision::ProceduralFailure
            );
            assert!(
                aggregate.lens_verdicts[0]
                    .validation_errors
                    .join("\n")
                    .contains(expected_error),
                "missing validation error for {expected_error}"
            );
        }
        Ok(())
    }

    #[test]
    fn review_lens_validated_quorum_keeps_disagreement_visible() -> Result<()> {
        let lenses = vec![
            model_review_lens(
                "lens-a",
                "backend-a",
                "model-a",
                ReviewInformationScope::DiffOnly,
            ),
            model_review_lens(
                "lens-b",
                "backend-b",
                "model-b",
                ReviewInformationScope::OutputReportOnly,
            ),
            model_review_lens(
                "lens-c",
                "backend-c",
                "model-c",
                ReviewInformationScope::DiffOnly,
            ),
        ];
        let aggregate = aggregate_review_lenses(
            &lenses,
            ReviewAggregationPolicy::ValidatedQuorum { minimum_accepts: 2 },
            ReviewCoverageRequirement {
                worker_ids: vec!["worker-a".to_string()],
                paths: vec![PathBuf::from("src/review.rs")],
            },
            vec![
                bound_lens_verdict(&lenses[0], ReviewLensVerdictStatus::Accept, "binding-a"),
                bound_lens_verdict(&lenses[1], ReviewLensVerdictStatus::Accept, "binding-b"),
                bound_lens_verdict(&lenses[2], ReviewLensVerdictStatus::Reject, "binding-c"),
            ],
        )?;

        assert_eq!(aggregate.decision, ReviewAggregationDecision::Accept);
        assert_eq!(aggregate.validated_accepts, 2);
        assert_eq!(aggregate.rejected_lenses, 1);
        assert_eq!(aggregate.lens_verdicts.len(), 3);
        assert_eq!(
            aggregate.lens_verdicts[2].effective_verdict,
            ReviewLensVerdictStatus::Reject
        );
        Ok(())
    }

    #[test]
    fn review_lens_validated_quorum_does_not_waive_all_worker_coverage() -> Result<()> {
        let lenses = vec![
            model_review_lens(
                "lens-a",
                "backend-a",
                "model-a",
                ReviewInformationScope::DiffOnly,
            ),
            model_review_lens(
                "lens-b",
                "backend-b",
                "model-b",
                ReviewInformationScope::OutputReportOnly,
            ),
            model_review_lens(
                "lens-c",
                "backend-c",
                "model-c",
                ReviewInformationScope::DiffOnly,
            ),
        ];
        let aggregate = aggregate_review_lenses(
            &lenses,
            ReviewAggregationPolicy::ValidatedQuorum { minimum_accepts: 2 },
            ReviewCoverageRequirement {
                worker_ids: vec!["worker-a".to_string(), "worker-b".to_string()],
                paths: vec![
                    PathBuf::from("src/review.rs"),
                    PathBuf::from("src/supervise.rs"),
                ],
            },
            vec![
                bound_lens_verdict(&lenses[0], ReviewLensVerdictStatus::Accept, "binding-a"),
                bound_lens_verdict(&lenses[1], ReviewLensVerdictStatus::Accept, "binding-b"),
                bound_lens_verdict(&lenses[2], ReviewLensVerdictStatus::Reject, "binding-c"),
            ],
        )?;

        assert_eq!(
            aggregate.decision,
            ReviewAggregationDecision::ProceduralFailure
        );
        assert_eq!(aggregate.validated_accepts, 0);
        assert_eq!(aggregate.procedural_failures, 2);
        for verdict in &aggregate.lens_verdicts[..2] {
            let errors = verdict.validation_errors.join("\n");
            assert!(errors.contains("worker-b"));
            assert!(errors.contains("src/supervise.rs"));
        }
        Ok(())
    }

    #[test]
    fn review_lens_precomputed_process_evidence_participates_in_aggregation() -> Result<()> {
        let lenses = vec![ReviewLensConfig {
            id: "process-evidence".to_string(),
            backend: ReviewLensBackendConfig::Precomputed {
                backend_id: "verified-process-attestor".to_string(),
                model: "process-evidence-v1".to_string(),
                evidence_kind: ReviewLensEvidenceKind::ProcessEvidence,
            },
            information_scope: ReviewInformationScope::OutputReportOnly,
        }];
        let aggregate = aggregate_review_lenses(
            &lenses,
            ReviewAggregationPolicy::AllMustAccept,
            ReviewCoverageRequirement {
                worker_ids: vec!["worker-a".to_string()],
                paths: vec![PathBuf::from("src/review.rs")],
            },
            vec![ReviewLensVerdict::for_lens(
                &lenses[0],
                sha256_hex(b"process-evidence-request"),
                ReviewLensVerdictStatus::Accept,
                ReviewLensCoverage {
                    worker_ids: vec!["worker-a".to_string()],
                    paths: vec![PathBuf::from("src/review.rs")],
                },
                vec![(
                    ReviewLensEvidenceKind::ProcessEvidence,
                    "process-binding-v1".to_string(),
                )],
            )?],
        )?;

        assert_eq!(aggregate.decision, ReviewAggregationDecision::Accept);
        assert_eq!(aggregate.validated_accepts, 1);
        assert!(build_review_lens_request(
            &lenses[0],
            ReviewLensRequestSources {
                child_transcript: "excluded",
                diff: "excluded",
                output_report: "excluded",
            }
        )
        .is_err());
        Ok(())
    }

    #[test]
    fn fake_review_constructs_passed_report_with_deterministic_identity() {
        let report = fake_review(ReviewPrOptions {
            repo: PathBuf::from("."),
            target: "#42".to_string(),
            reviewer: ReviewerConfig::default(),
            attempt: 1,
            changed_paths: vec![PathBuf::from("src/review.rs")],
            diff_summary: Some("changed src/review.rs".to_string()),
        });

        assert_eq!(report.status, ReviewReportStatus::Passed);
        assert!(report.success);
        assert_eq!(report.target, "#42");
        assert_eq!(report.reviewer.mode, ReviewerMode::Fake);
        assert_eq!(report.reviewer.reviewer_id, "autopilot-fake-reviewer");
        assert_eq!(report.reviewer.model, "deterministic-local-reviewer");
        assert_eq!(report.findings, Vec::<ReviewFinding>::new());
        assert_eq!(report.blocking_finding_count, 0);
        assert_eq!(report.diff_source, "sanitized_merge_candidate_summary");
        assert!(!report.ci_reaction_supported);
        assert_eq!(report.ci_reaction, "unsupported");
    }

    #[test]
    fn sanitize_review_output_with_dot_repo_does_not_expand_empty_parent() {
        let output = sanitize_review_output(Path::new("."), b"plain diagnostics");

        assert_eq!(output.text, "plain diagnostics");
        assert!(!output.truncated);
    }

    #[test]
    fn sanitize_review_output_redacts_canonical_repo_path() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let diagnostic = format!("failure in {}/src/review.rs", temp.path().display());

        let output = sanitize_review_output(temp.path(), diagnostic.as_bytes());

        assert_eq!(output.text, "failure in ./src/review.rs");
        Ok(())
    }

    #[test]
    fn sanitize_review_output_rejects_control_and_external_path_diagnostics() {
        let control = sanitize_review_output(Path::new("."), b"unsafe\x1bdiagnostic");
        assert_eq!(control.text, "<redacted:control-character-diagnostic>");
        assert!(control.truncated);

        let external = sanitize_review_output(Path::new("."), b"failure in /private/sibling");
        assert_eq!(external.text, "<redacted:absolute-path-diagnostic>");
    }

    #[test]
    fn fake_review_constructs_blocking_template_finding() {
        let report = fake_review(ReviewPrOptions {
            repo: PathBuf::from("."),
            target: "#43".to_string(),
            reviewer: ReviewerConfig {
                mode: ReviewerMode::Fake,
                blocking_attempts: 1,
                finding: Some(FakeReviewFindingTemplate {
                    severity: "warning".to_string(),
                    path: None,
                    summary: "deterministic template finding".to_string(),
                    suggested_fix: "apply the deterministic fix".to_string(),
                }),
                ..ReviewerConfig::default()
            },
            attempt: 1,
            changed_paths: vec![PathBuf::from("src/review.rs")],
            diff_summary: None,
        });

        assert_eq!(report.status, ReviewReportStatus::Blocked);
        assert!(!report.success);
        assert_eq!(report.blocking_finding_count, 1);
        assert_eq!(report.diff_source, "pr_target_only");
        assert_eq!(
            report.findings,
            vec![ReviewFinding {
                severity: "warning".to_string(),
                path: Some(PathBuf::from("src/review.rs")),
                summary: "deterministic template finding".to_string(),
                suggested_fix: "apply the deterministic fix".to_string(),
                blocking: true,
            }]
        );
        assert!(!report.ci_reaction_supported);
    }

    #[cfg(unix)]
    #[test]
    fn verified_reviewer_rejects_native_interpreter_stdin_eval_and_dispatch_forms() {
        let native_image = b"\x7fELF dedicated fixture";
        let cases = [
            ("/bin/sh", "/usr/bin/dash", Vec::<String>::new()),
            ("/bin/sh", "/usr/bin/dash", vec!["-s".to_string()]),
            (
                "/usr/bin/python3",
                "/usr/bin/python3.13",
                vec!["-c".to_string(), "review()".to_string()],
            ),
            (
                "/usr/bin/python3",
                "/usr/bin/python3.13",
                vec!["-".to_string()],
            ),
            (
                "/usr/bin/node",
                "/usr/bin/node",
                vec!["--eval".to_string(), "review()".to_string()],
            ),
            ("/usr/bin/node", "/usr/bin/node", vec!["-".to_string()]),
            (
                "/usr/bin/perl",
                "/usr/bin/perl5.40",
                vec!["-e".to_string(), "review()".to_string()],
            ),
            ("/usr/bin/perl", "/usr/bin/perl5.40", vec!["-".to_string()]),
            (
                "/usr/bin/ruby",
                "/usr/bin/ruby3.4",
                vec!["-e".to_string(), "review()".to_string()],
            ),
            ("/usr/bin/ruby", "/usr/bin/ruby3.4", vec!["-".to_string()]),
            (
                "/usr/bin/env",
                "/usr/bin/coreutils",
                vec!["python3".to_string(), "-".to_string()],
            ),
            (
                "/opt/reviewer-alias",
                "/usr/bin/python3.13",
                vec!["-".to_string()],
            ),
            (
                "/opt/reviewer-alias",
                "/usr/bin/busybox",
                vec!["sh".to_string()],
            ),
        ];

        for (configured, canonical, args) in cases {
            let error = validate_verified_reviewer_image(
                Path::new(configured),
                Path::new(canonical),
                &args,
                native_image,
            )
            .expect_err("native interpreter and dispatcher authority must fail closed");
            assert!(error
                .to_string()
                .contains("shell, language interpreter, or command dispatcher"));
        }
    }

    #[cfg(unix)]
    #[test]
    fn verified_reviewer_allows_direct_shebang_script_and_dedicated_binary() -> Result<()> {
        validate_verified_reviewer_image(
            Path::new("reviewer-script"),
            Path::new("/private/runtime/reviewer-script"),
            &[],
            b"#!/bin/sh\nexit 0\n",
        )?;
        validate_verified_reviewer_image(
            Path::new("reviewer-python-adapter"),
            Path::new("/opt/review/reviewer-python-adapter"),
            &["--strict".to_string()],
            b"\x7fELF dedicated reviewer fixture",
        )?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn reviewer_script_rejects_configured_and_canonical_dispatcher_shebangs() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir()?;
        let dispatcher = temp.path().join("env");
        std::fs::write(&dispatcher, b"native dispatcher fixture")?;
        std::fs::set_permissions(&dispatcher, std::fs::Permissions::from_mode(0o700))?;
        let script = format!("#!{}\nexit 0\n", dispatcher.display());
        let error = reviewer_script_interpreter(script.as_bytes())
            .expect_err("dispatcher shebang must fail closed");
        assert!(error.to_string().contains("command dispatchers"));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn bound_verified_reviewer_classifies_script_binary_and_interpreter_images() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir()?;
        git2::Repository::init(temp.path())?;
        for (name, bytes) in [
            ("reviewer-binary", b"\x7fELF dedicated reviewer".as_slice()),
            ("sh", b"#!/bin/sh\nexit 0\n".as_slice()),
            ("python3", b"\x7fELF interpreter fixture".as_slice()),
        ] {
            let path = temp.path().join(name);
            std::fs::write(&path, bytes)?;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
        }
        let repository = ReviewRepositoryBinding::bind(temp.path())?;

        let binary = BoundReviewerProgram::bind(&repository, Path::new("reviewer-binary"))?;
        validate_verified_reviewer_program(&repository, &binary, &[])?;
        let script = BoundReviewerProgram::bind(&repository, Path::new("sh"))?;
        validate_verified_reviewer_program(&repository, &script, &[])?;
        let interpreter = BoundReviewerProgram::bind(&repository, Path::new("python3"))?;
        assert!(
            validate_verified_reviewer_program(&repository, &interpreter, &["-".to_string()])
                .is_err()
        );
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn sanitized_view_contains_only_selected_content_modes_and_internal_symlinks() -> Result<()> {
        use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};

        let temp = tempfile::tempdir()?;
        let repository = git2::Repository::init(temp.path())?;
        std::fs::write(temp.path().join(".gitignore"), "ignored/\n.maco/\n")?;
        std::fs::create_dir(temp.path().join("docs"))?;
        std::fs::set_permissions(
            temp.path().join("docs"),
            std::fs::Permissions::from_mode(0o750),
        )?;
        std::fs::write(temp.path().join("docs/tracked.txt"), "tracked\n")?;
        std::fs::set_permissions(
            temp.path().join("docs/tracked.txt"),
            std::fs::Permissions::from_mode(0o740),
        )?;
        symlink("docs/tracked.txt", temp.path().join("tracked-link"))?;
        let mut index = repository.index()?;
        for path in [
            Path::new(".gitignore"),
            Path::new("docs/tracked.txt"),
            Path::new("tracked-link"),
        ] {
            index.add_path(path)?;
        }
        index.write()?;
        std::fs::write(temp.path().join("untracked.txt"), "untracked\n")?;
        std::fs::create_dir(temp.path().join("ignored"))?;
        std::fs::write(temp.path().join("ignored/secret.txt"), "ignored-secret\n")?;
        std::fs::create_dir(temp.path().join(".maco"))?;
        std::fs::write(temp.path().join(".maco/auth-key"), "must-not-copy\n")?;

        let binding = ReviewRepositoryBinding::bind(temp.path())?;
        let view = SanitizedReviewerView::create(&binding)?;
        let view_path = view.path();
        assert!(!view_path.starts_with(temp.path()));
        assert_eq!(
            std::fs::read_to_string(view_path.join("docs/tracked.txt"))?,
            "tracked\n"
        );
        assert_eq!(
            std::fs::read_to_string(view_path.join("untracked.txt"))?,
            "untracked\n"
        );
        assert_eq!(
            std::fs::read_link(view_path.join("tracked-link"))?,
            PathBuf::from("docs/tracked.txt")
        );
        assert_eq!(
            std::fs::metadata(view_path.join("docs"))?.mode() & 0o7777,
            0o750
        );
        assert_eq!(
            std::fs::metadata(view_path.join("docs/tracked.txt"))?.mode() & 0o7777,
            0o740
        );
        assert_eq!(
            std::fs::symlink_metadata(view_path.join("tracked-link"))?.mode() & libc::S_IFMT,
            libc::S_IFLNK
        );
        assert!(!view_path.join("ignored").exists());
        assert!(!view_path.join(".git").exists());
        assert!(!view_path.join(".maco").exists());
        view.verify(&binding)?;
        drop(view);
        assert!(!view_path.exists());
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn sanitized_view_binding_changes_with_content_mode_and_path() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir()?;
        let repository = git2::Repository::init(temp.path())?;
        std::fs::write(temp.path().join("entry"), "one")?;
        let mut index = repository.index()?;
        index.add_path(Path::new("entry"))?;
        index.write()?;
        let repository_binding = ReviewRepositoryBinding::bind(temp.path())?;

        let content_binding = {
            let view = SanitizedReviewerView::create(&repository_binding)?;
            view.binding().to_string()
        };
        std::fs::write(temp.path().join("entry"), "two")?;
        let changed_content_binding = {
            let view = SanitizedReviewerView::create(&repository_binding)?;
            view.binding().to_string()
        };
        assert_ne!(content_binding, changed_content_binding);

        std::fs::set_permissions(
            temp.path().join("entry"),
            std::fs::Permissions::from_mode(0o700),
        )?;
        let changed_mode_binding = {
            let view = SanitizedReviewerView::create(&repository_binding)?;
            view.binding().to_string()
        };
        assert_ne!(changed_content_binding, changed_mode_binding);

        std::fs::rename(temp.path().join("entry"), temp.path().join("renamed"))?;
        let mut index = repository.index()?;
        index.remove_path(Path::new("entry"))?;
        index.add_path(Path::new("renamed"))?;
        index.write()?;
        let changed_path_binding = {
            let view = SanitizedReviewerView::create(&repository_binding)?;
            view.binding().to_string()
        };
        assert_ne!(changed_mode_binding, changed_path_binding);
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn sanitized_view_rejects_tracked_or_changed_maco_paths() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let repository = git2::Repository::init(temp.path())?;
        std::fs::create_dir(temp.path().join(".maco"))?;
        std::fs::write(temp.path().join(".maco/tracked"), "tracked runtime")?;
        let mut index = repository.index()?;
        index.add_path(Path::new(".maco/tracked"))?;
        index.write()?;
        let binding = ReviewRepositoryBinding::bind(temp.path())?;
        assert!(SanitizedReviewerView::create(&binding).is_err());
        assert!(validate_sanitized_changed_paths(&[PathBuf::from(".maco/report.json")]).is_err());
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn sanitized_view_rejects_external_dangling_symlinks_and_hardlinks() -> Result<()> {
        use std::os::unix::fs::symlink;

        let external = tempfile::tempdir()?;
        let external_repo = git2::Repository::init(external.path())?;
        symlink("/etc/passwd", external.path().join("escape"))?;
        external_repo.index()?.add_path(Path::new("escape"))?;
        external_repo.index()?.write()?;
        let binding = ReviewRepositoryBinding::bind(external.path())?;
        assert!(SanitizedReviewerView::create(&binding).is_err());

        let dangling = tempfile::tempdir()?;
        let dangling_repo = git2::Repository::init(dangling.path())?;
        symlink("missing", dangling.path().join("dangling"))?;
        let mut index = dangling_repo.index()?;
        index.add_path(Path::new("dangling"))?;
        index.write()?;
        let binding = ReviewRepositoryBinding::bind(dangling.path())?;
        assert!(SanitizedReviewerView::create(&binding).is_err());

        let hardlink_root = tempfile::tempdir()?;
        let repo_path = hardlink_root.path().join("repo");
        std::fs::create_dir(&repo_path)?;
        let hardlink_repo = git2::Repository::init(&repo_path)?;
        std::fs::write(hardlink_root.path().join("outside"), "hardlinked secret")?;
        std::fs::hard_link(
            hardlink_root.path().join("outside"),
            repo_path.join("hardlink"),
        )?;
        let mut index = hardlink_repo.index()?;
        index.add_path(Path::new("hardlink"))?;
        index.write()?;
        let binding = ReviewRepositoryBinding::bind(&repo_path)?;
        assert!(SanitizedReviewerView::create(&binding).is_err());
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn sanitized_view_detects_source_and_view_races() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let repository = git2::Repository::init(temp.path())?;
        std::fs::write(temp.path().join("tracked"), "before")?;
        let mut index = repository.index()?;
        index.add_path(Path::new("tracked"))?;
        index.write()?;
        let binding = ReviewRepositoryBinding::bind(temp.path())?;
        let view = SanitizedReviewerView::create(&binding)?;
        std::fs::write(temp.path().join("tracked"), "after")?;
        assert!(view.verify(&binding).is_err());
        drop(view);

        std::fs::write(temp.path().join("tracked"), "before")?;
        let binding = ReviewRepositoryBinding::bind(temp.path())?;
        let view = SanitizedReviewerView::create(&binding)?;
        std::fs::write(view.path().join("tracked"), "tampered")?;
        assert!(view.verify(&binding).is_err());
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn sanitized_view_rejects_gitlink_sparse_case_depth_and_aggregate_bounds() -> Result<()> {
        let gitlink = tempfile::tempdir()?;
        let repository = git2::Repository::init(gitlink.path())?;
        let mut index = repository.index()?;
        index.add(&git2::IndexEntry {
            ctime: git2::IndexTime::new(0, 0),
            mtime: git2::IndexTime::new(0, 0),
            dev: 0,
            ino: 0,
            mode: 0o160000,
            uid: 0,
            gid: 0,
            file_size: 0,
            id: git2::Oid::ZERO_SHA1,
            flags: 0,
            flags_extended: 0,
            path: b"submodule".to_vec(),
        })?;
        index.write()?;
        let binding = ReviewRepositoryBinding::bind(gitlink.path())?;
        assert!(SanitizedReviewerView::create(&binding).is_err());

        let sparse = tempfile::tempdir()?;
        let repository = git2::Repository::init(sparse.path())?;
        std::fs::write(sparse.path().join("sparse"), "sparse")?;
        let mut index = repository.index()?;
        index.add_path(Path::new("sparse"))?;
        let mut sparse_entry = index
            .get_path(Path::new("sparse"), 0)
            .context("sparse index entry")?;
        sparse_entry.flags_extended |= 1 << 14;
        index.add(&sparse_entry)?;
        index.write()?;
        std::fs::remove_file(sparse.path().join("sparse"))?;
        let binding = ReviewRepositoryBinding::bind(sparse.path())?;
        assert!(SanitizedReviewerView::create(&binding).is_err());

        let case = SanitizedViewSelection {
            entries: BTreeMap::from([
                (PathBuf::from("Case/file"), SanitizedViewOrigin::default()),
                (PathBuf::from("case/other"), SanitizedViewOrigin::default()),
            ]),
        };
        assert!(validate_sanitized_view_paths(&case).is_err());
        let deep = SanitizedViewSelection {
            entries: BTreeMap::from([(
                (0..=REVIEW_PREWALK_MAX_DEPTH)
                    .map(|_| "x")
                    .collect::<PathBuf>(),
                SanitizedViewOrigin::default(),
            )]),
        };
        assert!(validate_sanitized_view_paths(&deep).is_err());

        let aggregate = tempfile::tempdir()?;
        git2::Repository::init(aggregate.path())?;
        std::fs::write(aggregate.path().join("entry"), "x")?;
        let root = SafeRoot::open_existing(aggregate.path())?;
        let reader = ReviewTreeReader::bind(&root)?;
        let mut total = REVIEW_SNAPSHOT_TOTAL_LIMIT_BYTES;
        assert!(reader
            .snapshot_entry(Path::new("entry"), &mut total)
            .is_err());
        Ok(())
    }

    #[test]
    fn sanitized_view_rejects_special_modes_and_collapses_hidden_ancestors() {
        let entry = SnapshotTreeEntry::Regular {
            mode: unsigned_to_u32(libc::S_IFREG) | 0o4755,
            length: 1,
            sha256: [0; 32],
            identity: FileIdentity { device: 1, file: 1 },
            modified_seconds: 0,
            modified_nanoseconds: 0,
            changed_seconds: 0,
            changed_nanoseconds: 0,
        };
        assert!(validate_sanitized_view_entry_mode(&entry).is_err());

        let requested = BTreeSet::from([
            PathBuf::from("/data/primary"),
            PathBuf::from("/data/primary/.git"),
            PathBuf::from("/data/primary/.git/maco/state"),
            PathBuf::from("/data/worktrees"),
            PathBuf::from("/data/worktrees/review"),
        ]);
        let hidden = minimal_sanitized_hidden_roots(requested.clone());
        assert_eq!(
            hidden,
            vec![
                PathBuf::from("/data/primary"),
                PathBuf::from("/data/worktrees")
            ]
        );
        assert!(requested
            .iter()
            .all(|path| hidden.iter().any(|root| path.starts_with(root))));
        assert!(hidden.iter().enumerate().all(|(index, path)| hidden
            .iter()
            .enumerate()
            .all(|(other, candidate)| index == other
                || (!path.starts_with(candidate) && !candidate.starts_with(path)))));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn sanitized_confinement_exposes_only_view_store_and_materialized_reviewer() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir()?;
        let repository = git2::Repository::init(temp.path())?;
        let maco = repository.path().join("maco");
        let state = maco.join("state");
        std::fs::create_dir_all(&state)?;
        std::fs::set_permissions(&maco, std::fs::Permissions::from_mode(0o700))?;
        std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700))?;
        std::fs::write(state.join("auth.key"), "never-read-or-copied")?;
        let binding = ReviewRepositoryBinding::bind(temp.path())?;
        let runtime = trusted_linux_runtime_root()?;
        let view = runtime.join("sanitized-view-fixture");
        let materialized = runtime.join("materialized-reviewer-fixture");
        let profile = binding.sanitized_confinement_profile(&view, &materialized)?;

        assert!(profile.isolated_host_view());
        assert!(profile
            .visible_read_only_roots()
            .contains(&PathBuf::from("/nix/store")));
        assert!(profile.visible_read_only_roots().contains(&materialized));
        for original in [
            binding.worktree_root.path(),
            binding.git_dir_root.path(),
            binding.common_dir_root.path(),
            state.as_path(),
        ] {
            assert!(profile
                .hidden_roots()
                .iter()
                .any(|root| original.starts_with(root)));
        }
        assert!(profile.hidden_roots().iter().all(|root| {
            !view.starts_with(root)
                && !materialized.starts_with(root)
                && !root.starts_with(&view)
                && !root.starts_with(&materialized)
        }));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn external_review_drains_large_output_before_timeout() -> Result<()> {
        let temp = tempfile::tempdir()?;
        git2::Repository::init(temp.path())?;
        let command = external_echo_command(
            "#44",
            1,
            r#"["src/review.rs"]"#,
            "pr_target_only",
            "i=0; while [ \"$i\" -lt 256 ]; do printf '%4096s' ' ' >&2; i=$((i + 1)); done;",
        );
        let program = write_reviewer_script(temp.path(), "reviewer-large", &command)?;

        let report = external_review_simulation(ReviewPrOptions {
            repo: temp.path().to_path_buf(),
            target: "#44".to_string(),
            reviewer: ReviewerConfig {
                mode: ReviewerMode::ExternalCommand,
                program: Some(program),
                timeout_seconds: Some(3),
                ..ReviewerConfig::default()
            },
            attempt: 1,
            changed_paths: vec![PathBuf::from("src/review.rs")],
            diff_summary: None,
        })?;

        assert_eq!(report.status, ReviewReportStatus::Passed);
        assert!(report.success);
        assert_eq!(report.reviewer.mode, ReviewerMode::ExternalCommand);
        assert_eq!(
            report
                .diagnostics
                .as_ref()
                .and_then(|diagnostics| diagnostics.timeout_seconds),
            Some(3)
        );
        Ok(())
    }

    #[test]
    fn reviewer_config_wires_are_versioned_strict_and_omission_compatible() -> Result<()> {
        let config: ReviewerConfig = serde_json::from_str(
            r#"{
                "mode": "fake",
                "blocking_attempts": 1,
                "finding": {
                    "severity": "warning",
                    "summary": "bounded finding",
                    "suggested_fix": "bounded fix"
                }
            }"#,
        )?;
        let serialized = serde_json::to_value(&config)?;
        assert_eq!(serialized["version"], REVIEW_SCHEMA_VERSION);
        assert_eq!(serialized["finding"]["version"], REVIEW_SCHEMA_VERSION);

        assert!(serde_json::from_str::<ReviewerConfig>(r#"{"version":2,"mode":"fake"}"#).is_err());
        assert!(
            serde_json::from_str::<ReviewerConfig>(r#"{"mode":"fake","unknown":true}"#).is_err()
        );
        assert!(serde_json::from_str::<ReviewerConfig>(
            r#"{"mode":"fake","finding":{"summary":"x","suggested_fix":"y","unknown":true}}"#
        )
        .is_err());
        assert!(serde_json::from_str::<ReviewerConfig>(
            r#"{"mode":"fake","finding":{"version":2,"summary":"x","suggested_fix":"y"}}"#
        )
        .is_err());
        Ok(())
    }

    #[test]
    fn review_entry_rejects_invalid_mode_combinations_and_bounds_before_repo_access() {
        let invalid_fake = review_pr(ReviewPrOptions {
            repo: PathBuf::from("/repository/does/not/exist"),
            target: "#1".to_string(),
            reviewer: ReviewerConfig {
                command: Some("true".to_string()),
                ..ReviewerConfig::default()
            },
            attempt: 1,
            changed_paths: Vec::new(),
            diff_summary: None,
        })
        .expect_err("fake command must be rejected");
        assert!(invalid_fake.to_string().contains("fake reviewer mode"));

        let invalid_external = review_pr(ReviewPrOptions {
            repo: PathBuf::from("/repository/does/not/exist"),
            target: "#1".to_string(),
            reviewer: ReviewerConfig {
                mode: ReviewerMode::ExternalCommand,
                blocking_attempts: 1,
                program: Some(PathBuf::from("reviewer")),
                ..ReviewerConfig::default()
            },
            attempt: 1,
            changed_paths: Vec::new(),
            diff_summary: None,
        })
        .expect_err("external fake fields must be rejected");
        assert!(invalid_external
            .to_string()
            .contains("fake blocking_attempts"));

        let invalid_timeout = review_pr(ReviewPrOptions {
            repo: PathBuf::from("/repository/does/not/exist"),
            target: "#1".to_string(),
            reviewer: ReviewerConfig {
                mode: ReviewerMode::ExternalCommand,
                program: Some(PathBuf::from("reviewer")),
                timeout_seconds: Some(REVIEW_TIMEOUT_LIMIT_SECONDS.saturating_add(1)),
                ..ReviewerConfig::default()
            },
            attempt: 1,
            changed_paths: Vec::new(),
            diff_summary: None,
        })
        .expect_err("oversized timeout must be rejected");
        assert!(invalid_timeout.to_string().contains("timeout_seconds"));

        let legacy_shell = review_pr(ReviewPrOptions {
            repo: PathBuf::from("/repository/does/not/exist"),
            target: "#1".to_string(),
            reviewer: ReviewerConfig {
                mode: ReviewerMode::ExternalCommand,
                command: Some("reviewer --unsafe-shell".to_string()),
                ..ReviewerConfig::default()
            },
            attempt: 1,
            changed_paths: Vec::new(),
            diff_summary: None,
        })
        .expect_err("legacy shell reviewer authority must fail before repository access");
        assert!(legacy_shell.to_string().contains("non-authoritative"));

        for shell_arg in ["-c", "-ec", "--command=unsafe"] {
            let shell_command = review_pr(ReviewPrOptions {
                repo: PathBuf::from("/repository/does/not/exist"),
                target: "#1".to_string(),
                reviewer: ReviewerConfig {
                    mode: ReviewerMode::ExternalCommand,
                    program: Some(PathBuf::from("/bin/sh")),
                    args: vec![shell_arg.to_string(), "unsafe".to_string()],
                    ..ReviewerConfig::default()
                },
                attempt: 1,
                changed_paths: Vec::new(),
                diff_summary: None,
            })
            .expect_err("shell command-string authority must fail before repository access");
            assert!(shell_command.to_string().contains("shell -c"));
        }

        let noncanonical_path = review_pr(ReviewPrOptions {
            repo: PathBuf::from("/repository/does/not/exist"),
            target: "#1".to_string(),
            reviewer: ReviewerConfig::default(),
            attempt: 1,
            changed_paths: vec![PathBuf::from("src//review.rs")],
            diff_summary: None,
        })
        .expect_err("noncanonical public paths must be rejected before repository access");
        assert!(noncanonical_path.to_string().contains("canonical"));
    }

    #[test]
    fn fake_request_binding_frames_path_count_diff_presence_and_reviewer_config() {
        let base = ReviewPrOptions {
            repo: PathBuf::from("."),
            target: "#binding".to_string(),
            reviewer: ReviewerConfig::default(),
            attempt: 1,
            changed_paths: vec![PathBuf::from("a"), PathBuf::from("b")],
            diff_summary: None,
        };
        let ambiguous_without_framing = ReviewPrOptions {
            changed_paths: vec![PathBuf::from("a")],
            diff_summary: Some("b".to_string()),
            ..base.clone()
        };
        assert_ne!(
            fake_review_request_binding(&base),
            fake_review_request_binding(&ambiguous_without_framing)
        );
        let configured = ReviewPrOptions {
            reviewer: ReviewerConfig {
                blocking_attempts: 1,
                finding: Some(FakeReviewFindingTemplate {
                    severity: "warning".to_string(),
                    path: Some(PathBuf::from("a")),
                    summary: "bounded".to_string(),
                    suggested_fix: "repair".to_string(),
                }),
                ..ReviewerConfig::default()
            },
            ..base.clone()
        };
        assert_ne!(
            fake_review_request_binding(&base),
            fake_review_request_binding(&configured)
        );
    }

    #[test]
    fn external_report_wire_is_strict_exact_bounded_and_sensitive_fail_closed() -> Result<()> {
        let options = ReviewPrOptions {
            repo: PathBuf::from("."),
            target: "#77".to_string(),
            reviewer: ReviewerConfig {
                mode: ReviewerMode::ExternalCommand,
                program: Some(PathBuf::from("reviewer")),
                ..ReviewerConfig::default()
            },
            attempt: 2,
            changed_paths: vec![PathBuf::from("src/review.rs")],
            diff_summary: Some("bounded diff".to_string()),
        };
        let mut report = fake_review(ReviewPrOptions {
            repo: options.repo.clone(),
            target: options.target.clone(),
            reviewer: ReviewerConfig::default(),
            attempt: options.attempt,
            changed_paths: options.changed_paths.clone(),
            diff_summary: options.diff_summary.clone(),
        });
        let expected_reviewer = ReviewerIdentity {
            mode: ReviewerMode::ExternalCommand,
            reviewer_id: "external-program-test".to_string(),
            model: "parent-bound-direct-program-v1".to_string(),
        };
        let expected_binding = "a".repeat(64);
        report.reviewer = expected_reviewer.clone();
        report.request_binding = expected_binding.clone();
        let accepted = serde_json::to_vec(&report)?;
        assert!(matches!(
            parse_external_review_report(
                &accepted,
                &options,
                &expected_reviewer,
                &expected_binding
            )?,
            ParsedExternalReview::Accepted(_)
        ));

        let mut unknown = serde_json::to_value(&report)?;
        unknown["unexpected"] = serde_json::json!(true);
        assert!(parse_external_review_report(
            &serde_json::to_vec(&unknown)?,
            &options,
            &expected_reviewer,
            &expected_binding
        )
        .is_err());

        let mut nested_unknown = serde_json::to_value(&report)?;
        nested_unknown["reviewer"]["unexpected"] = serde_json::json!(true);
        assert!(parse_external_review_report(
            &serde_json::to_vec(&nested_unknown)?,
            &options,
            &expected_reviewer,
            &expected_binding
        )
        .is_err());

        let mut legacy_mode = serde_json::to_value(&report)?;
        legacy_mode["reviewer"]["mode"] = serde_json::json!("external");
        assert!(parse_external_review_report(
            &serde_json::to_vec(&legacy_mode)?,
            &options,
            &expected_reviewer,
            &expected_binding
        )
        .is_err());
        let mut missing_version = serde_json::to_value(&report)?;
        missing_version
            .as_object_mut()
            .context("report object")?
            .remove("version");
        assert!(parse_external_review_report(
            &serde_json::to_vec(&missing_version)?,
            &options,
            &expected_reviewer,
            &expected_binding
        )
        .is_err());

        let mut mismatched = serde_json::to_value(&report)?;
        mismatched["attempt"] = serde_json::json!(3);
        assert!(parse_external_review_report(
            &serde_json::to_vec(&mismatched)?,
            &options,
            &expected_reviewer,
            &expected_binding
        )
        .is_err());

        let mut critical_nonblocking = serde_json::to_value(&report)?;
        critical_nonblocking["findings"] = serde_json::json!([{
            "severity": "critical",
            "summary": "critical issue",
            "suggested_fix": "repair it",
            "blocking": false
        }]);
        assert!(parse_external_review_report(
            &serde_json::to_vec(&critical_nonblocking)?,
            &options,
            &expected_reviewer,
            &expected_binding
        )
        .is_err());
        let mut unknown_severity = critical_nonblocking.clone();
        unknown_severity["findings"][0]["severity"] = serde_json::json!("urgent");
        assert!(parse_external_review_report(
            &serde_json::to_vec(&unknown_severity)?,
            &options,
            &expected_reviewer,
            &expected_binding
        )
        .is_err());

        let mut absolute_path = serde_json::to_value(&report)?;
        absolute_path["changed_paths"] = serde_json::json!(["/external/path"]);
        assert!(parse_external_review_report(
            &serde_json::to_vec(&absolute_path)?,
            &options,
            &expected_reviewer,
            &expected_binding
        )
        .is_err());

        let mut sensitive_path = serde_json::to_value(&report)?;
        sensitive_path["status"] = serde_json::json!("blocked");
        sensitive_path["success"] = serde_json::json!(false);
        sensitive_path["findings"] = serde_json::json!([{
            "severity": "error",
            "path": "/external/private/path",
            "summary": "bounded issue",
            "suggested_fix": "repair it",
            "blocking": true
        }]);
        sensitive_path["blocking_finding_count"] = serde_json::json!(1);
        assert!(matches!(
            parse_external_review_report(
                &serde_json::to_vec(&sensitive_path)?,
                &options,
                &expected_reviewer,
                &expected_binding
            )?,
            ParsedExternalReview::RejectedSensitive
        ));

        for unsafe_summary in [
            "API_TOKEN=top-secret",
            "-----BEGIN PRIVATE KEY-----",
            "/external/private/path",
            "control\u{0001}value",
        ] {
            let mut sensitive = serde_json::to_value(&report)?;
            sensitive["next_action"] = serde_json::json!(unsafe_summary);
            assert!(matches!(
                parse_external_review_report(
                    &serde_json::to_vec(&sensitive)?,
                    &options,
                    &expected_reviewer,
                    &expected_binding
                )?,
                ParsedExternalReview::RejectedSensitive
            ));
        }
        assert!(parse_external_review_report(
            &vec![b' '; REVIEW_JSON_LIMIT_BYTES + 1],
            &options,
            &expected_reviewer,
            &expected_binding
        )
        .is_err());
        assert!(parse_external_review_report(
            &[0xff, 0xfe],
            &options,
            &expected_reviewer,
            &expected_binding
        )
        .is_err());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn exact_snapshot_detects_tracked_untracked_ignored_mode_symlink_and_head_changes() -> Result<()>
    {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let temp = tempfile::tempdir()?;
        let repository = git2::Repository::init(temp.path())?;
        std::fs::write(temp.path().join(".gitignore"), "ignored/\n")?;
        std::fs::write(temp.path().join("tracked.txt"), "tracked-a")?;
        std::fs::write(temp.path().join("target-a.txt"), "target-a")?;
        std::fs::write(temp.path().join("target-b.txt"), "target-b")?;
        let mut index = repository.index()?;
        for path in [
            Path::new(".gitignore"),
            Path::new("tracked.txt"),
            Path::new("target-a.txt"),
            Path::new("target-b.txt"),
        ] {
            index.add_path(path)?;
        }
        index.write()?;
        let tree_id = index.write_tree()?;
        let tree = repository.find_tree(tree_id)?;
        let signature = git2::Signature::now("Review Test", "review@example.invalid")?;
        let commit = repository.commit(
            Some("HEAD"),
            &signature,
            &signature,
            "snapshot baseline",
            &tree,
            &[],
        )?;
        drop(tree);
        std::fs::write(temp.path().join("untracked.txt"), "untracked-a")?;
        std::fs::create_dir(temp.path().join("ignored"))?;
        std::fs::write(temp.path().join("ignored/secret.txt"), "ignored-a")?;
        symlink("target-a.txt", temp.path().join("link.txt"))?;
        std::fs::write(temp.path().join("reviewer.sh"), "#!/bin/sh\nexit 0\n")?;
        std::fs::set_permissions(
            temp.path().join("reviewer.sh"),
            std::fs::Permissions::from_mode(0o700),
        )?;

        let binding = ReviewRepositoryBinding::bind(temp.path())?;
        let program = MaterializedReviewerProgram::create(BoundReviewerProgram::bind(
            &binding,
            Path::new("reviewer.sh"),
        )?)?;
        let baseline = binding.snapshot()?;

        std::fs::write(temp.path().join("tracked.txt"), "tracked-b")?;
        let changed_content = binding.snapshot()?;
        assert_ne!(baseline, changed_content);
        let request = ReviewPrOptions {
            repo: temp.path().to_path_buf(),
            target: "#snapshot".to_string(),
            reviewer: ReviewerConfig {
                mode: ReviewerMode::ExternalCommand,
                program: Some(PathBuf::from("reviewer.sh")),
                ..ReviewerConfig::default()
            },
            attempt: 1,
            changed_paths: vec![PathBuf::from("tracked.txt")],
            diff_summary: Some("same labels".to_string()),
        };
        let identity = bound_external_reviewer_identity(&program.binding, &[])?;
        let baseline_binding = external_review_request_binding(
            &request,
            &baseline,
            &identity,
            &program.binding,
            None,
            REVIEW_DEFAULT_TIMEOUT_SECONDS,
        )?;
        assert_ne!(
            baseline_binding,
            external_review_request_binding(
                &request,
                &baseline,
                &identity,
                &program.binding,
                None,
                REVIEW_DEFAULT_TIMEOUT_SECONDS.saturating_add(1)
            )?
        );
        let sanitized_binding = external_review_request_binding(
            &request,
            &baseline,
            &identity,
            &program.binding,
            Some("sanitized-view-a"),
            REVIEW_DEFAULT_TIMEOUT_SECONDS,
        )?;
        assert_ne!(baseline_binding, sanitized_binding);
        assert_ne!(
            sanitized_binding,
            external_review_request_binding(
                &request,
                &baseline,
                &identity,
                &program.binding,
                Some("sanitized-view-b"),
                REVIEW_DEFAULT_TIMEOUT_SECONDS,
            )?
        );
        let changed_policy_payload = serde_json::to_vec(&ExternalReviewRequestBindingPayload {
            version: REVIEW_SCHEMA_VERSION,
            target: &request.target,
            attempt: request.attempt,
            changed_paths: &request.changed_paths,
            diff_summary: request.diff_summary.as_deref(),
            reviewer: &identity,
            program: &program.binding,
            args: &request.reviewer.args,
            sanitized_view_binding: None,
            effective_timeout_seconds: REVIEW_DEFAULT_TIMEOUT_SECONDS,
            sandbox_policy_version: REVIEW_SANDBOX_POLICY_VERSION.saturating_add(1),
            repository_snapshot: &baseline,
        })?;
        assert_ne!(
            baseline_binding,
            domain_sha256(EXTERNAL_REVIEW_REQUEST_DOMAIN, &changed_policy_payload)
        );
        let args_request = ReviewPrOptions {
            reviewer: ReviewerConfig {
                args: vec!["--bounded".to_string()],
                ..request.reviewer.clone()
            },
            ..request.clone()
        };
        let args_identity =
            bound_external_reviewer_identity(&program.binding, &args_request.reviewer.args)?;
        assert_ne!(
            baseline_binding,
            external_review_request_binding(
                &args_request,
                &baseline,
                &args_identity,
                &program.binding,
                None,
                REVIEW_DEFAULT_TIMEOUT_SECONDS
            )?
        );
        assert_ne!(
            external_review_request_binding(
                &request,
                &baseline,
                &identity,
                &program.binding,
                None,
                REVIEW_DEFAULT_TIMEOUT_SECONDS
            )?,
            external_review_request_binding(
                &request,
                &changed_content,
                &identity,
                &program.binding,
                None,
                REVIEW_DEFAULT_TIMEOUT_SECONDS
            )?
        );
        std::fs::write(temp.path().join("tracked.txt"), "tracked-a")?;
        let restored_content = binding.snapshot()?;
        assert_ne!(baseline, restored_content);
        assert_ne!(
            external_review_request_binding(
                &request,
                &baseline,
                &identity,
                &program.binding,
                None,
                REVIEW_DEFAULT_TIMEOUT_SECONDS
            )?,
            external_review_request_binding(
                &request,
                &restored_content,
                &identity,
                &program.binding,
                None,
                REVIEW_DEFAULT_TIMEOUT_SECONDS
            )?
        );

        let mut permissions = std::fs::metadata(temp.path().join("tracked.txt"))?.permissions();
        permissions.set_mode(0o700);
        std::fs::set_permissions(temp.path().join("tracked.txt"), permissions)?;
        assert_ne!(restored_content, binding.snapshot()?);
        let mut permissions = std::fs::metadata(temp.path().join("tracked.txt"))?.permissions();
        permissions.set_mode(0o644);
        std::fs::set_permissions(temp.path().join("tracked.txt"), permissions)?;
        let restored_mode = binding.snapshot()?;
        assert_ne!(restored_content, restored_mode);

        std::fs::write(temp.path().join("untracked.txt"), "untracked-b")?;
        assert_ne!(restored_mode, binding.snapshot()?);
        std::fs::write(temp.path().join("untracked.txt"), "untracked-a")?;
        let restored_untracked = binding.snapshot()?;
        assert_ne!(restored_mode, restored_untracked);
        std::fs::write(temp.path().join("ignored/secret.txt"), "ignored-b")?;
        assert_ne!(restored_untracked, binding.snapshot()?);
        std::fs::write(temp.path().join("ignored/secret.txt"), "ignored-a")?;
        let restored_ignored = binding.snapshot()?;
        assert_ne!(restored_untracked, restored_ignored);

        std::fs::remove_file(temp.path().join("link.txt"))?;
        symlink("target-b.txt", temp.path().join("link.txt"))?;
        assert_ne!(restored_ignored, binding.snapshot()?);
        std::fs::remove_file(temp.path().join("link.txt"))?;
        symlink("target-a.txt", temp.path().join("link.txt"))?;
        assert_ne!(restored_ignored, binding.snapshot()?);

        repository.reference("refs/heads/same-commit", commit, true, "test")?;
        std::fs::write(
            repository.path().join("HEAD"),
            "ref: refs/heads/same-commit\n",
        )?;
        let rebound = binding.snapshot()?;
        assert_eq!(rebound.head, baseline.head);
        assert_ne!(rebound.head_admin_sha256, baseline.head_admin_sha256);
        assert_ne!(rebound.head_symbolic_target, baseline.head_symbolic_target);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn snapshot_refuses_hardlinks_special_entries_external_symlinks_and_gitlinks() -> Result<()> {
        use std::os::unix::{ffi::OsStrExt, fs::symlink};

        let temp = tempfile::tempdir()?;
        let root = SafeRoot::open_existing(temp.path())?;
        let reader = ReviewTreeReader::bind(&root)?;
        std::fs::write(temp.path().join("hard-a"), "same")?;
        std::fs::hard_link(temp.path().join("hard-a"), temp.path().join("hard-b"))?;
        assert!(reader.snapshot_entry(Path::new("hard-a"), &mut 0).is_err());

        symlink("/external/path", temp.path().join("escape-link"))?;
        assert!(reader
            .snapshot_entry(Path::new("escape-link"), &mut 0)
            .is_err());

        let fifo = std::ffi::CString::new(temp.path().join("fifo").as_os_str().as_bytes())?;
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        assert!(reader.snapshot_entry(Path::new("fifo"), &mut 0).is_err());

        let repo_dir = tempfile::tempdir()?;
        let repository = git2::Repository::init(repo_dir.path())?;
        let mut index = repository.index()?;
        index.add(&git2::IndexEntry {
            ctime: git2::IndexTime::new(0, 0),
            mtime: git2::IndexTime::new(0, 0),
            dev: 0,
            ino: 0,
            mode: 0o160000,
            uid: 0,
            gid: 0,
            file_size: 0,
            id: git2::Oid::ZERO_SHA1,
            flags: 0,
            flags_extended: 0,
            path: b"submodule".to_vec(),
        })?;
        index.write()?;
        let binding = ReviewRepositoryBinding::bind(repo_dir.path())?;
        let error = binding.snapshot().expect_err("gitlink must fail closed");
        assert!(error.to_string().contains("gitlink/submodule"));
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn descriptor_prewalk_rejects_oversized_ignored_file_before_git_status() -> Result<()> {
        let temp = tempfile::tempdir()?;
        git2::Repository::init(temp.path())?;
        std::fs::write(temp.path().join(".gitignore"), "ignored.bin\n")?;
        let ignored = File::create(temp.path().join("ignored.bin"))?;
        ignored.set_len(REVIEW_SNAPSHOT_FILE_LIMIT_BYTES.saturating_add(1))?;

        let binding = ReviewRepositoryBinding::bind(temp.path())?;
        let error = binding
            .snapshot()
            .expect_err("oversized ignored files must fail in descriptor prewalk");
        assert!(error.to_string().contains("prewalk"));
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn reviewer_program_materialization_binds_source_copy_and_interpreter() -> Result<()> {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let temp = tempfile::tempdir()?;
        git2::Repository::init(temp.path())?;
        let relative = write_reviewer_script(temp.path(), "reviewer-script", "exit 0")?;
        let repository = ReviewRepositoryBinding::bind(temp.path())?;
        let source = BoundReviewerProgram::bind(&repository, &relative)?;
        let materialized = MaterializedReviewerProgram::create(source)?;
        assert_ne!(
            materialized.execution_path,
            temp.path().join("reviewer-script")
        );
        assert!(materialized.binding.interpreter_source.is_some());
        assert!(materialized.binding.interpreter_copy.is_some());
        materialized.verify(&repository)?;

        std::fs::write(temp.path().join("reviewer-script"), "#!/bin/sh\nexit 1\n")?;
        std::fs::set_permissions(
            temp.path().join("reviewer-script"),
            std::fs::Permissions::from_mode(0o700),
        )?;
        assert!(materialized.verify(&repository).is_err());

        let canonical_interpreter = Path::new("/bin/sh").canonicalize()?;
        let absolute = BoundReviewerProgram::bind(&repository, &canonical_interpreter)?;
        assert!(absolute.path.is_absolute());
        let symlink_path = temp.path().join("reviewer-link");
        symlink(&canonical_interpreter, &symlink_path)?;
        assert!(BoundReviewerProgram::bind(&repository, &symlink_path).is_err());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn review_profile_hides_bound_common_state_without_reading_keys() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir()?;
        let repository = git2::Repository::init(temp.path())?;
        let state = repository.path().join("maco/state");
        std::fs::create_dir_all(&state)?;
        std::fs::set_permissions(
            repository.path().join("maco"),
            std::fs::Permissions::from_mode(0o700),
        )?;
        std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700))?;
        std::fs::write(state.join("private.key"), "must-not-be-read-by-snapshot")?;

        let binding = ReviewRepositoryBinding::bind(temp.path())?;
        assert_eq!(
            binding.confinement_profile()?,
            StrictOfflineWorkspaceProfile::read_only(temp.path()).with_hidden_root(&state)
        );
        let snapshot = binding.snapshot()?;
        assert_eq!(snapshot.state_identity, binding.state.identity());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn external_simulation_rejects_truncated_stderr_and_applies_default_timeout() -> Result<()> {
        let temp = tempfile::tempdir()?;
        git2::Repository::init(temp.path())?;
        let truncated_program = write_reviewer_script(
            temp.path(),
            "reviewer-truncated",
            "cat >/dev/null; i=0; while [ \"$i\" -lt 1100 ]; do printf '%4096s' ' ' >&2; i=$((i + 1)); done",
        )?;
        let report = external_review_simulation(ReviewPrOptions {
            repo: temp.path().to_path_buf(),
            target: "#88".to_string(),
            reviewer: ReviewerConfig {
                mode: ReviewerMode::ExternalCommand,
                program: Some(truncated_program),
                timeout_seconds: None,
                ..ReviewerConfig::default()
            },
            attempt: 1,
            changed_paths: Vec::new(),
            diff_summary: None,
        })
        .expect_err("truncated stderr must be rejected");
        assert!(report.to_string().contains("stdout or stderr"));

        let command = external_echo_command("#89", 1, "[]", "pr_target_only", "");
        let accepted_program = write_reviewer_script(temp.path(), "reviewer-accepted", &command)?;
        let accepted = external_review_simulation(ReviewPrOptions {
            repo: temp.path().to_path_buf(),
            target: "#89".to_string(),
            reviewer: ReviewerConfig {
                mode: ReviewerMode::ExternalCommand,
                program: Some(accepted_program),
                timeout_seconds: None,
                ..ReviewerConfig::default()
            },
            attempt: 1,
            changed_paths: Vec::new(),
            diff_summary: None,
        })?;
        assert_eq!(
            accepted
                .diagnostics
                .and_then(|diagnostics| diagnostics.timeout_seconds),
            Some(REVIEW_DEFAULT_TIMEOUT_SECONDS)
        );

        let unsafe_program = write_reviewer_script(
            temp.path(),
            "reviewer-unsafe-diagnostics",
            &external_echo_command(
                "#90",
                1,
                "[]",
                "pr_target_only",
                "printf 'API_TOKEN=top-secret' >&2;",
            ),
        )?;
        let unsafe_diagnostics = external_review_simulation(ReviewPrOptions {
            repo: temp.path().to_path_buf(),
            target: "#90".to_string(),
            reviewer: ReviewerConfig {
                mode: ReviewerMode::ExternalCommand,
                program: Some(unsafe_program),
                timeout_seconds: Some(30),
                ..ReviewerConfig::default()
            },
            attempt: 1,
            changed_paths: Vec::new(),
            diff_summary: None,
        })?;
        assert_eq!(unsafe_diagnostics.status, ReviewReportStatus::Failed);
        assert!(!unsafe_diagnostics.success);
        let diagnostics = unsafe_diagnostics
            .diagnostics
            .context("failed review diagnostics")?;
        assert_eq!(
            diagnostics.stderr.text,
            "<redacted:unsafe-external-review-diagnostics>"
        );
        assert!(!diagnostics.stderr.text.contains("top-secret"));
        Ok(())
    }

    #[cfg(unix)]
    fn external_echo_command(
        target: &str,
        attempt: usize,
        changed_paths_json: &str,
        diff_source: &str,
        stderr_prefix: &str,
    ) -> String {
        format!(
            r#"input=$(cat); request_binding=$(printf '%s' "$input" | sed -n 's/.*"request_binding":"\([^"]*\)".*/\1/p'); reviewer_id=$(printf '%s' "$input" | sed -n 's/.*"reviewer_id":"\([^"]*\)".*/\1/p'); model=$(printf '%s' "$input" | sed -n 's/.*"model":"\([^"]*\)".*/\1/p'); {stderr_prefix} printf '{{"version":1,"status":"passed","success":true,"target":"{target}","reviewer":{{"mode":"external_command","reviewer_id":"%s","model":"%s"}},"attempt":{attempt},"request_binding":"%s","findings":[],"blocking_finding_count":0,"changed_paths":{changed_paths_json},"diff_source":"{diff_source}","ci_reaction_supported":false,"ci_reaction":"unsupported","next_action":"human review"}}\n' "$reviewer_id" "$model" "$request_binding""#
        )
    }

    #[cfg(unix)]
    fn write_reviewer_script(repo: &Path, name: &str, body: &str) -> Result<PathBuf> {
        use std::os::unix::fs::PermissionsExt;

        let path = repo.join(name);
        std::fs::write(&path, format!("#!/bin/sh\nset -eu\n{body}\n"))?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))?;
        Ok(PathBuf::from(name))
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires exclusive strict-systemd runtime validation"]
    fn strict_external_reviewer_cannot_read_hidden_common_state() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir()?;
        let repository = git2::Repository::init(temp.path())?;
        let state = repository.path().join("maco/state");
        std::fs::create_dir_all(&state)?;
        std::fs::set_permissions(
            repository.path().join("maco"),
            std::fs::Permissions::from_mode(0o700),
        )?;
        std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700))?;
        std::fs::write(state.join("private.key"), "hidden")?;
        let program = write_reviewer_script(
            temp.path(),
            "reviewer-hidden-state",
            "cat .git/maco/state/private.key >/dev/null; exit 99",
        )?;
        let report = external_review(ReviewPrOptions {
            repo: temp.path().to_path_buf(),
            target: "#90".to_string(),
            reviewer: ReviewerConfig {
                mode: ReviewerMode::ExternalCommand,
                program: Some(program),
                timeout_seconds: Some(30),
                ..ReviewerConfig::default()
            },
            attempt: 1,
            changed_paths: Vec::new(),
            diff_summary: None,
        })?;
        assert_eq!(report.status, ReviewReportStatus::Failed);
        Ok(())
    }
}
