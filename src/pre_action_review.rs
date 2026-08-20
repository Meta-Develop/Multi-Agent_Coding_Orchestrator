//! Context-aware policy core for reviewing child actions inside the sandbox ceiling.
//!
//! The outer sandbox remains authoritative. This module can approve only actions
//! already inside that immutable ceiling. Clearly safe and clearly forbidden
//! actions are handled deterministically; only ambiguous actions reach the
//! read-only classifier boundary.

use crate::{
    gate_denial::{ApprovalReviewDenial, GateDenial},
    llm::Redactor,
    sync::normalize_repo_relative_path,
    worktree::normalize_agent_id,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeSet, VecDeque},
    fmt,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
use thiserror::Error;

pub const PRE_ACTION_REVIEW_VERSION: u32 = 1;
pub const DEFAULT_CLASSIFIER_P50_BUDGET_MS: u64 = 50;
pub const DEFAULT_CLASSIFIER_P95_BUDGET_MS: u64 = 200;
pub const DEFAULT_CLASSIFIER_TIMEOUT_MS: u64 = 500;
/// A 100-sample nearest-rank window gives p50 and p95 exact integer ranks 50 and 95.
pub const LATENCY_BUDGET_ENFORCEMENT_MIN_SAMPLES: usize = 100;

const MAX_IDENTIFIER_BYTES: usize = 128;
const MAX_INTENT_BYTES: usize = 8 * 1024;
const MAX_PROGRAM_BYTES: usize = 1024;
const MAX_ARGUMENT_BYTES: usize = 4 * 1024;
const MAX_ARGUMENTS: usize = 128;
const MAX_PATH_BYTES: usize = 4 * 1024;
const MAX_PATH_RULES: usize = 256;
const MAX_PATH_ACCESSES: usize = 256;
const MAX_CLASSIFIER_RESPONSE_BYTES: usize = 16 * 1024;
const MAX_LATENCY_SAMPLES: usize = 4096;

#[derive(Debug, Error)]
pub enum PreActionReviewError {
    #[error("invalid pre-action review data: {0}")]
    Invalid(String),
    #[error("approval denial construction failed: {0}")]
    GateDenial(#[from] crate::gate_denial::GateDenialError),
}

type Result<T> = std::result::Result<T, PreActionReviewError>;

/// Whether a canonical path rule covers one path or a complete subtree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PathCoverage {
    Exact,
    Subtree,
}

/// A bounded canonical repository-relative claim or sensitive-path rule.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RepoPathRule {
    path: PathBuf,
    coverage: PathCoverage,
}

impl RepoPathRule {
    pub fn exact(path: impl AsRef<Path>) -> Result<Self> {
        Self::new(path, PathCoverage::Exact)
    }

    pub fn subtree(path: impl AsRef<Path>) -> Result<Self> {
        Self::new(path, PathCoverage::Subtree)
    }

    pub fn new(path: impl AsRef<Path>, coverage: PathCoverage) -> Result<Self> {
        Ok(Self {
            path: canonical_path(path)?,
            coverage,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn coverage(&self) -> PathCoverage {
        self.coverage
    }

    fn covers(&self, candidate: &Path) -> bool {
        match self.coverage {
            PathCoverage::Exact => candidate == self.path,
            PathCoverage::Subtree => candidate == self.path || candidate.starts_with(&self.path),
        }
    }
}

/// Strict task context supplied by the supervisor, not by the acting child.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewContext {
    run_id: String,
    owner: String,
    intent_summary: String,
    claims: Vec<RepoPathRule>,
    sensitive_paths: Vec<RepoPathRule>,
}

impl ReviewContext {
    pub fn new<I, S>(
        run_id: impl AsRef<str>,
        owner: impl AsRef<str>,
        intent_summary: impl AsRef<str>,
        claims: I,
        sensitive_paths: S,
    ) -> Result<Self>
    where
        I: IntoIterator<Item = RepoPathRule>,
        S: IntoIterator<Item = RepoPathRule>,
    {
        let run_id = canonical_identifier(run_id.as_ref(), "run id")?;
        let owner = normalize_agent_id(owner.as_ref()).map_err(|error| {
            PreActionReviewError::Invalid(format!("review owner is invalid: {error:#}"))
        })?;
        let raw_intent = intent_summary.as_ref();
        validate_bounded_text(raw_intent, "intent summary", MAX_INTENT_BYTES, false)?;
        let intent_summary = Redactor::new().redact(raw_intent).text;
        let claims = canonical_rules(claims, "claim")?;
        if claims.iter().any(|claim| is_control_path(claim.path())) {
            return invalid("claims cannot expand access to hidden control roots");
        }
        let sensitive_paths = canonical_rules(sensitive_paths, "sensitive path")?;
        Ok(Self {
            run_id,
            owner,
            intent_summary,
            claims,
            sensitive_paths,
        })
    }

    pub fn run_id(&self) -> &str {
        &self.run_id
    }

    pub fn owner(&self) -> &str {
        &self.owner
    }

    pub fn intent_summary(&self) -> &str {
        &self.intent_summary
    }

    pub fn claims(&self) -> &[RepoPathRule] {
        &self.claims
    }

    pub fn sensitive_paths(&self) -> &[RepoPathRule] {
        &self.sensitive_paths
    }
}

/// Policy-level command classification supplied by the trusted adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CommandClass {
    ReadOnly,
    Validation,
    WorkspaceMutation,
    DestructiveWorkspace,
    ExternalSideEffect,
    Unknown,
}

/// Declared maximum reach of an action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BlastRadius {
    SingleClaimedPath,
    MultipleClaimedPaths,
    WorkspaceWide,
    OutsideWorkspace,
    External,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PathAccessMode {
    Read,
    Write,
    Delete,
}

/// One canonical path touched by the proposed action.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PathAccess {
    path: PathBuf,
    mode: PathAccessMode,
}

impl PathAccess {
    pub fn new(path: impl AsRef<Path>, mode: PathAccessMode) -> Result<Self> {
        Ok(Self {
            path: canonical_path(path)?,
            mode,
        })
    }

    pub fn read(path: impl AsRef<Path>) -> Result<Self> {
        Self::new(path, PathAccessMode::Read)
    }

    pub fn write(path: impl AsRef<Path>) -> Result<Self> {
        Self::new(path, PathAccessMode::Write)
    }

    pub fn delete(path: impl AsRef<Path>) -> Result<Self> {
        Self::new(path, PathAccessMode::Delete)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn mode(&self) -> PathAccessMode {
        self.mode
    }
}

/// Raw command material is kept private and receives a redacted `Debug` view.
#[derive(Clone, PartialEq, Eq)]
pub struct CommandInvocation {
    program: String,
    arguments: Vec<String>,
}

impl CommandInvocation {
    pub fn new<I, A>(program: impl AsRef<str>, arguments: I) -> Result<Self>
    where
        I: IntoIterator<Item = A>,
        A: AsRef<str>,
    {
        let program = program.as_ref();
        validate_bounded_text(program, "command program", MAX_PROGRAM_BYTES, false)?;
        if !program.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-' | '+' | '/')
        }) {
            return invalid(
                "command program may contain only ASCII letters, digits, '.', '_', '-', '+', and '/'",
            );
        }
        let mut bounded_arguments = Vec::new();
        for argument in arguments {
            if bounded_arguments.len() >= MAX_ARGUMENTS {
                return invalid(format!(
                    "command argument count exceeds the limit of {MAX_ARGUMENTS}"
                ));
            }
            let argument = argument.as_ref();
            validate_bounded_text(argument, "command argument", MAX_ARGUMENT_BYTES, true)?;
            bounded_arguments.push(argument.to_string());
        }
        Ok(Self {
            program: program.to_string(),
            arguments: bounded_arguments,
        })
    }

    pub fn program(&self) -> &str {
        &self.program
    }

    pub fn arguments(&self) -> &[String] {
        &self.arguments
    }

    fn redacted_arguments(&self) -> Vec<String> {
        self.arguments
            .iter()
            .map(|_| "<redacted:argument>".to_string())
            .collect()
    }
}

impl fmt::Debug for CommandInvocation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CommandInvocation")
            .field("program", &self.program)
            .field(
                "arguments",
                &format_args!("<redacted:{} arguments>", self.arguments.len()),
            )
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionKind {
    CommandExecution,
    FileChange,
}

/// Bounded description of an action proposed inside the child workspace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionDescriptor {
    kind: ActionKind,
    command: Option<CommandInvocation>,
    command_class: CommandClass,
    blast_radius: BlastRadius,
    accesses: Vec<PathAccess>,
    access_manifest_complete: bool,
}

impl ActionDescriptor {
    pub fn command<I>(
        command: CommandInvocation,
        command_class: CommandClass,
        blast_radius: BlastRadius,
        accesses: I,
        access_manifest_complete: bool,
    ) -> Result<Self>
    where
        I: IntoIterator<Item = PathAccess>,
    {
        Ok(Self {
            kind: ActionKind::CommandExecution,
            command: Some(command),
            command_class,
            blast_radius,
            accesses: canonical_accesses(accesses)?,
            access_manifest_complete,
        })
    }

    pub fn file_change<I>(accesses: I, destructive: bool) -> Result<Self>
    where
        I: IntoIterator<Item = PathAccess>,
    {
        Self::file_change_with_manifest(accesses, destructive, true)
    }

    /// Describes a file-change request whose path manifest may be incomplete.
    ///
    /// App-server approval requests can omit the full change list. Such requests remain valid
    /// inputs to the fail-closed reviewer, but can never use the deterministic allow path.
    pub fn file_change_with_manifest<I>(
        accesses: I,
        destructive: bool,
        access_manifest_complete: bool,
    ) -> Result<Self>
    where
        I: IntoIterator<Item = PathAccess>,
    {
        let accesses = canonical_accesses(accesses)?;
        if access_manifest_complete && accesses.is_empty() {
            return invalid("file-change action must include at least one path");
        }
        if accesses
            .iter()
            .any(|access| access.mode == PathAccessMode::Read)
        {
            return invalid("file-change action may contain only writes or deletes");
        }
        let blast_radius = match accesses.len() {
            0 => BlastRadius::WorkspaceWide,
            1 => BlastRadius::SingleClaimedPath,
            _ => BlastRadius::MultipleClaimedPaths,
        };
        Ok(Self {
            kind: ActionKind::FileChange,
            command: None,
            command_class: if destructive {
                CommandClass::DestructiveWorkspace
            } else {
                CommandClass::WorkspaceMutation
            },
            blast_radius,
            accesses,
            access_manifest_complete,
        })
    }

    pub fn kind(&self) -> ActionKind {
        self.kind
    }

    pub fn command_class(&self) -> CommandClass {
        self.command_class
    }

    pub fn blast_radius(&self) -> BlastRadius {
        self.blast_radius
    }

    pub fn accesses(&self) -> &[PathAccess] {
        &self.accesses
    }

    pub fn access_manifest_complete(&self) -> bool {
        self.access_manifest_complete
    }
}

/// Requested grants above the child's current sandbox profile.
///
/// All fields default to false. Setting any field asks for an expansion which
/// this reviewer is structurally unable to authorize.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PermissionRequest {
    network_access: bool,
    primary_root_access: bool,
    hidden_root_access: bool,
    outside_workspace_access: bool,
}

impl PermissionRequest {
    pub fn within_ceiling() -> Self {
        Self::default()
    }

    pub fn with_network_access(mut self) -> Self {
        self.network_access = true;
        self
    }

    pub fn with_primary_root_access(mut self) -> Self {
        self.primary_root_access = true;
        self
    }

    pub fn with_hidden_root_access(mut self) -> Self {
        self.hidden_root_access = true;
        self
    }

    pub fn with_outside_workspace_access(mut self) -> Self {
        self.outside_workspace_access = true;
        self
    }

    fn requests_expansion(self) -> bool {
        self.network_access
            || self.primary_root_access
            || self.hidden_root_access
            || self.outside_workspace_access
    }
}

/// Fixed non-expandable sandbox ceiling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct CapabilityCeiling {
    network_access: bool,
    primary_root_access: bool,
    hidden_root_access: bool,
    outside_workspace_access: bool,
}

impl CapabilityCeiling {
    pub fn hardened_child() -> Self {
        Self {
            network_access: false,
            primary_root_access: false,
            hidden_root_access: false,
            outside_workspace_access: false,
        }
    }

    pub fn permits_network_access(self) -> bool {
        self.network_access
    }

    pub fn permits_primary_root_access(self) -> bool {
        self.primary_root_access
    }

    pub fn permits_hidden_root_access(self) -> bool {
        self.hidden_root_access
    }

    pub fn permits_outside_workspace_access(self) -> bool {
        self.outside_workspace_access
    }
}

/// One action-review request with a separate correction lifecycle identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalReviewRequest {
    request_id: String,
    correction_correlation_id: String,
    action: ActionDescriptor,
    permissions: PermissionRequest,
}

impl ApprovalReviewRequest {
    pub fn new(
        request_id: impl AsRef<str>,
        correction_correlation_id: impl AsRef<str>,
        action: ActionDescriptor,
        permissions: PermissionRequest,
    ) -> Result<Self> {
        Ok(Self {
            request_id: canonical_identifier(request_id.as_ref(), "review request id")?,
            correction_correlation_id: canonical_identifier(
                correction_correlation_id.as_ref(),
                "correction correlation id",
            )?,
            action,
            permissions,
        })
    }

    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    pub fn correction_correlation_id(&self) -> &str {
        &self.correction_correlation_id
    }

    pub fn action(&self) -> &ActionDescriptor {
        &self.action
    }

    pub fn permissions(&self) -> PermissionRequest {
        self.permissions
    }
}

/// Request passed to the read-only classifier. Raw command arguments are never
/// included; this structure is also safe to use as a journal request record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RedactedClassifierRequest {
    pub version: u32,
    pub run_id: String,
    pub request_id: String,
    pub owner: String,
    pub intent_summary: String,
    pub claims: Vec<RepoPathRule>,
    pub sensitive_paths: Vec<RepoPathRule>,
    pub action: RedactedClassifierAction,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RedactedClassifierAction {
    pub kind: ActionKind,
    pub program: Option<String>,
    pub arguments: Vec<String>,
    pub command_class: CommandClass,
    pub blast_radius: BlastRadius,
    pub accesses: Vec<PathAccess>,
    pub access_manifest_complete: bool,
}

impl RedactedClassifierRequest {
    fn from_review(context: &ReviewContext, request: &ApprovalReviewRequest) -> Self {
        let command = request.action.command.as_ref();
        Self {
            version: PRE_ACTION_REVIEW_VERSION,
            run_id: context.run_id.clone(),
            request_id: request.request_id.clone(),
            owner: context.owner.clone(),
            intent_summary: context.intent_summary.clone(),
            claims: context.claims.clone(),
            sensitive_paths: context.sensitive_paths.clone(),
            action: RedactedClassifierAction {
                kind: request.action.kind,
                program: command.map(|value| value.program.clone()),
                arguments: match command {
                    Some(command) => command.redacted_arguments(),
                    None => Vec::new(),
                },
                command_class: request.action.command_class,
                blast_radius: request.action.blast_radius,
                accesses: request.action.accesses.clone(),
                access_manifest_complete: request.action.access_manifest_complete,
            },
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClassifierCallFailure {
    Timeout,
    ProtocolError,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassifierCall {
    pub response: std::result::Result<String, ClassifierCallFailure>,
    pub elapsed: Duration,
}

pub trait AmbiguousActionClassifier {
    fn classify(
        &mut self,
        request: &RedactedClassifierRequest,
        timeout: Duration,
    ) -> ClassifierCall;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ClassifierVerdict {
    Allow,
    Deny,
    HumanReview,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ClassifierResponse {
    version: u32,
    verdict: ClassifierVerdict,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionSource {
    DeterministicAllow,
    DeterministicDeny,
    Classifier,
    LatencyBudget,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReviewOutcome {
    Allowed {
        source: DecisionSource,
    },
    Denied {
        source: DecisionSource,
        denial: GateDenial,
    },
    HumanInterventionRequired {
        source: DecisionSource,
        denial: GateDenial,
    },
}

impl ReviewOutcome {
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allowed { .. })
    }

    pub fn denial(&self) -> Option<&GateDenial> {
        match self {
            Self::Allowed { .. } => None,
            Self::Denied { denial, .. } | Self::HumanInterventionRequired { denial, .. } => {
                Some(denial)
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub struct LatencyBudget {
    p50_ms: u64,
    p95_ms: u64,
    timeout_ms: u64,
}

impl LatencyBudget {
    pub fn new(p50_ms: u64, p95_ms: u64, timeout_ms: u64) -> Result<Self> {
        if p50_ms == 0 || p50_ms > p95_ms || p95_ms > timeout_ms {
            return invalid("latency budget must satisfy 0 < p50 <= p95 <= timeout");
        }
        Ok(Self {
            p50_ms,
            p95_ms,
            timeout_ms,
        })
    }

    pub fn interactive_default() -> Self {
        Self {
            p50_ms: DEFAULT_CLASSIFIER_P50_BUDGET_MS,
            p95_ms: DEFAULT_CLASSIFIER_P95_BUDGET_MS,
            timeout_ms: DEFAULT_CLASSIFIER_TIMEOUT_MS,
        }
    }

    pub fn p50_ms(self) -> u64 {
        self.p50_ms
    }

    pub fn p95_ms(self) -> u64 {
        self.p95_ms
    }

    pub fn timeout_ms(self) -> u64 {
        self.timeout_ms
    }

    fn timeout(self) -> Duration {
        Duration::from_millis(self.timeout_ms)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct LatencyReport {
    pub sample_count: u64,
    pub measured_p50_ms: Option<u64>,
    pub measured_p95_ms: Option<u64>,
    pub budget: LatencyBudget,
    pub p50_within_budget: Option<bool>,
    pub p95_within_budget: Option<bool>,
}

#[derive(Debug, Clone)]
struct LatencySeries {
    samples_ms: VecDeque<u64>,
    budget: LatencyBudget,
}

impl LatencySeries {
    fn new(budget: LatencyBudget) -> Self {
        Self {
            samples_ms: VecDeque::new(),
            budget,
        }
    }

    fn observe(&mut self, elapsed: Duration) {
        if self.samples_ms.len() == MAX_LATENCY_SAMPLES {
            self.samples_ms.pop_front();
        }
        self.samples_ms.push_back(duration_millis(elapsed));
    }

    fn observation_ceiling_exceeded(&self, elapsed: Duration) -> bool {
        // Percentiles need the exact 100-sample window below, but production children often end
        // before reaching it and each child receives fresh reviewer state. Treat the p95 budget as
        // the maximum tolerable latency of any individual observation so a short run cannot pass
        // an egregious review delay merely because its distribution is not yet meaningful.
        elapsed > Duration::from_millis(self.budget.p95_ms)
    }

    fn report(&self) -> LatencyReport {
        let mut sorted = self.samples_ms.iter().copied().collect::<Vec<_>>();
        sorted.sort_unstable();
        let measured_p50_ms = percentile(&sorted, 50);
        let measured_p95_ms = percentile(&sorted, 95);
        LatencyReport {
            sample_count: saturating_usize_to_u64(sorted.len()),
            measured_p50_ms,
            measured_p95_ms,
            budget: self.budget,
            p50_within_budget: measured_p50_ms.map(|value| value <= self.budget.p50_ms),
            p95_within_budget: measured_p95_ms.map(|value| value <= self.budget.p95_ms),
        }
    }

    fn budget_exceeded(&self) -> bool {
        if self.samples_ms.len() < LATENCY_BUDGET_ENFORCEMENT_MIN_SAMPLES {
            return false;
        }
        let report = self.report();
        report.p50_within_budget == Some(false) || report.p95_within_budget == Some(false)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub struct RatioMetric {
    pub numerator: u64,
    pub denominator: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct ReviewMetricSnapshot {
    pub reviewed_action_denials: RatioMetric,
    pub eligible_run_human_interruptions: RatioMetric,
    pub classifier_invocations: u64,
    pub review_latency: LatencyReport,
    pub classifier_latency: LatencyReport,
    #[serde(default)]
    pub latency_budget_latched: bool,
}

#[derive(Debug, Clone)]
struct ReviewMetrics {
    reviewed_actions: u64,
    denied_actions: u64,
    eligible_runs: BTreeSet<String>,
    human_interrupted_runs: BTreeSet<String>,
    classifier_invocations: u64,
    review_latency: LatencySeries,
    classifier_latency: LatencySeries,
}

impl ReviewMetrics {
    fn new(budget: LatencyBudget) -> Self {
        Self {
            reviewed_actions: 0,
            denied_actions: 0,
            eligible_runs: BTreeSet::new(),
            human_interrupted_runs: BTreeSet::new(),
            classifier_invocations: 0,
            review_latency: LatencySeries::new(budget),
            classifier_latency: LatencySeries::new(budget),
        }
    }

    fn observe_latency(
        &mut self,
        review_elapsed: Duration,
        classifier_elapsed: Option<Duration>,
    ) -> bool {
        let observation_ceiling_exceeded = self
            .review_latency
            .observation_ceiling_exceeded(review_elapsed)
            || classifier_elapsed.is_some_and(|elapsed| {
                self.classifier_latency
                    .observation_ceiling_exceeded(elapsed)
            });
        self.review_latency.observe(review_elapsed);
        if let Some(elapsed) = classifier_elapsed {
            self.classifier_invocations = self.classifier_invocations.saturating_add(1);
            self.classifier_latency.observe(elapsed);
        }
        observation_ceiling_exceeded
    }

    fn record_outcome(&mut self, run_id: &str, denied: bool, human_interrupted: bool) {
        self.reviewed_actions = self.reviewed_actions.saturating_add(1);
        if denied {
            self.denied_actions = self.denied_actions.saturating_add(1);
        }
        self.eligible_runs.insert(run_id.to_string());
        if human_interrupted {
            self.human_interrupted_runs.insert(run_id.to_string());
        }
    }

    fn latency_budget_exceeded(&self) -> bool {
        self.review_latency.budget_exceeded() || self.classifier_latency.budget_exceeded()
    }

    fn snapshot(&self, latency_budget_latched: bool) -> ReviewMetricSnapshot {
        ReviewMetricSnapshot {
            reviewed_action_denials: RatioMetric {
                numerator: self.denied_actions,
                denominator: self.reviewed_actions,
            },
            eligible_run_human_interruptions: RatioMetric {
                numerator: saturating_usize_to_u64(self.human_interrupted_runs.len()),
                denominator: saturating_usize_to_u64(self.eligible_runs.len()),
            },
            classifier_invocations: self.classifier_invocations,
            review_latency: self.review_latency.report(),
            classifier_latency: self.classifier_latency.report(),
            latency_budget_latched,
        }
    }
}

/// Deterministic policy engine and bounded classifier broker.
#[derive(Debug, Clone)]
pub struct PreActionReviewer {
    ceiling: CapabilityCeiling,
    latency_budget: LatencyBudget,
    metrics: ReviewMetrics,
    latency_budget_latched: bool,
    #[cfg(test)]
    synthetic_review_latencies: VecDeque<Duration>,
    #[cfg(test)]
    synthetic_classifier_latencies: VecDeque<Duration>,
}

impl PreActionReviewer {
    pub fn new(latency_budget: LatencyBudget) -> Self {
        Self {
            ceiling: CapabilityCeiling::hardened_child(),
            latency_budget,
            metrics: ReviewMetrics::new(latency_budget),
            latency_budget_latched: false,
            #[cfg(test)]
            synthetic_review_latencies: VecDeque::new(),
            #[cfg(test)]
            synthetic_classifier_latencies: VecDeque::new(),
        }
    }

    pub fn ceiling(&self) -> CapabilityCeiling {
        self.ceiling
    }

    pub fn metrics(&self) -> ReviewMetricSnapshot {
        self.metrics.snapshot(self.latency_budget_latched)
    }

    #[cfg(test)]
    fn with_synthetic_review_latencies(
        mut self,
        latencies: impl IntoIterator<Item = Duration>,
    ) -> Self {
        self.synthetic_review_latencies = latencies.into_iter().collect();
        self
    }

    #[cfg(test)]
    fn with_synthetic_classifier_latencies(
        mut self,
        latencies: impl IntoIterator<Item = Duration>,
    ) -> Self {
        self.synthetic_classifier_latencies = latencies.into_iter().collect();
        self
    }

    fn measured_review_elapsed(&mut self, started: Instant) -> Duration {
        #[cfg(test)]
        if let Some(elapsed) = self.synthetic_review_latencies.pop_front() {
            return elapsed;
        }
        started.elapsed()
    }

    fn measured_classifier_elapsed(&mut self, started: Instant, reported: Duration) -> Duration {
        #[cfg(test)]
        if let Some(elapsed) = self.synthetic_classifier_latencies.pop_front() {
            return elapsed;
        }
        reported.max(started.elapsed())
    }

    pub fn redacted_classifier_request(
        &self,
        context: &ReviewContext,
        request: &ApprovalReviewRequest,
    ) -> RedactedClassifierRequest {
        RedactedClassifierRequest::from_review(context, request)
    }

    pub fn review(
        &mut self,
        context: &ReviewContext,
        request: &ApprovalReviewRequest,
        classifier: Option<&mut dyn AmbiguousActionClassifier>,
    ) -> Result<ReviewOutcome> {
        if self.latency_budget_latched {
            let denial = GateDenial::from_approval_review(
                &request.correction_correlation_id,
                &context.owner,
                ApprovalReviewDenial::LatencyBudgetExceeded,
                action_paths(&request.action),
            )?;
            self.metrics.record_outcome(&context.run_id, true, false);
            return Ok(ReviewOutcome::Denied {
                source: DecisionSource::LatencyBudget,
                denial,
            });
        }
        let started = Instant::now();
        let fast_path = deterministic_decision(context, request);
        let mut classifier_elapsed = None;
        let (mut source, mut disposition) = match fast_path {
            PolicyDisposition::Allow => {
                (DecisionSource::DeterministicAllow, PolicyDisposition::Allow)
            }
            PolicyDisposition::Deny { denial, paths } => (
                DecisionSource::DeterministicDeny,
                PolicyDisposition::Deny { denial, paths },
            ),
            PolicyDisposition::Human { .. } => {
                return invalid("deterministic policy cannot request human review");
            }
            PolicyDisposition::Ambiguous => {
                let classifier_request = RedactedClassifierRequest::from_review(context, request);
                let classifier_started = Instant::now();
                let mut call = match classifier {
                    Some(classifier) => {
                        classifier.classify(&classifier_request, self.latency_budget.timeout())
                    }
                    None => ClassifierCall {
                        response: Err(ClassifierCallFailure::ProtocolError),
                        elapsed: Duration::ZERO,
                    },
                };
                call.elapsed = self.measured_classifier_elapsed(classifier_started, call.elapsed);
                classifier_elapsed = Some(call.elapsed);
                (
                    DecisionSource::Classifier,
                    classifier_disposition(call, request, self.latency_budget.timeout()),
                )
            }
        };

        let measured = self.measured_review_elapsed(started);
        let review_elapsed = match classifier_elapsed {
            Some(elapsed) => elapsed.max(measured),
            None => measured,
        };
        let observation_ceiling_exceeded = self
            .metrics
            .observe_latency(review_elapsed, classifier_elapsed);
        if observation_ceiling_exceeded || self.metrics.latency_budget_exceeded() {
            self.latency_budget_latched = true;
            if matches!(disposition, PolicyDisposition::Allow) {
                source = DecisionSource::LatencyBudget;
                disposition = PolicyDisposition::Deny {
                    denial: ApprovalReviewDenial::LatencyBudgetExceeded,
                    paths: action_paths(&request.action),
                };
            }
        }
        let (outcome, denied, human_interrupted) = match disposition {
            PolicyDisposition::Allow => (ReviewOutcome::Allowed { source }, false, false),
            PolicyDisposition::Deny { denial, paths } => {
                let denial = GateDenial::from_approval_review(
                    &request.correction_correlation_id,
                    &context.owner,
                    denial,
                    paths,
                )?;
                (ReviewOutcome::Denied { source, denial }, true, false)
            }
            PolicyDisposition::Human { denial, paths } => {
                let denial = GateDenial::from_approval_review(
                    &request.correction_correlation_id,
                    &context.owner,
                    denial,
                    paths,
                )?;
                (
                    ReviewOutcome::HumanInterventionRequired { source, denial },
                    true,
                    true,
                )
            }
            PolicyDisposition::Ambiguous => {
                return invalid("ambiguous review disposition was not resolved");
            }
        };
        self.metrics
            .record_outcome(&context.run_id, denied, human_interrupted);
        Ok(outcome)
    }
}

impl Default for PreActionReviewer {
    fn default() -> Self {
        Self::new(LatencyBudget::interactive_default())
    }
}

#[derive(Debug)]
enum PolicyDisposition {
    Allow,
    Deny {
        denial: ApprovalReviewDenial,
        paths: Vec<PathBuf>,
    },
    Human {
        denial: ApprovalReviewDenial,
        paths: Vec<PathBuf>,
    },
    Ambiguous,
}

fn deterministic_decision(
    context: &ReviewContext,
    request: &ApprovalReviewRequest,
) -> PolicyDisposition {
    let action = &request.action;
    let all_paths = action_paths(action);
    if request.permissions.requests_expansion() {
        return deny(ApprovalReviewDenial::PermissionExpansion, all_paths);
    }
    match action.blast_radius {
        BlastRadius::OutsideWorkspace => {
            return deny(ApprovalReviewDenial::OutsideWorkspace, all_paths);
        }
        BlastRadius::External => {
            return deny(ApprovalReviewDenial::PermissionExpansion, all_paths);
        }
        _ => {}
    }
    if action.kind == ActionKind::CommandExecution && action.command.is_none() {
        return deny(ApprovalReviewDenial::InconsistentRequest, all_paths);
    }
    let mutation_paths = action
        .accesses
        .iter()
        .filter(|access| matches!(access.mode, PathAccessMode::Write | PathAccessMode::Delete))
        .map(|access| access.path.clone())
        .collect::<Vec<_>>();
    if action.command_class == CommandClass::ReadOnly && !mutation_paths.is_empty() {
        return deny(ApprovalReviewDenial::InconsistentRequest, mutation_paths);
    }
    if action.blast_radius == BlastRadius::SingleClaimedPath && mutation_paths.len() > 1 {
        return deny(ApprovalReviewDenial::InconsistentRequest, mutation_paths);
    }
    if action.command_class == CommandClass::DestructiveWorkspace
        || action
            .accesses
            .iter()
            .any(|access| access.mode == PathAccessMode::Delete)
    {
        return deny(
            ApprovalReviewDenial::DestructiveWorkspaceOperation,
            mutation_paths,
        );
    }
    let escaped_claims = action
        .accesses
        .iter()
        .filter(|access| access.mode == PathAccessMode::Write)
        .filter(|access| {
            !context
                .claims
                .iter()
                .any(|claim| claim.covers(&access.path))
        })
        .map(|access| access.path.clone())
        .collect::<Vec<_>>();
    if !escaped_claims.is_empty() {
        return deny(ApprovalReviewDenial::ClaimEscape, escaped_claims);
    }
    let hidden_mutations = action
        .accesses
        .iter()
        .filter(|access| access.mode == PathAccessMode::Write)
        .filter(|access| is_control_path(&access.path))
        .map(|access| access.path.clone())
        .collect::<Vec<_>>();
    if !hidden_mutations.is_empty() {
        return deny(ApprovalReviewDenial::PermissionExpansion, hidden_mutations);
    }
    let sensitive_reads = action
        .accesses
        .iter()
        .filter(|access| access.mode == PathAccessMode::Read)
        .filter(|access| {
            is_intrinsically_sensitive(&access.path)
                || context
                    .sensitive_paths
                    .iter()
                    .any(|rule| rule.covers(&access.path))
        })
        .map(|access| access.path.clone())
        .collect::<Vec<_>>();
    if !sensitive_reads.is_empty() {
        return deny(ApprovalReviewDenial::SensitiveRead, sensitive_reads);
    }
    match action.kind {
        ActionKind::FileChange if action.access_manifest_complete => PolicyDisposition::Allow,
        ActionKind::FileChange => PolicyDisposition::Ambiguous,
        ActionKind::CommandExecution => match action.command_class {
            CommandClass::ReadOnly | CommandClass::Validation
                if action.access_manifest_complete =>
            {
                PolicyDisposition::Allow
            }
            CommandClass::DestructiveWorkspace | CommandClass::ExternalSideEffect => {
                deny(ApprovalReviewDenial::PermissionExpansion, all_paths)
            }
            CommandClass::ReadOnly
            | CommandClass::Validation
            | CommandClass::WorkspaceMutation
            | CommandClass::Unknown => PolicyDisposition::Ambiguous,
        },
    }
}

fn classifier_disposition(
    call: ClassifierCall,
    request: &ApprovalReviewRequest,
    timeout: Duration,
) -> PolicyDisposition {
    let paths = action_paths(&request.action);
    if call.elapsed >= timeout {
        return deny(ApprovalReviewDenial::ClassifierTimeout, paths);
    }
    let response = match call.response {
        Ok(response) => response,
        Err(ClassifierCallFailure::Timeout) => {
            return deny(ApprovalReviewDenial::ClassifierTimeout, paths);
        }
        Err(ClassifierCallFailure::ProtocolError) => {
            return deny(ApprovalReviewDenial::ClassifierProtocolError, paths);
        }
    };
    if response.len() > MAX_CLASSIFIER_RESPONSE_BYTES {
        return deny(ApprovalReviewDenial::ClassifierMalformedResponse, paths);
    }
    let parsed = match serde_json::from_str::<ClassifierResponse>(&response) {
        Ok(parsed) => parsed,
        Err(_) => {
            return deny(ApprovalReviewDenial::ClassifierMalformedResponse, paths);
        }
    };
    if parsed.version != PRE_ACTION_REVIEW_VERSION {
        return deny(ApprovalReviewDenial::ClassifierMalformedResponse, paths);
    }
    match parsed.verdict {
        ClassifierVerdict::Allow => PolicyDisposition::Allow,
        ClassifierVerdict::Deny => deny(ApprovalReviewDenial::ClassifierDenied, paths),
        ClassifierVerdict::HumanReview => PolicyDisposition::Human {
            denial: ApprovalReviewDenial::HumanReviewRequired,
            paths,
        },
    }
}

fn deny(denial: ApprovalReviewDenial, paths: Vec<PathBuf>) -> PolicyDisposition {
    PolicyDisposition::Deny { denial, paths }
}

fn action_paths(action: &ActionDescriptor) -> Vec<PathBuf> {
    action
        .accesses
        .iter()
        .map(|access| access.path.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn canonical_rules<I>(rules: I, field: &str) -> Result<Vec<RepoPathRule>>
where
    I: IntoIterator<Item = RepoPathRule>,
{
    let rules = rules.into_iter().collect::<BTreeSet<_>>();
    if rules.len() > MAX_PATH_RULES {
        return invalid(format!(
            "{field} rule count exceeds the limit of {MAX_PATH_RULES}"
        ));
    }
    Ok(rules.into_iter().collect())
}

fn canonical_accesses<I>(accesses: I) -> Result<Vec<PathAccess>>
where
    I: IntoIterator<Item = PathAccess>,
{
    let accesses = accesses.into_iter().collect::<BTreeSet<_>>();
    if accesses.len() > MAX_PATH_ACCESSES {
        return invalid(format!(
            "path access count exceeds the limit of {MAX_PATH_ACCESSES}"
        ));
    }
    Ok(accesses.into_iter().collect())
}

fn canonical_path(path: impl AsRef<Path>) -> Result<PathBuf> {
    let path = path.as_ref();
    let text = path
        .to_str()
        .ok_or_else(|| PreActionReviewError::Invalid("path is not valid UTF-8".to_string()))?;
    validate_bounded_text(text, "path", MAX_PATH_BYTES, false)?;
    normalize_repo_relative_path(path).map_err(|error| {
        PreActionReviewError::Invalid(format!(
            "path must be canonical repository-relative data: {error:#}"
        ))
    })
}

fn canonical_identifier(value: &str, field: &str) -> Result<String> {
    let value = value.trim();
    if value.is_empty() {
        return invalid(format!("{field} cannot be empty"));
    }
    if value.len() > MAX_IDENTIFIER_BYTES {
        return invalid(format!(
            "{field} exceeds its {MAX_IDENTIFIER_BYTES}-byte limit"
        ));
    }
    if matches!(value, "." | "..")
        || !value.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-')
        })
    {
        return invalid(format!(
            "{field} may contain only ASCII letters, digits, '.', '_' and '-'"
        ));
    }
    Ok(value.to_string())
}

fn validate_bounded_text(
    value: &str,
    field: &str,
    max_bytes: usize,
    permit_line_controls: bool,
) -> Result<()> {
    if value.is_empty() {
        return invalid(format!("{field} cannot be empty"));
    }
    if value.len() > max_bytes {
        return invalid(format!("{field} exceeds its {max_bytes}-byte limit"));
    }
    if value.chars().any(|character| {
        character == '\0'
            || (!permit_line_controls && character.is_control())
            || (permit_line_controls
                && character.is_control()
                && !matches!(character, '\n' | '\r' | '\t'))
    }) {
        return invalid(format!("{field} contains forbidden control characters"));
    }
    Ok(())
}

fn is_control_path(path: &Path) -> bool {
    path.components()
        .next()
        .and_then(|component| component.as_os_str().to_str())
        .is_some_and(|component| matches!(component, ".git" | ".maco" | ".codex"))
}

fn is_intrinsically_sensitive(path: &Path) -> bool {
    if is_control_path(path) {
        return true;
    }
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return true;
    };
    let name = name.to_ascii_lowercase();
    name == ".env"
        || name.starts_with(".env.")
        || matches!(
            name.as_str(),
            ".netrc"
                | "auth.json"
                | "credentials"
                | "credentials.json"
                | "id_rsa"
                | "id_ed25519"
                | "private_key"
                | "secrets"
                | "secrets.json"
        )
        || name.ends_with(".pem")
        || name.ends_with(".key")
}

fn percentile(sorted: &[u64], percentile: usize) -> Option<u64> {
    if sorted.is_empty() {
        return None;
    }
    let rank = sorted.len().saturating_mul(percentile).saturating_add(99) / 100;
    sorted.get(rank.saturating_sub(1)).copied()
}

fn duration_millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

fn saturating_usize_to_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

fn invalid<T>(message: impl Into<String>) -> Result<T> {
    Err(PreActionReviewError::Invalid(message.into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gate_denial::{
        GateDenialReason, GateDenialRoute, GateRetryability, NextSafeOperation,
    };

    #[derive(Debug)]
    struct FakeClassifier {
        calls: usize,
        responses: VecDeque<ClassifierCall>,
        observed: Vec<RedactedClassifierRequest>,
    }

    impl FakeClassifier {
        fn new(responses: impl IntoIterator<Item = ClassifierCall>) -> Self {
            Self {
                calls: 0,
                responses: responses.into_iter().collect(),
                observed: Vec::new(),
            }
        }
    }

    impl AmbiguousActionClassifier for FakeClassifier {
        fn classify(
            &mut self,
            request: &RedactedClassifierRequest,
            _timeout: Duration,
        ) -> ClassifierCall {
            self.calls += 1;
            self.observed.push(request.clone());
            self.responses.pop_front().unwrap_or(ClassifierCall {
                response: Err(ClassifierCallFailure::ProtocolError),
                elapsed: Duration::ZERO,
            })
        }
    }

    #[derive(Debug)]
    struct SlowAllowClassifier;

    impl AmbiguousActionClassifier for SlowAllowClassifier {
        fn classify(
            &mut self,
            _request: &RedactedClassifierRequest,
            _timeout: Duration,
        ) -> ClassifierCall {
            std::thread::sleep(Duration::from_millis(5));
            ClassifierCall {
                response: Ok(r#"{"version":1,"verdict":"allow"}"#.to_string()),
                elapsed: Duration::ZERO,
            }
        }
    }

    fn response(verdict: &str, elapsed_ms: u64) -> ClassifierCall {
        ClassifierCall {
            response: Ok(format!(r#"{{"version":1,"verdict":"{verdict}"}}"#)),
            elapsed: Duration::from_millis(elapsed_ms),
        }
    }

    fn context(run_id: &str) -> ReviewContext {
        ReviewContext::new(
            run_id,
            "worker-a",
            "edit the assigned module",
            [RepoPathRule::subtree("src/review").expect("claim")],
            [RepoPathRule::subtree("private").expect("sensitive path")],
        )
        .expect("review context")
    }

    fn command_request(
        correlation: &str,
        class: CommandClass,
        blast: BlastRadius,
        accesses: Vec<PathAccess>,
        complete: bool,
        arguments: &[&str],
    ) -> ApprovalReviewRequest {
        let command =
            CommandInvocation::new("tool", arguments.iter().copied()).expect("command invocation");
        let action =
            ActionDescriptor::command(command, class, blast, accesses, complete).expect("action");
        ApprovalReviewRequest::new(
            format!("request-{correlation}"),
            correlation,
            action,
            PermissionRequest::within_ceiling(),
        )
        .expect("request")
    }

    fn denial_kind(outcome: &ReviewOutcome) -> ApprovalReviewDenial {
        match &outcome.denial().expect("denial").reason {
            GateDenialReason::ApprovalReview { denial } => *denial,
            other => panic!("unexpected reason: {other:?}"),
        }
    }

    #[test]
    fn context_and_requests_are_strictly_bounded_and_repo_relative() {
        for invalid_path in ["/etc/passwd", "../../escape", "src/\nother"] {
            assert!(RepoPathRule::exact(invalid_path).is_err());
            assert!(PathAccess::read(invalid_path).is_err());
        }
        assert!(ReviewContext::new(
            "run",
            "worker-a",
            "intent",
            [RepoPathRule::subtree(".git").expect("canonical rule")],
            []
        )
        .is_err());
        assert!(
            ReviewContext::new("run", "worker-a", "x".repeat(MAX_INTENT_BYTES + 1), [], [])
                .is_err()
        );
        assert!(CommandInvocation::new("tool", vec!["x"; MAX_ARGUMENTS + 1]).is_err());
    }

    #[test]
    fn clearly_safe_commands_and_file_changes_bypass_classifier() {
        let context = context("run-safe");
        let mut classifier = FakeClassifier::new([]);
        let mut reviewer = PreActionReviewer::default();
        let read = command_request(
            "safe-read",
            CommandClass::ReadOnly,
            BlastRadius::WorkspaceWide,
            vec![PathAccess::read("README.md").expect("read")],
            true,
            &["README.md"],
        );
        assert!(reviewer
            .review(&context, &read, Some(&mut classifier))
            .expect("review")
            .is_allowed());

        let file_action = ActionDescriptor::file_change(
            [PathAccess::write("src/review/policy.rs").expect("write")],
            false,
        )
        .expect("file action");
        let file_request = ApprovalReviewRequest::new(
            "request-file",
            "safe-file",
            file_action,
            PermissionRequest::within_ceiling(),
        )
        .expect("file request");
        assert!(reviewer
            .review(&context, &file_request, Some(&mut classifier))
            .expect("review")
            .is_allowed());
        assert_eq!(classifier.calls, 0);
    }

    #[test]
    fn incomplete_file_manifest_never_receives_a_deterministic_allow() {
        let context = context("run-incomplete-file-manifest");
        let action = ActionDescriptor::file_change_with_manifest(
            [PathAccess::write("src/review/policy.rs").expect("write")],
            false,
            false,
        )
        .expect("incomplete file action");
        let request = ApprovalReviewRequest::new(
            "request-incomplete-file",
            "incomplete-file",
            action,
            PermissionRequest::within_ceiling(),
        )
        .expect("incomplete file request");
        let mut classifier = FakeClassifier::new([response("allow", 1)]);
        let mut reviewer = PreActionReviewer::default();

        let outcome = reviewer
            .review(&context, &request, Some(&mut classifier))
            .expect("classifier-reviewed file request");
        assert_eq!(
            outcome,
            ReviewOutcome::Allowed {
                source: DecisionSource::Classifier
            }
        );
        assert_eq!(classifier.calls, 1);

        let no_manifest = ActionDescriptor::file_change_with_manifest([], false, false)
            .expect("missing file manifest remains reviewable");
        let no_manifest_request = ApprovalReviewRequest::new(
            "request-missing-file",
            "missing-file",
            no_manifest,
            PermissionRequest::within_ceiling(),
        )
        .expect("missing file request");
        let outcome = reviewer
            .review(&context, &no_manifest_request, None)
            .expect("fail-closed missing file review");
        assert_eq!(
            denial_kind(&outcome),
            ApprovalReviewDenial::ClassifierProtocolError
        );
    }

    #[test]
    fn destructive_workspace_operations_claim_escapes_and_sensitive_reads_are_denied() {
        let context = context("run-threats");
        let mut classifier = FakeClassifier::new([response("allow", 1)]);
        let mut reviewer = PreActionReviewer::default();
        let destructive = command_request(
            "destructive",
            CommandClass::DestructiveWorkspace,
            BlastRadius::WorkspaceWide,
            vec![PathAccess::delete("src/review").expect("delete")],
            true,
            &["-rf", "src/review"],
        );
        assert_eq!(
            denial_kind(
                &reviewer
                    .review(&context, &destructive, Some(&mut classifier))
                    .expect("denied review")
            ),
            ApprovalReviewDenial::DestructiveWorkspaceOperation
        );

        let escape = command_request(
            "escape",
            CommandClass::Validation,
            BlastRadius::SingleClaimedPath,
            vec![PathAccess::write("src/lib.rs").expect("write")],
            true,
            &["check"],
        );
        assert_eq!(
            denial_kind(
                &reviewer
                    .review(&context, &escape, Some(&mut classifier))
                    .expect("denied review")
            ),
            ApprovalReviewDenial::ClaimEscape
        );

        for (index, path) in ["private/token.txt", ".env", ".git/config"]
            .into_iter()
            .enumerate()
        {
            let sensitive = command_request(
                &format!("sensitive-{index}"),
                CommandClass::ReadOnly,
                BlastRadius::WorkspaceWide,
                vec![PathAccess::read(path).expect("read")],
                true,
                &["show", path],
            );
            assert_eq!(
                denial_kind(
                    &reviewer
                        .review(&context, &sensitive, Some(&mut classifier))
                        .expect("denied review")
                ),
                ApprovalReviewDenial::SensitiveRead
            );
        }
        assert_eq!(classifier.calls, 0);
    }

    #[test]
    fn permission_expansion_is_never_delegated_to_the_classifier() {
        let context = context("run-ceiling");
        let mut classifier = FakeClassifier::new([response("allow", 1)]);
        let mut reviewer = PreActionReviewer::default();
        let permission_requests = [
            PermissionRequest::within_ceiling().with_network_access(),
            PermissionRequest::within_ceiling().with_primary_root_access(),
            PermissionRequest::within_ceiling().with_hidden_root_access(),
            PermissionRequest::within_ceiling().with_outside_workspace_access(),
        ];
        for (index, permissions) in permission_requests.into_iter().enumerate() {
            let action = ActionDescriptor::command(
                CommandInvocation::new("curl", ["https://example.test"]).expect("command"),
                CommandClass::Unknown,
                BlastRadius::External,
                [],
                false,
            )
            .expect("action");
            let request = ApprovalReviewRequest::new(
                format!("request-expansion-{index}"),
                format!("expansion-{index}"),
                action,
                permissions,
            )
            .expect("request");
            let outcome = reviewer
                .review(&context, &request, Some(&mut classifier))
                .expect("denied review");
            assert_eq!(
                denial_kind(&outcome),
                ApprovalReviewDenial::PermissionExpansion
            );
        }
        assert_eq!(classifier.calls, 0);
        assert!(!reviewer.ceiling().permits_network_access());
        assert!(!reviewer.ceiling().permits_primary_root_access());
        assert!(!reviewer.ceiling().permits_hidden_root_access());
        assert!(!reviewer.ceiling().permits_outside_workspace_access());
    }

    #[test]
    fn only_ambiguous_actions_invoke_classifier_with_redacted_data() {
        let context = ReviewContext::new(
            "run-redaction",
            "worker-a",
            "API_TOKEN=top-secret",
            [RepoPathRule::subtree("src/review").expect("claim")],
            [],
        )
        .expect("context");
        let request = command_request(
            "ambiguous",
            CommandClass::Unknown,
            BlastRadius::SingleClaimedPath,
            vec![PathAccess::write("src/review/policy.rs").expect("write")],
            true,
            &[
                "--token",
                "secret-value",
                "API_KEY=another-secret",
                "Authorization: Bearer bearer-value",
                "https://user:url-token@example.test/?key=query-token",
                "ordinary-looking-value",
            ],
        );
        let mut classifier = FakeClassifier::new([response("allow", 12)]);
        let mut reviewer = PreActionReviewer::default();
        assert!(reviewer
            .review(&context, &request, Some(&mut classifier))
            .expect("review")
            .is_allowed());
        assert_eq!(classifier.calls, 1);
        let serialized =
            serde_json::to_string(&classifier.observed[0]).expect("classifier request JSON");
        assert!(!serialized.contains("top-secret"));
        assert!(!serialized.contains("secret-value"));
        assert!(!serialized.contains("another-secret"));
        assert!(!serialized.contains("bearer-value"));
        assert!(!serialized.contains("url-token"));
        assert!(!serialized.contains("query-token"));
        assert!(!serialized.contains("ordinary-looking-value"));
        assert_eq!(
            classifier.observed[0].action.arguments,
            vec!["<redacted:argument>"; 6]
        );
    }

    #[test]
    fn measured_callback_time_cannot_be_underreported_past_configured_timeout() {
        let context = context("run-measured-timeout");
        let request = command_request(
            "measured-timeout",
            CommandClass::Unknown,
            BlastRadius::WorkspaceWide,
            vec![PathAccess::read("README.md").expect("read")],
            false,
            &["inspect"],
        );
        let mut classifier = SlowAllowClassifier;
        let mut reviewer = PreActionReviewer::new(LatencyBudget::new(1, 1, 1).expect("budget"));
        let outcome = reviewer
            .review(&context, &request, Some(&mut classifier))
            .expect("fail-closed timeout");
        assert_eq!(
            denial_kind(&outcome),
            ApprovalReviewDenial::ClassifierTimeout
        );
        assert!(reviewer
            .metrics()
            .classifier_latency
            .measured_p50_ms
            .is_some_and(|elapsed| elapsed >= 5));
    }

    #[test]
    fn classifier_deny_timeout_malformed_and_protocol_loss_fail_closed() {
        let context = context("run-fail-closed");
        let calls = [
            response("deny", 10),
            ClassifierCall {
                response: Ok(r#"{"version":1,"verdict":"allow","extra":true}"#.to_string()),
                elapsed: Duration::from_millis(5),
            },
            ClassifierCall {
                response: Err(ClassifierCallFailure::ProtocolError),
                elapsed: Duration::from_millis(3),
            },
            ClassifierCall {
                response: Ok(r#"{"version":1,"verdict":"allow"}"#.to_string()),
                elapsed: Duration::from_millis(DEFAULT_CLASSIFIER_TIMEOUT_MS + 1),
            },
        ];
        let expected = [
            ApprovalReviewDenial::ClassifierDenied,
            ApprovalReviewDenial::ClassifierMalformedResponse,
            ApprovalReviewDenial::ClassifierProtocolError,
            ApprovalReviewDenial::ClassifierTimeout,
        ];
        let mut classifier = FakeClassifier::new(calls);
        let mut reviewer = PreActionReviewer::default();
        for (index, expected) in expected.into_iter().enumerate() {
            let request = command_request(
                &format!("failure-{index}"),
                CommandClass::Unknown,
                BlastRadius::WorkspaceWide,
                vec![PathAccess::read("README.md").expect("read")],
                false,
                &["inspect"],
            );
            let outcome = reviewer
                .review(&context, &request, Some(&mut classifier))
                .expect("fail-closed outcome");
            assert_eq!(denial_kind(&outcome), expected);
            assert!(!outcome.is_allowed());
        }
        assert_eq!(classifier.calls, 4);
    }

    #[test]
    fn approval_denial_preserves_stable_identity_and_typed_correction() {
        let context = context("run-denial");
        let first = command_request(
            "correction-a",
            CommandClass::DestructiveWorkspace,
            BlastRadius::WorkspaceWide,
            vec![PathAccess::delete("src/review/policy.rs").expect("delete")],
            true,
            &["delete"],
        );
        let second = ApprovalReviewRequest::new(
            "request-correction-b",
            "correction-b",
            first.action.clone(),
            PermissionRequest::within_ceiling(),
        )
        .expect("second request");
        let mut reviewer = PreActionReviewer::default();
        let first = reviewer
            .review(&context, &first, None)
            .expect("first denial");
        let second = reviewer
            .review(&context, &second, None)
            .expect("second denial");
        let first = first.denial().expect("first gate denial");
        let second = second.denial().expect("second gate denial");
        assert_eq!(first.denial_id, second.denial_id);
        assert_ne!(
            first.correction_correlation_id,
            second.correction_correlation_id
        );
        assert_eq!(first.retryability, GateRetryability::RetryAfterCorrection);
        assert_eq!(first.route, GateDenialRoute::ChildController);
        assert_eq!(
            first.next_safe_operation,
            NextSafeOperation::NarrowActionOrChooseAnotherTool
        );
        let prompt = first.corrective_prompt().expect("corrective prompt");
        assert!(prompt.contains("narrow the proposed action or choose another tool"));
        assert!(!prompt.contains("delete"));
    }

    #[test]
    fn reviewed_action_and_eligible_run_metrics_keep_distinct_denominators() {
        let mut classifier =
            FakeClassifier::new([response("human_review", 10), response("allow", 20)]);
        let mut reviewer = PreActionReviewer::new(LatencyBudget::new(15, 25, 100).expect("budget"));
        let denied = command_request(
            "metric-deny",
            CommandClass::DestructiveWorkspace,
            BlastRadius::WorkspaceWide,
            vec![PathAccess::delete("src/review/a.rs").expect("delete")],
            true,
            &["delete"],
        );
        reviewer
            .review(&context("run-a"), &denied, Some(&mut classifier))
            .expect("denial");

        let human = command_request(
            "metric-human",
            CommandClass::Unknown,
            BlastRadius::WorkspaceWide,
            vec![PathAccess::read("README.md").expect("read")],
            false,
            &["inspect"],
        );
        assert!(matches!(
            reviewer
                .review(&context("run-b"), &human, Some(&mut classifier))
                .expect("human outcome"),
            ReviewOutcome::HumanInterventionRequired { .. }
        ));

        let allowed = command_request(
            "metric-allow",
            CommandClass::Unknown,
            BlastRadius::WorkspaceWide,
            vec![PathAccess::read("README.md").expect("read")],
            false,
            &["inspect"],
        );
        reviewer
            .review(&context("run-c"), &allowed, Some(&mut classifier))
            .expect("allow");
        let safe = command_request(
            "metric-safe",
            CommandClass::ReadOnly,
            BlastRadius::WorkspaceWide,
            vec![PathAccess::read("README.md").expect("read")],
            true,
            &["inspect"],
        );
        reviewer
            .review(&context("run-a"), &safe, Some(&mut classifier))
            .expect("safe allow");

        let metrics = reviewer.metrics();
        assert_eq!(
            metrics.reviewed_action_denials,
            RatioMetric {
                numerator: 2,
                denominator: 4
            }
        );
        assert_eq!(
            metrics.eligible_run_human_interruptions,
            RatioMetric {
                numerator: 1,
                denominator: 3
            }
        );
        assert_eq!(metrics.classifier_invocations, 2);
        assert_eq!(metrics.classifier_latency.sample_count, 2);
        assert_eq!(metrics.classifier_latency.measured_p50_ms, Some(10));
        assert_eq!(metrics.classifier_latency.measured_p95_ms, Some(20));
        assert_eq!(metrics.classifier_latency.p50_within_budget, Some(true));
        assert_eq!(metrics.classifier_latency.p95_within_budget, Some(true));
        assert_eq!(metrics.classifier_latency.budget.p50_ms(), 15);
        assert_eq!(metrics.classifier_latency.budget.p95_ms(), 25);
        assert_eq!(metrics.classifier_latency.budget.timeout_ms(), 100);
    }

    #[test]
    fn short_safe_fast_path_p95_observation_breach_denies_and_latches_immediately() {
        let mut reviewer = PreActionReviewer::new(
            LatencyBudget::new(10, 20, 100).expect("valid deterministic budget"),
        )
        .with_synthetic_review_latencies([Duration::from_millis(21)]);
        let context = context("run-short-safe-ceiling");
        let mut classifier = FakeClassifier::new([]);
        let breach = command_request(
            "short-safe-ceiling",
            CommandClass::ReadOnly,
            BlastRadius::WorkspaceWide,
            vec![PathAccess::read("README.md").expect("read")],
            true,
            &["inspect"],
        );
        let outcome = reviewer
            .review(&context, &breach, Some(&mut classifier))
            .expect("latency refusal");
        assert!(matches!(
            outcome,
            ReviewOutcome::Denied {
                source: DecisionSource::LatencyBudget,
                ..
            }
        ));
        assert_eq!(
            denial_kind(&outcome),
            ApprovalReviewDenial::LatencyBudgetExceeded
        );
        let denial = outcome.denial().expect("typed latency denial");
        assert_eq!(denial.retryability, GateRetryability::NotRetryable);
        assert_eq!(
            denial.next_safe_operation,
            NextSafeOperation::RestorePreActionReviewService
        );
        assert_eq!(classifier.calls, 0, "safe fast path must be exercised");

        let metrics = reviewer.metrics();
        assert_eq!(metrics.review_latency.sample_count, 1);
        assert_eq!(metrics.review_latency.measured_p50_ms, Some(21));
        assert_eq!(metrics.review_latency.measured_p95_ms, Some(21));
        assert_eq!(metrics.review_latency.p50_within_budget, Some(false));
        assert_eq!(metrics.review_latency.p95_within_budget, Some(false));
        assert!(metrics.latency_budget_latched);
        assert_eq!(metrics.reviewed_action_denials.numerator, 1);
        assert_eq!(metrics.reviewed_action_denials.denominator, 1);
    }

    #[test]
    fn safe_fast_path_p50_breach_denies_at_exact_100_sample_rank() {
        let latencies = std::iter::repeat_n(Duration::from_millis(10), 49)
            .chain(std::iter::repeat_n(Duration::from_millis(11), 51));
        let mut reviewer = PreActionReviewer::new(
            LatencyBudget::new(10, 20, 100).expect("valid deterministic budget"),
        )
        .with_synthetic_review_latencies(latencies);
        let context = context("run-safe-percentile");
        let mut classifier = FakeClassifier::new([]);

        for sample in 0..99 {
            let request = command_request(
                &format!("safe-percentile-{sample}"),
                CommandClass::ReadOnly,
                BlastRadius::WorkspaceWide,
                vec![PathAccess::read("README.md").expect("read")],
                true,
                &["inspect"],
            );
            assert_eq!(
                reviewer
                    .review(&context, &request, Some(&mut classifier))
                    .expect("safe fast-path review"),
                ReviewOutcome::Allowed {
                    source: DecisionSource::DeterministicAllow
                }
            );
        }

        let breach = command_request(
            "safe-percentile-99",
            CommandClass::ReadOnly,
            BlastRadius::WorkspaceWide,
            vec![PathAccess::read("README.md").expect("read")],
            true,
            &["inspect"],
        );
        let outcome = reviewer
            .review(&context, &breach, Some(&mut classifier))
            .expect("latency refusal");
        assert!(matches!(
            outcome,
            ReviewOutcome::Denied {
                source: DecisionSource::LatencyBudget,
                ..
            }
        ));
        assert_eq!(
            denial_kind(&outcome),
            ApprovalReviewDenial::LatencyBudgetExceeded
        );
        assert_eq!(classifier.calls, 0, "safe fast path must be exercised");

        let metrics = reviewer.metrics();
        assert_eq!(metrics.review_latency.sample_count, 100);
        assert_eq!(metrics.review_latency.measured_p50_ms, Some(11));
        assert_eq!(metrics.review_latency.measured_p95_ms, Some(11));
        assert_eq!(metrics.review_latency.p50_within_budget, Some(false));
        assert_eq!(metrics.review_latency.p95_within_budget, Some(true));
        assert!(metrics.latency_budget_latched);
        assert_eq!(metrics.reviewed_action_denials.numerator, 1);
        assert_eq!(metrics.reviewed_action_denials.denominator, 100);
    }

    #[test]
    fn forbidden_fast_path_p50_breach_latches_before_the_next_safe_action() {
        let latencies = std::iter::repeat_n(Duration::from_millis(10), 49)
            .chain(std::iter::repeat_n(Duration::from_millis(11), 51));
        let mut reviewer = PreActionReviewer::new(
            LatencyBudget::new(10, 20, 100).expect("valid deterministic budget"),
        )
        .with_synthetic_review_latencies(latencies);
        let context = context("run-forbidden-percentile");
        let mut classifier = FakeClassifier::new([]);

        for sample in 0..100 {
            let forbidden = command_request(
                &format!("forbidden-percentile-{sample}"),
                CommandClass::ReadOnly,
                BlastRadius::WorkspaceWide,
                vec![PathAccess::read("private/token.txt").expect("sensitive read")],
                true,
                &["inspect"],
            );
            let outcome = reviewer
                .review(&context, &forbidden, Some(&mut classifier))
                .expect("forbidden fast-path review");
            assert!(matches!(
                outcome,
                ReviewOutcome::Denied {
                    source: DecisionSource::DeterministicDeny,
                    ..
                }
            ));
            assert_eq!(denial_kind(&outcome), ApprovalReviewDenial::SensitiveRead);
        }

        let safe_after_breach = command_request(
            "safe-after-forbidden-percentile",
            CommandClass::ReadOnly,
            BlastRadius::WorkspaceWide,
            vec![PathAccess::read("README.md").expect("read")],
            true,
            &["inspect"],
        );
        let outcome = reviewer
            .review(&context, &safe_after_breach, Some(&mut classifier))
            .expect("latched refusal");
        assert!(matches!(
            outcome,
            ReviewOutcome::Denied {
                source: DecisionSource::LatencyBudget,
                ..
            }
        ));
        assert_eq!(
            denial_kind(&outcome),
            ApprovalReviewDenial::LatencyBudgetExceeded
        );
        assert_eq!(
            classifier.calls, 0,
            "forbidden fast path and latched refusal must bypass the classifier"
        );

        let metrics = reviewer.metrics();
        assert_eq!(metrics.review_latency.sample_count, 100);
        assert_eq!(metrics.review_latency.measured_p50_ms, Some(11));
        assert_eq!(metrics.review_latency.measured_p95_ms, Some(11));
        assert_eq!(metrics.review_latency.p50_within_budget, Some(false));
        assert_eq!(metrics.review_latency.p95_within_budget, Some(true));
        assert!(metrics.latency_budget_latched);
        assert_eq!(metrics.reviewed_action_denials.numerator, 101);
        assert_eq!(metrics.reviewed_action_denials.denominator, 101);
    }

    #[test]
    fn classifier_p50_breach_is_enforced_when_fast_paths_dilute_overall_percentile() {
        let classifier_latencies = std::iter::repeat_n(Duration::from_millis(10), 49)
            .chain(std::iter::repeat_n(Duration::from_millis(11), 51));
        let mut reviewer = PreActionReviewer::new(
            LatencyBudget::new(10, 20, 100).expect("valid deterministic budget"),
        )
        .with_synthetic_review_latencies(std::iter::repeat_n(Duration::from_millis(1), 2_000))
        .with_synthetic_classifier_latencies(classifier_latencies);
        let context = context("run-classifier-percentile");
        let mut classifier = FakeClassifier::new(std::iter::repeat_n(response("allow", 1), 100));
        let safe = command_request(
            "classifier-dilution-safe",
            CommandClass::ReadOnly,
            BlastRadius::WorkspaceWide,
            vec![PathAccess::read("README.md").expect("read")],
            true,
            &["inspect"],
        );
        for _ in 0..1_900 {
            assert!(reviewer
                .review(&context, &safe, Some(&mut classifier))
                .expect("safe fast path")
                .is_allowed());
        }

        let ambiguous = command_request(
            "classifier-percentile",
            CommandClass::Unknown,
            BlastRadius::WorkspaceWide,
            vec![PathAccess::read("README.md").expect("read")],
            false,
            &["inspect"],
        );
        for _ in 0..99 {
            assert_eq!(
                reviewer
                    .review(&context, &ambiguous, Some(&mut classifier))
                    .expect("classifier review"),
                ReviewOutcome::Allowed {
                    source: DecisionSource::Classifier
                }
            );
        }
        let outcome = reviewer
            .review(&context, &ambiguous, Some(&mut classifier))
            .expect("classifier latency refusal");
        assert!(matches!(
            outcome,
            ReviewOutcome::Denied {
                source: DecisionSource::LatencyBudget,
                ..
            }
        ));
        assert_eq!(
            denial_kind(&outcome),
            ApprovalReviewDenial::LatencyBudgetExceeded
        );
        assert_eq!(classifier.calls, 100);

        let metrics = reviewer.metrics();
        assert_eq!(metrics.review_latency.sample_count, 2_000);
        assert_eq!(metrics.review_latency.measured_p95_ms, Some(1));
        assert_eq!(metrics.review_latency.p95_within_budget, Some(true));
        assert_eq!(metrics.classifier_latency.sample_count, 100);
        assert_eq!(metrics.classifier_latency.measured_p50_ms, Some(11));
        assert_eq!(metrics.classifier_latency.measured_p95_ms, Some(11));
        assert_eq!(metrics.classifier_latency.p50_within_budget, Some(false));
        assert_eq!(metrics.classifier_latency.p95_within_budget, Some(true));
        assert!(metrics.latency_budget_latched);
    }

    #[test]
    fn short_classifier_p95_observation_breach_denies_on_first_callback() {
        let mut reviewer = PreActionReviewer::new(
            LatencyBudget::new(10, 20, 100).expect("valid deterministic budget"),
        )
        .with_synthetic_review_latencies([Duration::from_millis(1)])
        .with_synthetic_classifier_latencies([Duration::from_millis(21)]);
        let context = context("run-short-classifier-ceiling");
        let mut classifier = FakeClassifier::new([response("allow", 1)]);
        let ambiguous = command_request(
            "short-classifier-ceiling",
            CommandClass::Unknown,
            BlastRadius::WorkspaceWide,
            vec![PathAccess::read("README.md").expect("read")],
            false,
            &["inspect"],
        );

        let outcome = reviewer
            .review(&context, &ambiguous, Some(&mut classifier))
            .expect("first-callback latency refusal");
        assert!(matches!(
            outcome,
            ReviewOutcome::Denied {
                source: DecisionSource::LatencyBudget,
                ..
            }
        ));
        assert_eq!(
            denial_kind(&outcome),
            ApprovalReviewDenial::LatencyBudgetExceeded
        );
        assert_eq!(classifier.calls, 1, "classifier path must be exercised");

        let metrics = reviewer.metrics();
        assert_eq!(metrics.review_latency.sample_count, 1);
        assert_eq!(metrics.review_latency.measured_p95_ms, Some(21));
        assert_eq!(metrics.classifier_latency.sample_count, 1);
        assert_eq!(metrics.classifier_latency.measured_p95_ms, Some(21));
        assert!(metrics.latency_budget_latched);
    }

    #[test]
    fn inconsistent_command_metadata_fails_closed_without_classifier() {
        let context = context("run-inconsistent");
        let request = command_request(
            "inconsistent",
            CommandClass::ReadOnly,
            BlastRadius::SingleClaimedPath,
            vec![PathAccess::write("src/review/policy.rs").expect("write")],
            true,
            &["edit"],
        );
        let mut classifier = FakeClassifier::new([response("allow", 1)]);
        let mut reviewer = PreActionReviewer::default();
        let outcome = reviewer
            .review(&context, &request, Some(&mut classifier))
            .expect("denial");
        assert_eq!(
            denial_kind(&outcome),
            ApprovalReviewDenial::InconsistentRequest
        );
        assert_eq!(classifier.calls, 0);
    }
}
