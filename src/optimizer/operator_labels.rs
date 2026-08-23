//! Implicit operator-behaviour labels (issue #199).
//!
//! Certification (#161) remains the only authority that can set or clear
//! `certified`. These labels complete an already-terminal #159 record with
//! post-run observations: they are a high-precision *negative-evidence*
//! detector, never a positive-evidence source. An open observation window is
//! censored; absence of a signal is not learned as acceptance.
//!
//! Detection is provenance-by-elimination: MACO knows which hunks it produced.
//! A later change to those hunks that MACO did not produce is human. Commit
//! authorship is never consulted.
//!
//! The first slice attributes one dense implicit outcome row to the originating
//! policy `DecisionId` and persists it append-only. It does not update a
//! predictor, router, or other learner.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use super::certification::CertificationResult;
use super::error::OptimizerError;
use super::failure_classifier::TrajectoryLabel;
use super::ids::{PolicyId, ResourceDimensionId, TimestampMillis};
use super::resources::Quantity;
use super::telemetry::{DecisionId, InvocationRecord, PolicyExecutionId};

/// Current label-schema version. Old records without new fields stay readable.
pub const LABEL_SCHEMA_VERSION: u32 = 1;

/// Default post-run window, in milliseconds (seven days).
pub const DEFAULT_WINDOW_MILLIS: u64 = 7 * 24 * 60 * 60 * 1_000;

/// Distinct resource dimension for human rework cost. The identifier is a
/// static well-known string so construction cannot fail at runtime.
pub fn human_rework_dimension() -> ResourceDimensionId {
    ResourceDimensionId::well_known(ResourceDimensionId::HUMAN_REWORK_COST)
}

macro_rules! label_id {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, OptimizerError> {
                let value = value.into();
                if value.trim().is_empty() || value != value.trim() {
                    return Err(OptimizerError::EmptyIdentifier);
                }
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(&self.0)
            }
        }
    };
}

label_id!(/// Stable identity of one derived operator label.
    OperatorLabelId);

/// Phase-1 signals scale with compute (zero operator attention). Phase-2
/// signals are only meaningful when [`OperatorLabel::attention_observed`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationPhase {
    ZeroAttention,
    AttentionDependent,
}

/// Kind of implicit operator / forge signal.
///
/// This is a high-precision negative-evidence vocabulary. "The operator
/// moved on" is *not* a member — that would treat unobserved attention as
/// acceptance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperatorSignalKind {
    ManualRedispatch,
    OperatorInterrupt,
    OperatorKill,
    PostMergeCiFailure,
    LaterAuditFinding,
    BotReviewRound,
    RevertOfProducedCommits,
    HumanFixupOnProducedPaths,
    HumanReviewRound,
    FollowUpIssue,
    ReopenedIssue,
}

impl OperatorSignalKind {
    pub fn phase(self) -> ObservationPhase {
        match self {
            Self::ManualRedispatch
            | Self::OperatorInterrupt
            | Self::OperatorKill
            | Self::PostMergeCiFailure
            | Self::LaterAuditFinding
            | Self::BotReviewRound
            | Self::RevertOfProducedCommits => ObservationPhase::ZeroAttention,
            Self::HumanFixupOnProducedPaths
            | Self::HumanReviewRound
            | Self::FollowUpIssue
            | Self::ReopenedIssue => ObservationPhase::AttentionDependent,
        }
    }

    pub fn polarity(self) -> SignalPolarity {
        SignalPolarity::Negative
    }
}

/// Labels are negative evidence. Neutral is reserved for censored windows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignalPolarity {
    Negative,
    Censored,
}

/// Where the observation was taken. Local repository and local forge only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LabelSource {
    LocalGitProvenance,
    LocalForge,
    InRunControlPlane,
}

/// One derived post-run label. Completes a #159 record; never rewrites it.
///
/// There is deliberately no `certified` field. The type cannot represent a
/// certification mutation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorLabel {
    pub schema_version: u32,
    pub label_id: OperatorLabelId,
    pub policy_execution_id: PolicyExecutionId,
    #[serde(default)]
    pub root_decision_id: Option<DecisionId>,
    pub observed_at: TimestampMillis,
    pub window_closes_at: TimestampMillis,
    pub kind: OperatorSignalKind,
    pub polarity: SignalPolarity,
    pub attention_observed: bool,
    pub phase: ObservationPhase,
    pub excluded_from_model_stats: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exclusion_reason: Option<String>,
    #[serde(default)]
    pub produced_paths: Vec<String>,
    pub source: LabelSource,
    #[serde(default)]
    pub volume: u32,
}

impl OperatorLabel {
    pub fn validate(&self) -> Result<(), OptimizerError> {
        if self.schema_version == 0 {
            return Err(OptimizerError::invalid(
                "operator label schema_version must be at least 1",
            ));
        }
        if self.phase != self.kind.phase() {
            return Err(OptimizerError::invalid(
                "operator label phase does not match signal kind",
            ));
        }
        if self.polarity != self.kind.polarity() {
            return Err(OptimizerError::invalid(
                "operator labels are negative evidence only",
            ));
        }
        if self.kind.phase() == ObservationPhase::AttentionDependent && !self.attention_observed {
            return Err(OptimizerError::invalid(
                "attention-dependent operator labels require attention_observed",
            ));
        }
        if self.root_decision_id.is_none() {
            return Err(OptimizerError::invalid(
                "operator label must attribute to a root_decision_id",
            ));
        }
        Ok(())
    }
}

/// Copy of the certification bit taken from the certifier, never from a label.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertificationSnapshot {
    certified: bool,
}

impl CertificationSnapshot {
    pub fn from_certification_result(result: &CertificationResult) -> Self {
        Self {
            certified: result.certified,
        }
    }

    pub fn from_recorded_invocation(record: &InvocationRecord) -> Self {
        Self {
            certified: record.certified.unwrap_or(false),
        }
    }

    pub fn from_recorded_bit(certified: bool) -> Self {
        Self { certified }
    }

    pub fn certified(self) -> bool {
        self.certified
    }
}

/// Terminal policy execution these labels complete.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompletedExecution {
    pub policy_execution_id: PolicyExecutionId,
    #[serde(default)]
    pub root_decision_id: Option<DecisionId>,
    pub policy_id: PolicyId,
    pub certification: CertificationSnapshot,
    pub finished_at: TimestampMillis,
    pub window_millis: u64,
    #[serde(default)]
    pub produced_paths: Vec<String>,
    #[serde(default)]
    pub in_run_failure_class: Option<TrajectoryLabel>,
}

impl CompletedExecution {
    pub fn window_closes_at(&self) -> TimestampMillis {
        TimestampMillis::from_millis(
            self.finished_at
                .as_millis()
                .saturating_add(self.window_millis),
        )
    }

    pub fn window_status(&self, now: TimestampMillis) -> WindowStatus {
        if now.as_millis() < self.window_closes_at().as_millis() {
            WindowStatus::OpenCensored
        } else {
            WindowStatus::Closed
        }
    }

    pub fn confounder_excluded(&self) -> bool {
        self.in_run_failure_class.is_some_and(is_non_model_failure)
    }
}

fn is_non_model_failure(label: TrajectoryLabel) -> bool {
    matches!(
        label,
        TrajectoryLabel::OracleFailure
            | TrajectoryLabel::EnvironmentFailure
            | TrajectoryLabel::ProviderFailure
            | TrajectoryLabel::QuotaFailure
    )
}

/// Later path change used for provenance-by-elimination.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PathChange {
    pub path: String,
    /// `true` when MACO itself produced this later change.
    pub produced_by_maco: bool,
}

/// Local-only observation taken after a policy execution ends.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorObservation {
    #[serde(default)]
    pub later_changes: Vec<PathChange>,
    #[serde(default)]
    pub revert_count: u32,
    #[serde(default)]
    pub change_request_rounds: u32,
    #[serde(default)]
    pub review_comment_volume: u32,
    #[serde(default)]
    pub operator_interrupt: bool,
    #[serde(default)]
    pub operator_kill: bool,
    #[serde(default)]
    pub manual_redispatch: bool,
    #[serde(default)]
    pub follow_up_issue: bool,
    #[serde(default)]
    pub reopened_issue: bool,
    #[serde(default)]
    pub post_merge_ci_failure: bool,
    #[serde(default)]
    pub later_audit_finding: bool,
    #[serde(default)]
    pub bot_review_rounds: u32,
    #[serde(default)]
    pub human_review_rounds: u32,
    #[serde(default)]
    pub attention_observed: bool,
}

impl OperatorObservation {
    /// Human fixup: a later change to a MACO-produced path that MACO did not
    /// produce. Authorship is never inspected.
    pub fn human_fixup_by_elimination(&self, produced_paths: &[String]) -> bool {
        self.later_changes.iter().any(|change| {
            !change.produced_by_maco && produced_paths.iter().any(|path| path == &change.path)
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowStatus {
    OpenCensored,
    Closed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReworkSummary {
    pub kinds: Vec<OperatorSignalKind>,
    pub human_fixup: bool,
    pub label_count: u32,
}

/// Learned outcome that distinguishes "certified and accepted" from
/// "certified then reworked" without touching the certification bit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LearnedPolicyOutcome {
    pub policy_execution_id: PolicyExecutionId,
    pub certification: CertificationSnapshot,
    #[serde(default)]
    pub rework: Option<ReworkSummary>,
    pub human_rework_cost: Quantity,
    pub window: WindowStatus,
    pub attention_observed: bool,
    pub included_in_model_stats: bool,
}

impl LearnedPolicyOutcome {
    pub fn treated_as_positive_implicit_signal(&self) -> bool {
        self.window == WindowStatus::Closed
            && self.rework.is_none()
            && self.attention_observed
            && self.included_in_model_stats
    }
}

/// Dense implicit outcome attributed to one policy decision.
///
/// Written even when no negative signal fired. An empty signal list is
/// censored, never implicit acceptance. There is no `certified` field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttributedDecisionLabel {
    pub schema_version: u32,
    pub label_id: OperatorLabelId,
    pub root_decision_id: DecisionId,
    pub policy_execution_id: PolicyExecutionId,
    pub observed_at: TimestampMillis,
    pub window_closes_at: TimestampMillis,
    pub window: WindowStatus,
    pub polarity: SignalPolarity,
    pub attention_observed: bool,
    pub excluded_from_model_stats: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exclusion_reason: Option<String>,
    #[serde(default)]
    pub signal_labels: Vec<OperatorLabel>,
}

impl AttributedDecisionLabel {
    pub fn validate(&self) -> Result<(), OptimizerError> {
        if self.schema_version == 0 {
            return Err(OptimizerError::invalid(
                "attributed decision label schema_version must be at least 1",
            ));
        }
        if self.signal_labels.is_empty() {
            if self.polarity != SignalPolarity::Censored {
                return Err(OptimizerError::invalid(
                    "dense implicit outcome without signals must be censored",
                ));
            }
        } else if self.polarity != SignalPolarity::Negative {
            return Err(OptimizerError::invalid(
                "dense implicit outcome with signals is negative evidence only",
            ));
        }
        for label in &self.signal_labels {
            label.validate()?;
            if label.policy_execution_id != self.policy_execution_id {
                return Err(OptimizerError::invalid(
                    "signal label policy_execution_id does not match attributed decision",
                ));
            }
            match &label.root_decision_id {
                Some(decision) if decision == &self.root_decision_id => {}
                _ => {
                    return Err(OptimizerError::invalid(
                        "signal label must attribute to the same root_decision_id",
                    ));
                }
            }
        }
        Ok(())
    }
}

/// Append-only ledger of derived labels. Original #159 records stay intact.
///
/// Optional JSONL persistence stores dense [`AttributedDecisionLabel`] rows.
/// Reloading reconstructs both those rows and their nested signal labels.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorLabelLedger {
    labels: Vec<OperatorLabel>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    attributed: Vec<AttributedDecisionLabel>,
    #[serde(skip)]
    durable_path: Option<PathBuf>,
}

impl OperatorLabelLedger {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn open_durable(path: impl AsRef<Path>) -> Result<Self, OptimizerError> {
        let path = path.as_ref().to_path_buf();
        let attributed = load_attributed_jsonl(&path)?;
        let mut labels = Vec::new();
        for record in &attributed {
            record.validate()?;
            labels.extend(record.signal_labels.iter().cloned());
        }
        Ok(Self {
            labels,
            attributed,
            durable_path: Some(path),
        })
    }

    pub fn append(&mut self, label: OperatorLabel) -> Result<(), OptimizerError> {
        label.validate()?;
        if self
            .labels
            .iter()
            .any(|existing| existing.label_id == label.label_id)
        {
            return Err(OptimizerError::invalid(format!(
                "append-only operator ledger already contains {}",
                label.label_id
            )));
        }
        self.labels.push(label);
        Ok(())
    }

    pub fn labels(&self) -> &[OperatorLabel] {
        &self.labels
    }

    pub fn attributed(&self) -> &[AttributedDecisionLabel] {
        &self.attributed
    }

    pub fn for_execution(&self, execution: &PolicyExecutionId) -> Vec<&OperatorLabel> {
        self.labels
            .iter()
            .filter(|label| &label.policy_execution_id == execution)
            .collect()
    }

    pub fn for_decision(&self, decision: &DecisionId) -> Vec<&OperatorLabel> {
        self.labels
            .iter()
            .filter(|label| label.root_decision_id.as_ref() == Some(decision))
            .collect()
    }

    pub fn attributed_for_decision(&self, decision: &DecisionId) -> Vec<&AttributedDecisionLabel> {
        self.attributed
            .iter()
            .filter(|record| &record.root_decision_id == decision)
            .collect()
    }

    /// Derive signal labels, attribute one dense outcome to `decision_id`,
    /// and persist that row. Does not update a learner.
    pub fn attribute_and_persist(
        &mut self,
        decision_id: &DecisionId,
        execution: &CompletedExecution,
        observation: &OperatorObservation,
        now: TimestampMillis,
    ) -> Result<AttributedDecisionLabel, OptimizerError> {
        require_matching_decision(decision_id, execution)?;
        let signal_labels = derive_labels(execution, observation, now)?;
        let polarity = if signal_labels.is_empty() {
            SignalPolarity::Censored
        } else {
            SignalPolarity::Negative
        };
        let exclusion_reason = execution
            .in_run_failure_class
            .filter(|label| is_non_model_failure(*label))
            .map(|label| format!("non_model_failure:{label:?}"));
        let record = AttributedDecisionLabel {
            schema_version: LABEL_SCHEMA_VERSION,
            label_id: OperatorLabelId::new(format!(
                "{}:{}:{}",
                decision_id,
                execution.policy_execution_id,
                now.as_millis()
            ))?,
            root_decision_id: decision_id.clone(),
            policy_execution_id: execution.policy_execution_id.clone(),
            observed_at: now,
            window_closes_at: execution.window_closes_at(),
            window: execution.window_status(now),
            polarity,
            attention_observed: observation.attention_observed,
            excluded_from_model_stats: exclusion_reason.is_some(),
            exclusion_reason,
            signal_labels,
        };
        record.validate()?;
        if self
            .attributed
            .iter()
            .any(|existing| existing.label_id == record.label_id)
            || record.signal_labels.iter().any(|label| {
                self.labels
                    .iter()
                    .any(|existing| existing.label_id == label.label_id)
            })
        {
            return Err(OptimizerError::invalid(format!(
                "append-only operator ledger already contains {}",
                record.label_id
            )));
        }
        if let Some(path) = &self.durable_path {
            append_attributed_jsonl(path, &record)?;
        }
        self.labels.extend(record.signal_labels.iter().cloned());
        self.attributed.push(record.clone());
        Ok(record)
    }
}

fn require_matching_decision(
    decision_id: &DecisionId,
    execution: &CompletedExecution,
) -> Result<(), OptimizerError> {
    match &execution.root_decision_id {
        Some(existing) if existing == decision_id => Ok(()),
        Some(existing) => Err(OptimizerError::invalid(format!(
            "cannot attribute labels for decision {decision_id} to execution owned by {existing}"
        ))),
        None => Err(OptimizerError::invalid(
            "cannot attribute labels without a root_decision_id on the completed execution",
        )),
    }
}

fn load_attributed_jsonl(path: &Path) -> Result<Vec<AttributedDecisionLabel>, OptimizerError> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let file = File::open(path).map_err(|error| {
        OptimizerError::invalid(format!("failed to open operator label log: {error}"))
    })?;
    let mut records = Vec::new();
    for (index, line) in BufReader::new(file).lines().enumerate() {
        let line = line.map_err(|error| {
            OptimizerError::invalid(format!("failed to read operator label log: {error}"))
        })?;
        if line.trim().is_empty() {
            continue;
        }
        let record: AttributedDecisionLabel = serde_json::from_str(&line).map_err(|error| {
            OptimizerError::invalid(format!(
                "operator label log line {} is not a valid AttributedDecisionLabel: {error}",
                index + 1
            ))
        })?;
        records.push(record);
    }
    Ok(records)
}

fn append_attributed_jsonl(
    path: &Path,
    record: &AttributedDecisionLabel,
) -> Result<(), OptimizerError> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|error| {
                OptimizerError::invalid(format!(
                    "failed to create operator label directory: {error}"
                ))
            })?;
        }
    }
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|error| {
            OptimizerError::invalid(format!("failed to append operator label log: {error}"))
        })?;
    let line = serde_json::to_string(record).map_err(|error| {
        OptimizerError::invalid(format!(
            "failed to serialize attributed decision label: {error}"
        ))
    })?;
    writeln!(file, "{line}").map_err(|error| {
        OptimizerError::invalid(format!("failed to write operator label log: {error}"))
    })?;
    file.flush().map_err(|error| {
        OptimizerError::invalid(format!("failed to flush operator label log: {error}"))
    })
}

/// Derive labels from a local observation. Phase-2 kinds are dropped when
/// nobody looked. Confounder failures are labelled but excluded from model
/// statistics.
pub fn derive_labels(
    execution: &CompletedExecution,
    observation: &OperatorObservation,
    now: TimestampMillis,
) -> Result<Vec<OperatorLabel>, OptimizerError> {
    let exclusion_reason = execution
        .in_run_failure_class
        .filter(|label| is_non_model_failure(*label))
        .map(|label| format!("non_model_failure:{label:?}"));
    let excluded = exclusion_reason.is_some();
    let window_closes_at = execution.window_closes_at();
    let mut labels = Vec::new();

    let mut push = |kind: OperatorSignalKind,
                    source: LabelSource,
                    volume: u32|
     -> Result<(), OptimizerError> {
        if kind.phase() == ObservationPhase::AttentionDependent && !observation.attention_observed {
            return Ok(());
        }
        let seq = labels.len() + 1;
        let label = OperatorLabel {
            schema_version: LABEL_SCHEMA_VERSION,
            label_id: OperatorLabelId::new(format!(
                "{}:{kind:?}:{seq}",
                execution.policy_execution_id
            ))?,
            policy_execution_id: execution.policy_execution_id.clone(),
            root_decision_id: execution.root_decision_id.clone(),
            observed_at: now,
            window_closes_at,
            kind,
            polarity: kind.polarity(),
            attention_observed: observation.attention_observed,
            phase: kind.phase(),
            excluded_from_model_stats: excluded,
            exclusion_reason: exclusion_reason.clone(),
            produced_paths: execution.produced_paths.clone(),
            source,
            volume,
        };
        label.validate()?;
        labels.push(label);
        Ok(())
    };

    if observation.manual_redispatch {
        push(
            OperatorSignalKind::ManualRedispatch,
            LabelSource::InRunControlPlane,
            1,
        )?;
    }
    if observation.operator_interrupt {
        push(
            OperatorSignalKind::OperatorInterrupt,
            LabelSource::InRunControlPlane,
            1,
        )?;
    }
    if observation.operator_kill {
        push(
            OperatorSignalKind::OperatorKill,
            LabelSource::InRunControlPlane,
            1,
        )?;
    }
    if observation.post_merge_ci_failure {
        push(
            OperatorSignalKind::PostMergeCiFailure,
            LabelSource::LocalForge,
            1,
        )?;
    }
    if observation.later_audit_finding {
        push(
            OperatorSignalKind::LaterAuditFinding,
            LabelSource::LocalForge,
            1,
        )?;
    }
    if observation.bot_review_rounds > 0 {
        push(
            OperatorSignalKind::BotReviewRound,
            LabelSource::LocalForge,
            observation.bot_review_rounds,
        )?;
    }
    if observation.revert_count > 0 {
        push(
            OperatorSignalKind::RevertOfProducedCommits,
            LabelSource::LocalGitProvenance,
            observation.revert_count,
        )?;
    }
    if observation.human_fixup_by_elimination(&execution.produced_paths) {
        push(
            OperatorSignalKind::HumanFixupOnProducedPaths,
            LabelSource::LocalGitProvenance,
            1,
        )?;
    }
    if observation.human_review_rounds > 0 || observation.change_request_rounds > 0 {
        push(
            OperatorSignalKind::HumanReviewRound,
            LabelSource::LocalForge,
            observation
                .human_review_rounds
                .max(observation.change_request_rounds),
        )?;
    }
    if observation.follow_up_issue {
        push(
            OperatorSignalKind::FollowUpIssue,
            LabelSource::LocalForge,
            1,
        )?;
    }
    if observation.reopened_issue {
        push(
            OperatorSignalKind::ReopenedIssue,
            LabelSource::LocalForge,
            1,
        )?;
    }

    Ok(labels)
}

/// Join labels onto a completed execution. The certification snapshot is
/// copied through; labels cannot flip it.
pub fn learn_outcome(
    execution: &CompletedExecution,
    labels: &[OperatorLabel],
    now: TimestampMillis,
) -> LearnedPolicyOutcome {
    let relevant: Vec<&OperatorLabel> = labels
        .iter()
        .filter(|label| label.policy_execution_id == execution.policy_execution_id)
        .collect();
    let window = execution.window_status(now);
    let included = !execution.confounder_excluded()
        && relevant
            .iter()
            .all(|label| !label.excluded_from_model_stats);
    let kinds: Vec<OperatorSignalKind> = relevant.iter().map(|label| label.kind).collect();
    let rework = if kinds.is_empty() {
        None
    } else {
        Some(ReworkSummary {
            human_fixup: kinds.contains(&OperatorSignalKind::HumanFixupOnProducedPaths),
            label_count: u32::try_from(kinds.len()).unwrap_or(u32::MAX),
            kinds,
        })
    };
    let minutes = relevant
        .iter()
        .map(|label| i64::from(label.volume.max(1)))
        .fold(0i64, i64::saturating_add);
    LearnedPolicyOutcome {
        policy_execution_id: execution.policy_execution_id.clone(),
        certification: execution.certification,
        rework,
        human_rework_cost: Quantity::new(minutes.saturating_mul(60_000_000)),
        window,
        attention_observed: relevant.iter().any(|label| label.attention_observed),
        included_in_model_stats: included && window == WindowStatus::Closed,
    }
}

/// Aggregate learned outcomes. Unlabelled / censored rows never increment
/// the implicit-success count.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImplicitOutcomeStats {
    pub closed_observations: u32,
    pub censored_observations: u32,
    pub rework_labels: u32,
    pub implicit_successes: u32,
    pub excluded_confounders: u32,
    pub rework_by_kind: BTreeMap<String, u32>,
}

impl ImplicitOutcomeStats {
    pub fn from_outcomes(outcomes: &[LearnedPolicyOutcome]) -> Self {
        let mut stats = Self::default();
        for outcome in outcomes {
            match outcome.window {
                WindowStatus::OpenCensored => {
                    stats.censored_observations = stats.censored_observations.saturating_add(1);
                }
                WindowStatus::Closed => {
                    stats.closed_observations = stats.closed_observations.saturating_add(1);
                }
            }
            if !outcome.included_in_model_stats
                && outcome.window == WindowStatus::Closed
                && outcome.rework.is_some()
            {
                stats.excluded_confounders = stats.excluded_confounders.saturating_add(1);
            }
            if let Some(rework) = &outcome.rework {
                stats.rework_labels = stats.rework_labels.saturating_add(rework.label_count);
                for kind in &rework.kinds {
                    *stats.rework_by_kind.entry(format!("{kind:?}")).or_insert(0) += 1;
                }
            }
            if outcome.treated_as_positive_implicit_signal() {
                stats.implicit_successes = stats.implicit_successes.saturating_add(1);
            }
        }
        stats
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::optimizer::ids::CandidateId;
    use crate::optimizer::resources::ResourceVector;
    use crate::optimizer::telemetry::InvocationRecord;
    use tempfile::TempDir;

    fn execution(id: &str, certified: bool, finished_at: u64) -> CompletedExecution {
        CompletedExecution {
            policy_execution_id: PolicyExecutionId::new(id).expect("exec"),
            root_decision_id: Some(DecisionId::new(format!("dec-{id}")).expect("dec")),
            policy_id: PolicyId::new("worker-low").expect("policy"),
            certification: CertificationSnapshot::from_recorded_bit(certified),
            finished_at: TimestampMillis::from_millis(finished_at),
            window_millis: DEFAULT_WINDOW_MILLIS,
            produced_paths: vec!["src/optimizer/online_router.rs".to_string()],
            in_run_failure_class: None,
        }
    }

    fn invocation(id: &str, certified: bool) -> InvocationRecord {
        let mut record = InvocationRecord::new(
            PolicyId::new("worker-low").expect("policy"),
            CandidateId::new("cand").expect("cand"),
            TimestampMillis::from_millis(1),
            ResourceVector::new().snapshot(TimestampMillis::from_millis(1)),
        );
        record.policy_execution_id = Some(PolicyExecutionId::new(id).expect("exec"));
        record.certified = Some(certified);
        record
    }

    #[test]
    fn certified_executions_diverge_on_human_fixup() {
        let untouched = execution("ok", true, 1_000);
        let reworked = execution("fixup", true, 1_000);
        let now = TimestampMillis::from_millis(1_000 + DEFAULT_WINDOW_MILLIS);
        let no_change = OperatorObservation {
            attention_observed: true,
            ..OperatorObservation::default()
        };
        let fixup = OperatorObservation {
            attention_observed: true,
            later_changes: vec![PathChange {
                path: "src/optimizer/online_router.rs".to_string(),
                produced_by_maco: false,
            }],
            ..OperatorObservation::default()
        };

        let ok_labels = derive_labels(&untouched, &no_change, now).expect("ok labels");
        let fixup_labels = derive_labels(&reworked, &fixup, now).expect("fixup labels");
        let ok = learn_outcome(&untouched, &ok_labels, now);
        let bad = learn_outcome(&reworked, &fixup_labels, now);

        assert!(ok.certification.certified());
        assert!(bad.certification.certified());
        assert_eq!(ok.rework, None);
        let rework = bad.rework.as_ref().expect("rework label");
        assert!(rework.human_fixup);
        assert!(rework
            .kinds
            .contains(&OperatorSignalKind::HumanFixupOnProducedPaths));
        assert_ne!(ok, bad);
        assert!(bad.human_rework_cost.as_i64() > 0);
        assert_eq!(ok.human_rework_cost.as_i64(), 0);
    }

    #[test]
    fn label_appends_without_rewriting_original_record() {
        let mut original = invocation("exec-1", true);
        let before = original.clone();
        let mut ledger = OperatorLabelLedger::new();
        let exec = execution("exec-1", true, 1_000);
        let now = TimestampMillis::from_millis(2_000);
        let labels = derive_labels(
            &exec,
            &OperatorObservation {
                attention_observed: true,
                later_changes: vec![PathChange {
                    path: "src/optimizer/online_router.rs".to_string(),
                    produced_by_maco: false,
                }],
                ..OperatorObservation::default()
            },
            now,
        )
        .expect("labels");
        for label in labels {
            ledger.append(label).expect("append");
        }
        assert_eq!(original, before);
        original.certified = Some(true);
        assert_eq!(original.certified, before.certified);
        assert_eq!(ledger.for_execution(&exec.policy_execution_id).len(), 1);
        assert!(serde_json::to_string(&ledger.labels()[0])
            .expect("json")
            .contains("human_fixup_on_produced_paths"));
    }

    #[test]
    fn open_window_is_censored_not_positive() {
        let exec = execution("open", true, 1_000);
        let now = TimestampMillis::from_millis(2_000);
        assert_eq!(exec.window_status(now), WindowStatus::OpenCensored);
        let outcome = learn_outcome(&exec, &[], now);
        assert_eq!(outcome.window, WindowStatus::OpenCensored);
        assert!(!outcome.treated_as_positive_implicit_signal());
        assert!(!outcome.included_in_model_stats);
        let stats = ImplicitOutcomeStats::from_outcomes(&[outcome]);
        assert_eq!(stats.censored_observations, 1);
        assert_eq!(stats.implicit_successes, 0);
        assert_eq!(stats.closed_observations, 0);
    }

    #[test]
    fn closed_window_without_attention_is_not_acceptance() {
        let exec = execution("nobody-looked", true, 1_000);
        let now = TimestampMillis::from_millis(1_000 + DEFAULT_WINDOW_MILLIS);
        let outcome = learn_outcome(&exec, &[], now);
        assert_eq!(outcome.window, WindowStatus::Closed);
        assert!(!outcome.attention_observed);
        assert!(!outcome.treated_as_positive_implicit_signal());
        let stats = ImplicitOutcomeStats::from_outcomes(&[outcome]);
        assert_eq!(stats.implicit_successes, 0);
    }

    #[test]
    fn operator_label_cannot_set_or_clear_certified() {
        let exec = execution("auth", true, 1_000);
        let now = TimestampMillis::from_millis(1_000 + DEFAULT_WINDOW_MILLIS);
        let labels = derive_labels(
            &exec,
            &OperatorObservation {
                attention_observed: true,
                later_changes: vec![PathChange {
                    path: "src/optimizer/online_router.rs".to_string(),
                    produced_by_maco: false,
                }],
                operator_kill: true,
                ..OperatorObservation::default()
            },
            now,
        )
        .expect("labels");
        for label in &labels {
            let json = serde_json::to_value(label).expect("json");
            assert!(
                json.get("certified").is_none(),
                "OperatorLabel must not carry a certified field: {json}"
            );
        }
        let outcome = learn_outcome(&exec, &labels, now);
        assert!(outcome.certification.certified());
        assert!(outcome.rework.is_some());

        let uncertified = execution("fail", false, 1_000);
        let still = learn_outcome(&uncertified, &[], now);
        assert!(!still.certification.certified());
    }

    #[test]
    fn non_model_failure_rework_is_excluded_from_model_stats() {
        let mut exec = execution("oracle", true, 1_000);
        exec.in_run_failure_class = Some(TrajectoryLabel::OracleFailure);
        let now = TimestampMillis::from_millis(1_000 + DEFAULT_WINDOW_MILLIS);
        let labels = derive_labels(
            &exec,
            &OperatorObservation {
                attention_observed: true,
                later_changes: vec![PathChange {
                    path: "src/optimizer/online_router.rs".to_string(),
                    produced_by_maco: false,
                }],
                ..OperatorObservation::default()
            },
            now,
        )
        .expect("labels");
        assert!(labels.iter().all(|label| label.excluded_from_model_stats));
        assert!(labels.iter().all(|label| {
            label.exclusion_reason.as_deref() == Some("non_model_failure:OracleFailure")
        }));
        let outcome = learn_outcome(&exec, &labels, now);
        assert!(!outcome.included_in_model_stats);
        assert!(outcome.rework.is_some());
        let stats = ImplicitOutcomeStats::from_outcomes(&[outcome]);
        assert_eq!(stats.excluded_confounders, 1);
        assert_eq!(stats.implicit_successes, 0);
    }

    #[test]
    fn attention_dependent_signals_are_dropped_without_attention() {
        let exec = execution("no-eyes", true, 1_000);
        let now = TimestampMillis::from_millis(2_000);
        let labels = derive_labels(
            &exec,
            &OperatorObservation {
                attention_observed: false,
                later_changes: vec![PathChange {
                    path: "src/optimizer/online_router.rs".to_string(),
                    produced_by_maco: false,
                }],
                follow_up_issue: true,
                manual_redispatch: true,
                ..OperatorObservation::default()
            },
            now,
        )
        .expect("labels");
        assert!(labels
            .iter()
            .any(|label| label.kind == OperatorSignalKind::ManualRedispatch));
        assert!(labels
            .iter()
            .all(|label| label.kind != OperatorSignalKind::HumanFixupOnProducedPaths));
        assert!(labels
            .iter()
            .all(|label| label.kind != OperatorSignalKind::FollowUpIssue));
    }

    #[test]
    fn maco_produced_later_change_is_not_a_human_fixup() {
        let exec = execution("maco-edit", true, 1_000);
        let now = TimestampMillis::from_millis(2_000);
        let labels = derive_labels(
            &exec,
            &OperatorObservation {
                attention_observed: true,
                later_changes: vec![PathChange {
                    path: "src/optimizer/online_router.rs".to_string(),
                    produced_by_maco: true,
                }],
                ..OperatorObservation::default()
            },
            now,
        )
        .expect("labels");
        assert!(labels.is_empty());
    }

    #[test]
    fn duplicate_label_id_fails_closed() {
        let mut ledger = OperatorLabelLedger::new();
        let exec = execution("dup", true, 1_000);
        let now = TimestampMillis::from_millis(2_000);
        let labels = derive_labels(
            &exec,
            &OperatorObservation {
                manual_redispatch: true,
                ..OperatorObservation::default()
            },
            now,
        )
        .expect("labels");
        ledger.append(labels[0].clone()).expect("first");
        let err = ledger.append(labels[0].clone()).expect_err("dup");
        assert!(err.to_string().contains("append-only"));
    }

    #[test]
    fn human_rework_dimension_is_provider_neutral() {
        assert_eq!(human_rework_dimension().as_str(), "human_rework_cost");
    }

    fn fixup_observation() -> OperatorObservation {
        OperatorObservation {
            attention_observed: true,
            later_changes: vec![PathChange {
                path: "src/optimizer/online_router.rs".to_string(),
                produced_by_maco: false,
            }],
            ..OperatorObservation::default()
        }
    }

    #[test]
    fn unattributed_label_fails_validation() {
        let exec = execution("missing-decision", true, 1_000);
        let mut orphan = exec.clone();
        orphan.root_decision_id = None;
        let now = TimestampMillis::from_millis(2_000);
        let err = derive_labels(
            &orphan,
            &OperatorObservation {
                manual_redispatch: true,
                ..OperatorObservation::default()
            },
            now,
        )
        .expect_err("unattributed");
        assert!(err.to_string().contains("root_decision_id"));
    }

    #[test]
    fn attribute_and_persist_binds_decision_and_reloads() {
        let dir = TempDir::new().expect("tempdir");
        let path = dir.path().join("operator-labels.jsonl");
        let mut ledger = OperatorLabelLedger::open_durable(&path).expect("open");
        let exec = execution("persist-1", true, 1_000);
        let decision = exec.root_decision_id.clone().expect("decision");
        let now = TimestampMillis::from_millis(2_000);
        let record = ledger
            .attribute_and_persist(&decision, &exec, &fixup_observation(), now)
            .expect("persist");

        assert_eq!(record.root_decision_id, decision);
        assert_eq!(record.polarity, SignalPolarity::Negative);
        assert_eq!(ledger.for_decision(&decision).len(), 1);
        assert_eq!(ledger.attributed_for_decision(&decision).len(), 1);
        assert!(ledger
            .for_decision(&decision)
            .iter()
            .all(|label| label.root_decision_id.as_ref() == Some(&decision)));

        drop(ledger);
        let reloaded = OperatorLabelLedger::open_durable(&path).expect("reload");
        assert_eq!(reloaded.attributed().len(), 1);
        assert_eq!(
            reloaded.attributed()[0].root_decision_id.as_str(),
            decision.as_str()
        );
        assert_eq!(reloaded.for_decision(&decision).len(), 1);
        let json = serde_json::to_value(&reloaded.attributed()[0]).expect("json");
        assert!(json.get("certified").is_none());
        assert_eq!(json["root_decision_id"], decision.as_str());
    }

    #[test]
    fn dense_outcome_without_signals_is_censored_and_persisted() {
        let dir = TempDir::new().expect("tempdir");
        let path = dir.path().join("operator-labels.jsonl");
        let mut ledger = OperatorLabelLedger::open_durable(&path).expect("open");
        let exec = execution("quiet", true, 1_000);
        let decision = exec.root_decision_id.clone().expect("decision");
        let now = TimestampMillis::from_millis(2_000);
        let record = ledger
            .attribute_and_persist(
                &decision,
                &exec,
                &OperatorObservation {
                    attention_observed: true,
                    ..OperatorObservation::default()
                },
                now,
            )
            .expect("persist");

        assert_eq!(record.polarity, SignalPolarity::Censored);
        assert!(record.signal_labels.is_empty());
        assert_eq!(record.window, WindowStatus::OpenCensored);
        assert_eq!(ledger.for_decision(&decision).len(), 0);
        assert_eq!(ledger.attributed_for_decision(&decision).len(), 1);
        let outcome = learn_outcome(&exec, &[], now);
        assert!(!outcome.treated_as_positive_implicit_signal());
    }

    #[test]
    fn mismatched_or_missing_decision_id_fails_closed() {
        let mut ledger = OperatorLabelLedger::new();
        let exec = execution("mismatch", true, 1_000);
        let now = TimestampMillis::from_millis(2_000);
        let other = DecisionId::new("dec-other").expect("dec");
        let err = ledger
            .attribute_and_persist(&other, &exec, &fixup_observation(), now)
            .expect_err("mismatch");
        assert!(err.to_string().contains("cannot attribute"));

        let mut missing = exec.clone();
        missing.root_decision_id = None;
        let err = ledger
            .attribute_and_persist(
                &DecisionId::new("dec-mismatch").expect("dec"),
                &missing,
                &fixup_observation(),
                now,
            )
            .expect_err("missing");
        assert!(err.to_string().contains("root_decision_id"));
    }

    #[test]
    fn later_label_appends_without_rewriting_persisted_row() {
        let dir = TempDir::new().expect("tempdir");
        let path = dir.path().join("operator-labels.jsonl");
        let mut ledger = OperatorLabelLedger::open_durable(&path).expect("open");
        let exec = execution("append-later", true, 1_000);
        let decision = exec.root_decision_id.clone().expect("decision");
        let first = ledger
            .attribute_and_persist(
                &decision,
                &exec,
                &OperatorObservation {
                    attention_observed: true,
                    ..OperatorObservation::default()
                },
                TimestampMillis::from_millis(2_000),
            )
            .expect("first");
        let second = ledger
            .attribute_and_persist(
                &decision,
                &exec,
                &fixup_observation(),
                TimestampMillis::from_millis(3_000),
            )
            .expect("second");

        assert_ne!(first.label_id, second.label_id);
        assert_eq!(first.polarity, SignalPolarity::Censored);
        assert_eq!(second.polarity, SignalPolarity::Negative);
        assert_eq!(ledger.attributed_for_decision(&decision).len(), 2);

        let persisted = std::fs::read_to_string(&path).expect("read");
        assert_eq!(persisted.lines().count(), 2);
        assert!(persisted
            .lines()
            .next()
            .expect("first line")
            .contains("censored"));
        drop(ledger);
        let reloaded = OperatorLabelLedger::open_durable(&path).expect("reload");
        assert_eq!(reloaded.attributed().len(), 2);
        assert_eq!(reloaded.attributed()[0], first);
        assert_eq!(reloaded.attributed()[1], second);
    }

    #[test]
    fn certified_pair_persists_distinct_decision_outcomes() {
        let dir = TempDir::new().expect("tempdir");
        let path = dir.path().join("operator-labels.jsonl");
        let mut ledger = OperatorLabelLedger::open_durable(&path).expect("open");
        let untouched = execution("ok", true, 1_000);
        let reworked = execution("fixup", true, 1_000);
        let now = TimestampMillis::from_millis(1_000 + DEFAULT_WINDOW_MILLIS);
        let ok_decision = untouched.root_decision_id.clone().expect("ok dec");
        let bad_decision = reworked.root_decision_id.clone().expect("bad dec");

        let ok = ledger
            .attribute_and_persist(
                &ok_decision,
                &untouched,
                &OperatorObservation {
                    attention_observed: true,
                    ..OperatorObservation::default()
                },
                now,
            )
            .expect("ok");
        let bad = ledger
            .attribute_and_persist(&bad_decision, &reworked, &fixup_observation(), now)
            .expect("bad");

        assert_ne!(ok, bad);
        assert_eq!(ok.polarity, SignalPolarity::Censored);
        assert_eq!(bad.polarity, SignalPolarity::Negative);
        assert!(bad.signal_labels.iter().any(|label| {
            label.kind == OperatorSignalKind::HumanFixupOnProducedPaths
                && label.root_decision_id.as_ref() == Some(&bad_decision)
        }));
        assert!(ok.signal_labels.is_empty());
        assert_eq!(ledger.attributed_for_decision(&ok_decision).len(), 1);
        assert_eq!(ledger.for_decision(&bad_decision).len(), 1);
    }
}
