//! Attributed invocation telemetry (issue #159).
//!
//! One append-only record per model call, with complete downstream attribution
//! back to the originating policy execution. Unobservable fields stay `None`
//! and are never fabricated. This module records; it does not select or route.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use super::action::{AgentRole, CanonicalEffort};
use super::error::OptimizerError;
use super::features::{RepoFeatures, TaskFeatures, TrajectoryFeatures};
use super::ids::{
    BackendId, CandidateId, PolicyId, ProviderId, ResourceDimensionId, RuntimeSlug, TimestampMillis,
};
use super::resources::{ObservationKind, Quantity, ResourceObservation, ResourceSnapshot};

macro_rules! telemetry_id {
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

telemetry_id!(/// Cross-run optimizer session that groups policy executions.
    OptimizationRunId);
telemetry_id!(/// One policy-graph execution from intake through certification.
    PolicyExecutionId);
telemetry_id!(/// One model invocation inside a policy execution.
    InvocationId);
telemetry_id!(/// Decision that authorized the root invocation of a cost chain.
    DecisionId);

/// How an invocation's cost is attributed on the originating policy execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CostClass {
    DirectPlanner,
    DirectWorker,
    DirectRepair,
    DirectAuditor,
    DirectCertifier,
    InducedRetry,
    InducedDownstreamRepair,
    InducedHumanIntervention,
}

/// Test oracle snapshot. Missing counts stay `None` rather than zero-filled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct TestCounts {
    pub passed: Option<u32>,
    pub failed: Option<u32>,
}

/// Before/after quota observation for one invocation.
///
/// Weekly pools without exact token accounting use basis points
/// (`10000` = 100%). Inferred observations must not be labelled measured.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuotaWindow {
    pub before_bp: Option<i64>,
    pub after_bp: Option<i64>,
    pub delta_bp: Option<i64>,
    pub measurement_timestamp: TimestampMillis,
    pub observation: ResourceObservation,
}

impl QuotaWindow {
    pub fn measured(
        before_bp: Option<i64>,
        after_bp: Option<i64>,
        measurement_timestamp: TimestampMillis,
        confidence_bp: u16,
    ) -> Self {
        Self {
            before_bp,
            after_bp,
            delta_bp: delta_bp(before_bp, after_bp),
            measurement_timestamp,
            observation: ResourceObservation {
                kind: ObservationKind::Measured,
                confidence_bp,
            },
        }
    }

    pub fn inferred(
        before_bp: Option<i64>,
        after_bp: Option<i64>,
        measurement_timestamp: TimestampMillis,
        confidence_bp: u16,
    ) -> Self {
        Self {
            before_bp,
            after_bp,
            delta_bp: delta_bp(before_bp, after_bp),
            measurement_timestamp,
            observation: ResourceObservation {
                kind: ObservationKind::Inferred,
                confidence_bp,
            },
        }
    }

    pub fn is_measured(&self) -> bool {
        self.observation.kind == ObservationKind::Measured
    }
}

fn delta_bp(before: Option<i64>, after: Option<i64>) -> Option<i64> {
    Some(after? - before?)
}

/// One durable invocation record. New fields are optional so older fixtures
/// remain readable; [`InvocationRecord::validate`] enforces the complete
/// attribution contract for newly written records.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvocationRecord {
    pub policy_id: PolicyId,
    pub candidate_id: CandidateId,
    pub started_at: TimestampMillis,
    pub finished_at: Option<TimestampMillis>,
    pub quota_snapshot: ResourceSnapshot,
    #[serde(default)]
    pub optimization_run_id: Option<OptimizationRunId>,
    #[serde(default)]
    pub policy_execution_id: Option<PolicyExecutionId>,
    #[serde(default)]
    pub invocation_id: Option<InvocationId>,
    #[serde(default)]
    pub parent_invocation_id: Option<InvocationId>,
    #[serde(default)]
    pub root_decision_id: Option<DecisionId>,
    #[serde(default)]
    pub task_class: Option<String>,
    #[serde(default)]
    pub backend: Option<BackendId>,
    #[serde(default)]
    pub provider: Option<ProviderId>,
    #[serde(default)]
    pub requested_model: Option<RuntimeSlug>,
    #[serde(default)]
    pub resolved_model: Option<RuntimeSlug>,
    /// Durable runtime session identity used to distinguish a warm model
    /// transition from a fresh-session transition.
    #[serde(default)]
    pub session_id: Option<String>,
    /// Durable checkout/worktree identity; changing it invalidates runtime-side
    /// state even when backend and model strings are unchanged.
    #[serde(default)]
    pub worktree_id: Option<String>,
    /// Measured adapter startup/session warmup time. Absence is unknown, never
    /// a measured zero.
    #[serde(default)]
    pub runtime_startup_micros: Option<i64>,
    /// Measured value of checkpointed runtime-side state lost on transition.
    /// Absence is unknown, never a measured zero.
    #[serde(default)]
    pub lost_checkpoint_cost_micros: Option<i64>,
    #[serde(default)]
    pub requested_effort: Option<CanonicalEffort>,
    #[serde(default)]
    pub resolved_effort: Option<CanonicalEffort>,
    #[serde(default)]
    pub role: Option<AgentRole>,
    #[serde(default)]
    pub input_tokens: Option<u64>,
    #[serde(default)]
    pub cached_input_tokens: Option<u64>,
    #[serde(default)]
    pub output_tokens: Option<u64>,
    #[serde(default)]
    pub provider_credits: Option<i64>,
    #[serde(default)]
    pub quota_window: Option<QuotaWindow>,
    #[serde(default)]
    pub api_cost_micros: Option<i64>,
    #[serde(default)]
    pub tool_calls: Option<u32>,
    #[serde(default)]
    pub files_read: Option<u32>,
    #[serde(default)]
    pub files_changed: Option<u32>,
    #[serde(default)]
    pub tests_before: Option<TestCounts>,
    #[serde(default)]
    pub tests_after: Option<TestCounts>,
    #[serde(default)]
    pub failure_class: Option<String>,
    #[serde(default)]
    pub certified: Option<bool>,
    #[serde(default)]
    pub cost_class: Option<CostClass>,
    #[serde(default)]
    pub cost_micros: Option<i64>,
    #[serde(default)]
    pub produced_useful_evidence: bool,
    #[serde(default)]
    pub produced_valid_patch: bool,
    #[serde(default)]
    pub human_intervention: bool,
    #[serde(default)]
    pub task_features: Option<TaskFeatures>,
    #[serde(default)]
    pub repo_features: Option<RepoFeatures>,
    #[serde(default)]
    pub trajectory_features: Option<TrajectoryFeatures>,
}

impl InvocationRecord {
    pub fn new(
        policy_id: PolicyId,
        candidate_id: CandidateId,
        started_at: TimestampMillis,
        quota_snapshot: ResourceSnapshot,
    ) -> Self {
        Self {
            policy_id,
            candidate_id,
            started_at,
            finished_at: None,
            quota_snapshot,
            optimization_run_id: None,
            policy_execution_id: None,
            invocation_id: None,
            parent_invocation_id: None,
            root_decision_id: None,
            task_class: None,
            backend: None,
            provider: None,
            requested_model: None,
            resolved_model: None,
            session_id: None,
            worktree_id: None,
            runtime_startup_micros: None,
            lost_checkpoint_cost_micros: None,
            requested_effort: None,
            resolved_effort: None,
            role: None,
            input_tokens: None,
            cached_input_tokens: None,
            output_tokens: None,
            provider_credits: None,
            quota_window: None,
            api_cost_micros: None,
            tool_calls: None,
            files_read: None,
            files_changed: None,
            tests_before: None,
            tests_after: None,
            failure_class: None,
            certified: None,
            cost_class: None,
            cost_micros: None,
            produced_useful_evidence: false,
            produced_valid_patch: false,
            human_intervention: false,
            task_features: None,
            repo_features: None,
            trajectory_features: None,
        }
    }

    /// Complete-attribution contract for newly written records.
    pub fn validate(&self) -> Result<(), OptimizerError> {
        require_present(self.optimization_run_id.is_some(), "optimization_run_id")?;
        require_present(self.policy_execution_id.is_some(), "policy_execution_id")?;
        require_present(self.invocation_id.is_some(), "invocation_id")?;
        require_present(self.root_decision_id.is_some(), "root_decision_id")?;
        require_present(self.requested_model.is_some(), "requested_model")?;
        require_present(self.resolved_model.is_some(), "resolved_model")?;
        require_present(self.requested_effort.is_some(), "requested_effort")?;
        require_present(self.resolved_effort.is_some(), "resolved_effort")?;
        if let Some(finished) = self.finished_at {
            if finished.as_millis() < self.started_at.as_millis() {
                return Err(OptimizerError::invalid("finished_at precedes started_at"));
            }
        }
        if self.runtime_startup_micros.is_some_and(|value| value < 0) {
            return Err(OptimizerError::invalid(
                "runtime_startup_micros must be non-negative",
            ));
        }
        if self
            .lost_checkpoint_cost_micros
            .is_some_and(|value| value < 0)
        {
            return Err(OptimizerError::invalid(
                "lost_checkpoint_cost_micros must be non-negative",
            ));
        }
        Ok(())
    }

    pub fn attaches_feature_hooks(&self) -> bool {
        self.task_features.is_some()
            || self.repo_features.is_some()
            || self.trajectory_features.is_some()
    }
}

fn require_present(present: bool, field: &str) -> Result<(), OptimizerError> {
    if present {
        Ok(())
    } else {
        Err(OptimizerError::invalid(format!(
            "invocation record missing required field {field}"
        )))
    }
}

pub trait TelemetrySink {
    fn record(&self, record: &InvocationRecord) -> Result<(), OptimizerError>;
}

/// Append-only in-memory ledger with optional durable JSONL persistence.
pub struct AttributedTelemetrySink {
    records: Mutex<Vec<InvocationRecord>>,
    durable_path: Option<PathBuf>,
}

impl AttributedTelemetrySink {
    pub fn in_memory() -> Self {
        Self {
            records: Mutex::new(Vec::new()),
            durable_path: None,
        }
    }

    pub fn open_durable(path: impl AsRef<Path>) -> Result<Self, OptimizerError> {
        let path = path.as_ref().to_path_buf();
        let records = load_jsonl(&path)?;
        Ok(Self {
            records: Mutex::new(records),
            durable_path: Some(path),
        })
    }

    pub fn records(&self) -> Result<Vec<InvocationRecord>, OptimizerError> {
        Ok(self.lock()?.clone())
    }

    pub fn records_for_execution(
        &self,
        execution: &PolicyExecutionId,
    ) -> Result<Vec<InvocationRecord>, OptimizerError> {
        Ok(self
            .lock()?
            .iter()
            .filter(|record| record.policy_execution_id.as_ref() == Some(execution))
            .cloned()
            .collect())
    }

    pub fn cost_chain(
        &self,
        execution: &PolicyExecutionId,
    ) -> Result<CostBreakdown, OptimizerError> {
        Ok(CostBreakdown::from_records(
            &self.records_for_execution(execution)?,
        ))
    }

    pub fn policy_totals(
        &self,
        execution: &PolicyExecutionId,
    ) -> Result<PolicyExecutionTotals, OptimizerError> {
        Ok(PolicyExecutionTotals::from_records(
            &self.records_for_execution(execution)?,
        ))
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Vec<InvocationRecord>>, OptimizerError> {
        self.records
            .lock()
            .map_err(|_| OptimizerError::invalid("telemetry lock poisoned"))
    }
}

impl TelemetrySink for AttributedTelemetrySink {
    fn record(&self, record: &InvocationRecord) -> Result<(), OptimizerError> {
        record.validate()?;
        let invocation_id = record
            .invocation_id
            .as_ref()
            .expect("validate requires invocation_id");
        let mut records = self.lock()?;
        if records
            .iter()
            .any(|existing| existing.invocation_id.as_ref() == Some(invocation_id))
        {
            return Err(OptimizerError::invalid(format!(
                "append-only telemetry already contains invocation {invocation_id}"
            )));
        }
        if let Some(path) = &self.durable_path {
            append_jsonl(path, record)?;
        }
        records.push(record.clone());
        Ok(())
    }
}

fn load_jsonl(path: &Path) -> Result<Vec<InvocationRecord>, OptimizerError> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let file = File::open(path).map_err(|error| {
        OptimizerError::invalid(format!("failed to open telemetry log: {error}"))
    })?;
    let mut records = Vec::new();
    for (index, line) in BufReader::new(file).lines().enumerate() {
        let line = line.map_err(|error| {
            OptimizerError::invalid(format!("failed to read telemetry log: {error}"))
        })?;
        if line.trim().is_empty() {
            continue;
        }
        let record: InvocationRecord = serde_json::from_str(&line).map_err(|error| {
            OptimizerError::invalid(format!(
                "telemetry log line {} is not a valid InvocationRecord: {error}",
                index + 1
            ))
        })?;
        records.push(record);
    }
    Ok(records)
}

fn append_jsonl(path: &Path, record: &InvocationRecord) -> Result<(), OptimizerError> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|error| {
                OptimizerError::invalid(format!("failed to create telemetry directory: {error}"))
            })?;
        }
    }
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|error| {
            OptimizerError::invalid(format!("failed to append telemetry log: {error}"))
        })?;
    let line = serde_json::to_string(record).map_err(|error| {
        OptimizerError::invalid(format!("failed to serialize invocation record: {error}"))
    })?;
    writeln!(file, "{line}").map_err(|error| {
        OptimizerError::invalid(format!("failed to write telemetry log: {error}"))
    })?;
    file.flush()
        .map_err(|error| OptimizerError::invalid(format!("failed to flush telemetry log: {error}")))
}

/// Direct versus induced costs for one policy execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct CostBreakdown {
    pub direct_planner_micros: Option<i64>,
    pub direct_worker_micros: Option<i64>,
    pub direct_repair_micros: Option<i64>,
    pub direct_auditor_micros: Option<i64>,
    pub direct_certifier_micros: Option<i64>,
    pub induced_retry_micros: Option<i64>,
    pub induced_downstream_repair_micros: Option<i64>,
    pub induced_human_intervention_micros: Option<i64>,
    pub total_to_certification_micros: Option<i64>,
    pub unobservable_cost_present: bool,
}

impl CostBreakdown {
    pub fn from_records(records: &[InvocationRecord]) -> Self {
        let mut breakdown = Self::default();
        let mut total = 0_i64;
        let mut any_known = false;
        for record in records {
            match record.cost_micros {
                Some(cost) => {
                    any_known = true;
                    total = total.saturating_add(cost);
                    add_cost(&mut breakdown, record.cost_class, cost);
                }
                None => breakdown.unobservable_cost_present = true,
            }
        }
        if any_known {
            breakdown.total_to_certification_micros = Some(total);
        }
        breakdown
    }
}

fn add_cost(breakdown: &mut CostBreakdown, class: Option<CostClass>, cost: i64) {
    let slot = match class {
        Some(CostClass::DirectPlanner) => &mut breakdown.direct_planner_micros,
        Some(CostClass::DirectWorker) => &mut breakdown.direct_worker_micros,
        Some(CostClass::DirectRepair) => &mut breakdown.direct_repair_micros,
        Some(CostClass::DirectAuditor) => &mut breakdown.direct_auditor_micros,
        Some(CostClass::DirectCertifier) => &mut breakdown.direct_certifier_micros,
        Some(CostClass::InducedRetry) => &mut breakdown.induced_retry_micros,
        Some(CostClass::InducedDownstreamRepair) => &mut breakdown.induced_downstream_repair_micros,
        Some(CostClass::InducedHumanIntervention) => {
            &mut breakdown.induced_human_intervention_micros
        }
        None => return,
    };
    *slot = Some(slot.unwrap_or(0).saturating_add(cost));
}

/// Policy-level totals retained per policy execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct PolicyExecutionTotals {
    pub time_to_first_useful_evidence_ms: Option<u64>,
    pub time_to_first_valid_patch_ms: Option<u64>,
    pub time_to_certification_ms: Option<u64>,
    pub per_provider_consumption: BTreeMap<ResourceDimensionId, Quantity>,
    pub total_monetary_cost_micros: Option<i64>,
    pub total_repair_cost_micros: Option<i64>,
    pub total_audit_cost_micros: Option<i64>,
    pub human_intervention: bool,
    pub final_certification_result: Option<bool>,
}

impl PolicyExecutionTotals {
    pub fn from_records(records: &[InvocationRecord]) -> Self {
        let start = records
            .iter()
            .map(|record| record.started_at.as_millis())
            .min();
        let mut totals = Self {
            human_intervention: records.iter().any(|record| record.human_intervention),
            final_certification_result: records.iter().rev().find_map(|record| record.certified),
            ..Self::default()
        };
        if let Some(start) = start {
            totals.time_to_first_useful_evidence_ms =
                first_elapsed(records, start, |record| record.produced_useful_evidence);
            totals.time_to_first_valid_patch_ms =
                first_elapsed(records, start, |record| record.produced_valid_patch);
            totals.time_to_certification_ms =
                first_elapsed(records, start, |record| record.certified == Some(true));
        }
        totals.total_monetary_cost_micros = sum_known(records.iter().map(|r| r.api_cost_micros));
        totals.total_repair_cost_micros =
            sum_known(records.iter().map(|record| match record.cost_class {
                Some(CostClass::DirectRepair | CostClass::InducedDownstreamRepair) => {
                    record.cost_micros
                }
                _ => None,
            }));
        totals.total_audit_cost_micros =
            sum_known(records.iter().map(|record| match record.cost_class {
                Some(CostClass::DirectAuditor) => record.cost_micros,
                _ => None,
            }));

        for record in records {
            if let Some(window) = &record.quota_window {
                if let (Some(provider), Some(delta)) = (&record.provider, window.delta_bp) {
                    let id = ResourceDimensionId::new(format!("quota.{}", provider.as_str()))
                        .unwrap_or_else(|_| {
                            ResourceDimensionId::well_known(ResourceDimensionId::API_COST_USD)
                        });
                    let current = totals
                        .per_provider_consumption
                        .get(&id)
                        .copied()
                        .unwrap_or(Quantity::ZERO);
                    totals
                        .per_provider_consumption
                        .insert(id, current.saturating_add(Quantity::new(delta.abs())));
                }
            }
            for (id, remaining, _reserve, _price) in
                record.quota_snapshot.balances_reserves_and_prices()
            {
                totals
                    .per_provider_consumption
                    .entry(id)
                    .or_insert(remaining);
            }
        }
        totals
    }
}

fn first_elapsed(
    records: &[InvocationRecord],
    start_ms: u64,
    predicate: impl Fn(&InvocationRecord) -> bool,
) -> Option<u64> {
    records
        .iter()
        .filter(|record| predicate(record))
        .map(|record| {
            record
                .finished_at
                .unwrap_or(record.started_at)
                .as_millis()
                .saturating_sub(start_ms)
        })
        .min()
}

fn sum_known<I>(values: I) -> Option<i64>
where
    I: IntoIterator<Item = Option<i64>>,
{
    let mut total = 0_i64;
    let mut any = false;
    for value in values.into_iter().flatten() {
        any = true;
        total = total.saturating_add(value);
    }
    any.then_some(total)
}

/// Feature-bag hook helper so later phases can attach versioned vectors.
pub fn attach_feature_hooks(
    record: &mut InvocationRecord,
    task: TaskFeatures,
    repo: RepoFeatures,
    trajectory: TrajectoryFeatures,
) {
    record.task_features = Some(task);
    record.repo_features = Some(repo);
    record.trajectory_features = Some(trajectory);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::optimizer::ids::{FeatureId, ResourceDimensionId};
    use crate::optimizer::resources::{
        ObservationKind, ResourceDimension, ResourceObservation, ResourceVector,
    };
    use tempfile::TempDir;

    fn snapshot_at(ms: u64) -> ResourceSnapshot {
        let mut vector = ResourceVector::new();
        vector.insert(ResourceDimension {
            id: ResourceDimensionId::well_known(ResourceDimensionId::GROK_BASIS_POINTS),
            remaining: Quantity::new(9_000),
            reset_at: None,
            frontier_reserve: Quantity::new(500),
            emergency_margin: Quantity::new(0),
            uncertainty: Quantity::ZERO,
            shadow_price: 0,
            observation: ResourceObservation {
                kind: ObservationKind::Measured,
                confidence_bp: 10_000,
            },
            chance_epsilon_bp: 1_000,
            target_usage_bp: 5_000,
            learning_rate: 1_000,
        });
        vector.snapshot(TimestampMillis::from_millis(ms))
    }

    fn ids() -> (
        PolicyId,
        CandidateId,
        OptimizationRunId,
        PolicyExecutionId,
        DecisionId,
    ) {
        (
            PolicyId::new("probe-repair").expect("policy"),
            CandidateId::new("cand-1").expect("candidate"),
            OptimizationRunId::new("opt-1").expect("run"),
            PolicyExecutionId::new("policy-run-1").expect("exec"),
            DecisionId::new("decision-1").expect("decision"),
        )
    }

    fn complete_record(invocation: &str, started: u64, finished: u64) -> InvocationRecord {
        let (policy_id, candidate_id, run, execution, decision) = ids();
        let mut record = InvocationRecord::new(
            policy_id,
            candidate_id,
            TimestampMillis::from_millis(started),
            snapshot_at(started),
        );
        record.finished_at = Some(TimestampMillis::from_millis(finished));
        record.optimization_run_id = Some(run);
        record.policy_execution_id = Some(execution);
        record.invocation_id = Some(InvocationId::new(invocation).expect("id"));
        record.root_decision_id = Some(decision);
        record.backend = Some(BackendId::well_known(BackendId::FAKE_PROVIDER));
        record.provider = Some(ProviderId::new("local").expect("provider"));
        record.requested_model = Some(RuntimeSlug::new("requested-slug").expect("req"));
        record.resolved_model = Some(RuntimeSlug::new("resolved-slug").expect("res"));
        record.requested_effort = Some(CanonicalEffort::High);
        record.resolved_effort = Some(CanonicalEffort::High);
        record.task_class = Some("localized_bugfix".to_string());
        record
    }

    #[test]
    fn worker_repair_audit_chain_attributes_to_originating_execution() {
        let sink = AttributedTelemetrySink::in_memory();
        let mut worker = complete_record("call-worker", 1_000, 2_000);
        worker.role = Some(AgentRole::Worker);
        worker.cost_class = Some(CostClass::DirectWorker);
        worker.cost_micros = Some(100);
        worker.produced_useful_evidence = true;
        worker.quota_window = Some(QuotaWindow::measured(
            Some(3_100),
            Some(3_158),
            TimestampMillis::from_millis(2_000),
            10_000,
        ));

        let mut repair = complete_record("call-repair", 2_100, 3_000);
        repair.role = Some(AgentRole::Repairer);
        repair.parent_invocation_id = worker.invocation_id.clone();
        repair.cost_class = Some(CostClass::InducedDownstreamRepair);
        repair.cost_micros = Some(40);
        repair.produced_valid_patch = true;
        repair.quota_window = Some(QuotaWindow::inferred(
            Some(3_158),
            Some(3_200),
            TimestampMillis::from_millis(3_000),
            6_000,
        ));

        let mut audit = complete_record("call-audit", 3_100, 4_000);
        audit.role = Some(AgentRole::Auditor);
        audit.parent_invocation_id = repair.invocation_id.clone();
        audit.cost_class = Some(CostClass::DirectAuditor);
        audit.cost_micros = Some(25);
        audit.certified = Some(true);
        audit.finished_at = Some(TimestampMillis::from_millis(4_000));

        sink.record(&worker).expect("worker");
        sink.record(&repair).expect("repair");
        sink.record(&audit).expect("audit");

        let execution = PolicyExecutionId::new("policy-run-1").expect("exec");
        let chain = sink.records_for_execution(&execution).expect("chain");
        assert_eq!(chain.len(), 3);
        assert!(chain.iter().all(|record| {
            record
                .optimization_run_id
                .as_ref()
                .map(OptimizationRunId::as_str)
                == Some("opt-1")
                && record.root_decision_id.as_ref().map(DecisionId::as_str) == Some("decision-1")
                && record.requested_model.is_some()
                && record.resolved_model.is_some()
                && record.requested_model != record.resolved_model
                && record.requested_effort.is_some()
                && record.resolved_effort.is_some()
        }));
        assert_eq!(
            chain[1]
                .parent_invocation_id
                .as_ref()
                .map(InvocationId::as_str),
            Some("call-worker")
        );
        assert_eq!(
            chain[2]
                .parent_invocation_id
                .as_ref()
                .map(InvocationId::as_str),
            Some("call-repair")
        );

        let costs = sink.cost_chain(&execution).expect("costs");
        assert_eq!(costs.direct_worker_micros, Some(100));
        assert_eq!(costs.induced_downstream_repair_micros, Some(40));
        assert_eq!(costs.direct_auditor_micros, Some(25));
        assert_eq!(costs.total_to_certification_micros, Some(165));
        assert!(!costs.unobservable_cost_present);

        let totals = sink.policy_totals(&execution).expect("totals");
        assert_eq!(totals.time_to_first_useful_evidence_ms, Some(1_000));
        assert_eq!(totals.time_to_first_valid_patch_ms, Some(2_000));
        assert_eq!(totals.time_to_certification_ms, Some(3_000));
        assert_eq!(totals.final_certification_result, Some(true));
        assert_eq!(totals.total_repair_cost_micros, Some(40));
        assert_eq!(totals.total_audit_cost_micros, Some(25));
    }

    #[test]
    fn quota_observations_distinguish_measured_from_inferred() {
        let measured = QuotaWindow::measured(
            Some(3_100),
            Some(3_158),
            TimestampMillis::from_millis(1),
            10_000,
        );
        let inferred =
            QuotaWindow::inferred(Some(3_158), None, TimestampMillis::from_millis(2), 4_000);
        assert!(measured.is_measured());
        assert_eq!(measured.delta_bp, Some(58));
        assert_eq!(measured.observation.kind, ObservationKind::Measured);
        assert!(!inferred.is_measured());
        assert_eq!(inferred.delta_bp, None);
        assert_eq!(inferred.observation.kind, ObservationKind::Inferred);
        assert_eq!(inferred.after_bp, None);
    }

    #[test]
    fn unobservable_fields_are_null_not_fabricated() {
        let record = complete_record("call-sparse", 1, 2);
        assert!(record.input_tokens.is_none());
        assert!(record.cached_input_tokens.is_none());
        assert!(record.output_tokens.is_none());
        assert!(record.provider_credits.is_none());
        assert!(record.api_cost_micros.is_none());
        assert!(record.failure_class.is_none());
        assert!(record.certified.is_none());
        let json = serde_json::to_value(&record).expect("json");
        assert!(json["input_tokens"].is_null());
        assert!(json["api_cost_micros"].is_null());
    }

    #[test]
    fn records_are_durable_append_only_and_round_trip() {
        let dir = TempDir::new().expect("tempdir");
        let path = dir.path().join("telemetry.jsonl");
        let sink = AttributedTelemetrySink::open_durable(&path).expect("open");
        let first = complete_record("call-1", 10, 20);
        sink.record(&first).expect("first");
        let err = sink.record(&first).expect_err("duplicate");
        assert!(err.to_string().contains("append-only"));

        drop(sink);
        let reloaded = AttributedTelemetrySink::open_durable(&path).expect("reload");
        let records = reloaded.records().expect("records");
        assert_eq!(records, vec![first]);
    }

    #[test]
    fn feature_hooks_attach_versioned_vectors() {
        let mut record = complete_record("call-features", 1, 2);
        let mut task = TaskFeatures::new();
        task.insert(
            FeatureId::new("schema.version").expect("id"),
            crate::optimizer::features::FeatureValue::Integer(1),
        );
        attach_feature_hooks(
            &mut record,
            task.clone(),
            RepoFeatures::new(),
            TrajectoryFeatures::new(),
        );
        assert!(record.attaches_feature_hooks());
        assert_eq!(
            record.task_features.as_ref().and_then(|bag| {
                bag.get(&FeatureId::new("schema.version").expect("id"))
                    .cloned()
            }),
            Some(crate::optimizer::features::FeatureValue::Integer(1))
        );
    }

    #[test]
    fn incomplete_records_are_rejected() {
        let sink = AttributedTelemetrySink::in_memory();
        let record = InvocationRecord::new(
            PolicyId::new("p").expect("p"),
            CandidateId::new("c").expect("c"),
            TimestampMillis::from_millis(1),
            snapshot_at(1),
        );
        let error = sink.record(&record).expect_err("incomplete");
        assert!(error.to_string().contains("optimization_run_id"));
    }
}
