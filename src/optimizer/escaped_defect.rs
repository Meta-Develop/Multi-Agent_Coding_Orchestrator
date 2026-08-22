//! Escaped-defect measurement and quality-contract completeness (issue #210).
//!
//! Certification is satisfaction of the *declared* contract. This module
//! measures the gap between "certified" and "correct" and proposes
//! append-only contract amendments. Nothing here can mark a candidate
//! certified.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::convert::Infallible;

use super::digest::sha256_hex;
use super::error::OptimizerError;
use super::evidence_pool::{ClosedToken, ContentHash, TaxonomyCell};
use super::failure_classifier::TrajectoryLabel;
use super::ids::{ContractId, PolicyId, RequirementId, TimestampMillis, ValidatorId};
use super::quality::{QualityContract, ValidatorBinding};
use super::telemetry::PolicyExecutionId;

/// Why the declared contract failed to catch a later defect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MissingConditionClass {
    ValidatorAbsent,
    ValidatorTooWeak,
    RequirementNeverTraced,
    ScopeConstraintMissing,
    OracleWrong,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EscapeSource {
    PostRunSignal,
    PostMergeCiFailure,
    LaterAudit,
    GateFinding,
    RegressionBreakage,
    FollowUpIssue { requirement_id: RequirementId },
    HumanEditToMacoHunk,
    SamplingReaudit,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DefectId(String);

impl DefectId {
    pub fn new(value: impl Into<String>) -> Result<Self, OptimizerError> {
        ClosedToken::new(value).map(|token| Self(token.as_str().to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Primary output is about the *contract*, not the model.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EscapedDefectRecord {
    pub defect_id: DefectId,
    pub policy_execution_id: PolicyExecutionId,
    pub contract_id: ContractId,
    pub contract_version: ContentHash,
    pub cell: TaxonomyCell,
    pub certified_at: TimestampMillis,
    pub discovered_at: TimestampMillis,
    pub source: EscapeSource,
    pub attribution: MissingConditionClass,
    pub would_have_caught: String,
    pub why_it_did_not: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secondary_policy_id: Option<PolicyId>,
}

impl EscapedDefectRecord {
    pub fn time_to_discovery_ms(&self) -> Option<u64> {
        self.discovered_at
            .as_millis()
            .checked_sub(self.certified_at.as_millis())
    }
}

pub fn contract_version(contract: &QualityContract) -> Result<ContentHash, OptimizerError> {
    let encoded = serde_json::to_vec(contract).map_err(|error| {
        OptimizerError::invalid(format!("failed to fingerprint quality contract: {error}"))
    })?;
    Ok(ContentHash::from_hex(sha256_hex(&encoded))?)
}

/// Append-only amendment. There is no remove or weaken method.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractAmendment {
    pub from_defect: DefectId,
    pub added_validator: ValidatorBinding,
}

impl ContractAmendment {
    pub fn from_defect(
        defect: &EscapedDefectRecord,
        validator: ValidatorBinding,
    ) -> Result<Self, OptimizerError> {
        if validator.validator_id.as_str().is_empty() {
            return Err(OptimizerError::invalid(
                "amendment validator id must be non-empty",
            ));
        }
        Ok(Self {
            from_defect: defect.defect_id.clone(),
            added_validator: validator,
        })
    }

    pub fn apply(&self, contract: &QualityContract) -> QualityContract {
        contract.with_additional_validator(self.added_validator.clone())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CensoredDiscovery {
    pub observed_ms: Option<u64>,
    pub censored: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConditionFireRecord {
    pub validator_id: ValidatorId,
    pub fired: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompletenessMetrics {
    pub cell_task_class: String,
    pub contract_version: ContentHash,
    pub certified_executions: u32,
    pub escaped_defects: u32,
    pub escaped_defect_rate_bp: u16,
    pub time_to_discovery: Vec<CensoredDiscovery>,
    pub share_per_class_bp: BTreeMap<MissingConditionClass, u16>,
    pub contract_coverage: Vec<ConditionFireRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertifiedExecution {
    pub policy_execution_id: PolicyExecutionId,
    pub contract_id: ContractId,
    pub contract_version: ContentHash,
    pub cell: TaxonomyCell,
    pub certified_at: TimestampMillis,
    pub policy_id: PolicyId,
    pub cheap: bool,
}

#[derive(Debug, Clone, Default)]
pub struct EscapedDefectLedger {
    certified: Vec<CertifiedExecution>,
    escapes: Vec<EscapedDefectRecord>,
    fired_validators: BTreeMap<String, BTreeSet<String>>,
}

impl EscapedDefectLedger {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_certified(&mut self, execution: CertifiedExecution) {
        self.certified.push(execution);
    }

    pub fn record_validator_fired(
        &mut self,
        contract_version: &ContentHash,
        validator: &ValidatorId,
    ) {
        self.fired_validators
            .entry(contract_version.as_str().to_string())
            .or_default()
            .insert(validator.as_str().to_string());
    }

    /// Record an escaped defect. Non-model failure classes are not escapes.
    pub fn record_escape(
        &mut self,
        record: EscapedDefectRecord,
        failure_class: Option<TrajectoryLabel>,
    ) -> Result<(), OptimizerError> {
        if matches!(
            failure_class,
            Some(
                TrajectoryLabel::OracleFailure
                    | TrajectoryLabel::EnvironmentFailure
                    | TrajectoryLabel::ProviderFailure
                    | TrajectoryLabel::QuotaFailure
            )
        ) {
            return Err(OptimizerError::invalid(
                "non-model failure classes are not escaped defects",
            ));
        }
        if !self.certified.iter().any(|execution| {
            execution.policy_execution_id == record.policy_execution_id
                && execution.contract_version == record.contract_version
        }) {
            return Err(OptimizerError::invalid(
                "escaped defect must bind a previously certified execution and contract version",
            ));
        }
        self.escapes.push(record);
        Ok(())
    }

    pub fn metrics(
        &self,
        cell: &TaxonomyCell,
        contract_version: &ContentHash,
        declared_validators: &[ValidatorId],
        now: TimestampMillis,
    ) -> CompletenessMetrics {
        metrics_from_snapshot(
            &self.certified,
            &self.escapes,
            &self.fired_validators,
            cell,
            contract_version,
            declared_validators,
            now,
        )
    }

    pub fn propose_amendment(
        &self,
        defect_id: &DefectId,
        validator: ValidatorBinding,
    ) -> Result<ContractAmendment, OptimizerError> {
        let defect = self
            .escapes
            .iter()
            .find(|record| &record.defect_id == defect_id)
            .ok_or_else(|| OptimizerError::invalid("unknown escaped defect"))?;
        ContractAmendment::from_defect(defect, validator)
    }
}

/// Pure function of a ledger snapshot. Replayable.
pub fn metrics_from_snapshot(
    certified: &[CertifiedExecution],
    escapes: &[EscapedDefectRecord],
    fired_validators: &BTreeMap<String, BTreeSet<String>>,
    cell: &TaxonomyCell,
    contract_version: &ContentHash,
    declared_validators: &[ValidatorId],
    now: TimestampMillis,
) -> CompletenessMetrics {
    let certified_executions = certified
        .iter()
        .filter(|execution| {
            execution.cell.task_class == cell.task_class
                && execution.contract_version == *contract_version
        })
        .count() as u32;
    let cell_escapes: Vec<&EscapedDefectRecord> = escapes
        .iter()
        .filter(|record| {
            record.cell.task_class == cell.task_class
                && record.contract_version == *contract_version
        })
        .collect();
    let escaped_defects = cell_escapes.len() as u32;
    let escaped_defect_rate_bp = if certified_executions == 0 {
        0
    } else {
        ((u64::from(escaped_defects).saturating_mul(10_000)) / u64::from(certified_executions))
            .min(10_000) as u16
    };
    let mut class_counts: BTreeMap<MissingConditionClass, u32> = BTreeMap::new();
    let mut time_to_discovery = Vec::new();
    for record in &cell_escapes {
        *class_counts.entry(record.attribution).or_insert(0) += 1;
        match record.time_to_discovery_ms() {
            Some(ms) => time_to_discovery.push(CensoredDiscovery {
                observed_ms: Some(ms),
                censored: false,
            }),
            None => time_to_discovery.push(CensoredDiscovery {
                observed_ms: None,
                censored: true,
            }),
        }
    }
    for execution in certified.iter().filter(|execution| {
        execution.cell.task_class == cell.task_class
            && execution.contract_version == *contract_version
            && !cell_escapes
                .iter()
                .any(|record| record.policy_execution_id == execution.policy_execution_id)
    }) {
        time_to_discovery.push(CensoredDiscovery {
            observed_ms: Some(
                now.as_millis()
                    .saturating_sub(execution.certified_at.as_millis()),
            ),
            censored: true,
        });
    }
    let mut share_per_class_bp = BTreeMap::new();
    for class in [
        MissingConditionClass::ValidatorAbsent,
        MissingConditionClass::ValidatorTooWeak,
        MissingConditionClass::RequirementNeverTraced,
        MissingConditionClass::ScopeConstraintMissing,
        MissingConditionClass::OracleWrong,
    ] {
        let count = *class_counts.get(&class).unwrap_or(&0);
        let share = if escaped_defects == 0 {
            0
        } else {
            ((u64::from(count).saturating_mul(10_000)) / u64::from(escaped_defects)).min(10_000)
                as u16
        };
        share_per_class_bp.insert(class, share);
    }
    let fired = fired_validators
        .get(contract_version.as_str())
        .cloned()
        .unwrap_or_default();
    let contract_coverage = declared_validators
        .iter()
        .map(|validator| ConditionFireRecord {
            validator_id: validator.clone(),
            fired: fired.contains(validator.as_str()),
        })
        .collect();
    CompletenessMetrics {
        cell_task_class: cell.task_class.as_str().to_string(),
        contract_version: contract_version.clone(),
        certified_executions,
        escaped_defects,
        escaped_defect_rate_bp,
        time_to_discovery,
        share_per_class_bp,
        contract_coverage,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GuardLadder {
    WidenPosteriors,
    RaiseLcbMargin { additional_bp: u16 },
    RestrictToSafeBaseline,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GoodhartGuard {
    pub cell_task_class: String,
    pub action: GuardLadder,
    pub reason: String,
    pub recent_share_bp: u16,
    pub escaped_defect_rate_bp: u16,
    pub conditions_fired: u32,
}

/// Cheapness obtained by routing into a blind spot is priced as risk.
pub fn selection_guard(
    metrics: &CompletenessMetrics,
    recent_share_bp: u16,
) -> Option<GoodhartGuard> {
    let conditions_fired = metrics
        .contract_coverage
        .iter()
        .filter(|record| record.fired)
        .count() as u32;
    let thin = conditions_fired == 0 || metrics.escaped_defect_rate_bp >= 2_000;
    let concentrated = recent_share_bp >= 5_000;
    if !thin || !concentrated {
        return None;
    }
    let action = if metrics.escaped_defect_rate_bp >= 4_000 {
        GuardLadder::RestrictToSafeBaseline
    } else if metrics.escaped_defect_rate_bp >= 2_000 {
        GuardLadder::RaiseLcbMargin {
            additional_bp: 1_000,
        }
    } else {
        GuardLadder::WidenPosteriors
    };
    Some(GoodhartGuard {
        cell_task_class: metrics.cell_task_class.clone(),
        action,
        reason: format!(
            "selections concentrated ({recent_share_bp} bp) in a weak-contract cell (escape rate {} bp, fired {conditions_fired})",
            metrics.escaped_defect_rate_bp
        ),
        recent_share_bp,
        escaped_defect_rate_bp: metrics.escaped_defect_rate_bp,
        conditions_fired,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReauditBudget {
    pub max_samples: u32,
    pub max_cost_micros: i64,
}

/// Deterministic sample of already-certified work. Findings are escapes, never
/// a new certification.
pub fn schedule_reaudit(
    certified: &[CertifiedExecution],
    budget: ReauditBudget,
    seed: u64,
) -> Vec<CertifiedExecution> {
    if budget.max_samples == 0 || certified.is_empty() {
        return Vec::new();
    }
    let mut indexed: Vec<(u64, &CertifiedExecution)> = certified
        .iter()
        .enumerate()
        .map(|(index, execution)| {
            let mix = seed
                .wrapping_mul(0x9E37_79B9_7F4A_7C15)
                .wrapping_add(index as u64);
            (mix, execution)
        })
        .collect();
    indexed.sort_by_key(|(rank, execution)| {
        (*rank, execution.policy_execution_id.as_str().to_string())
    });
    let mut selected = Vec::new();
    let mut spent = 0i64;
    for (_, execution) in indexed {
        if selected.len() >= budget.max_samples as usize {
            break;
        }
        // CertifiedExecution has no per-sample cost today. Each draw costs 1
        // so max_cost_micros=0 returns empty and a positive budget caps the
        // spread sample instead of taking a consecutive prefix.
        let cost = 1;
        if spent.saturating_add(cost) > budget.max_cost_micros {
            continue;
        }
        spent = spent.saturating_add(cost);
        selected.push(execution.clone());
    }
    selected
}

/// Type-level: this module cannot certify. The only write of certification
/// status is [`EscapedDefectLedger::record_certified`], which records a
/// historical fact from #161 — it does not flip `certified` to true.
pub fn cannot_certify() -> Result<Infallible, OptimizerError> {
    Err(OptimizerError::invalid(
        "escaped-defect audit cannot mark a candidate certified",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::optimizer::quality::{RequirementContract, RequirementStatus, ValidatorKind};
    use std::path::PathBuf;

    fn cell() -> TaxonomyCell {
        TaxonomyCell::new("repair", "rust", "local-repo").expect("cell")
    }

    fn execution(id: &str, version: &ContentHash, cheap: bool) -> CertifiedExecution {
        CertifiedExecution {
            policy_execution_id: PolicyExecutionId::new(id).expect("id"),
            contract_id: ContractId::new("c1").expect("contract"),
            contract_version: version.clone(),
            cell: cell(),
            certified_at: TimestampMillis::from_millis(1_000),
            policy_id: PolicyId::new("cheap-policy").expect("policy"),
            cheap,
        }
    }

    fn escape(
        id: &str,
        exec: &str,
        version: &ContentHash,
        class: MissingConditionClass,
        source: EscapeSource,
    ) -> EscapedDefectRecord {
        EscapedDefectRecord {
            defect_id: DefectId::new(id).expect("id"),
            policy_execution_id: PolicyExecutionId::new(exec).expect("id"),
            contract_id: ContractId::new("c1").expect("contract"),
            contract_version: version.clone(),
            cell: cell(),
            certified_at: TimestampMillis::from_millis(1_000),
            discovered_at: TimestampMillis::from_millis(5_000),
            source,
            attribution: class,
            would_have_caught: format!("condition for {id}"),
            why_it_did_not: format!("{class:?}"),
            secondary_policy_id: Some(PolicyId::new("cheap-policy").expect("policy")),
        }
    }

    fn contract() -> QualityContract {
        let mut contract = QualityContract::new(ContractId::new("c1").expect("contract"));
        contract.add_requirement(RequirementContract {
            requirement_id: RequirementId::new("REQ-1").expect("req"),
            implementation_paths: vec![PathBuf::from("src/x.rs")],
            validation_ids: vec![ValidatorId::new("unit").expect("val")],
            status: RequirementStatus::Satisfied,
        });
        contract.add_mandatory_validator(ValidatorBinding {
            validator_id: ValidatorId::new("unit").expect("val"),
            kind: ValidatorKind::DeterministicCommand {
                name: "cargo-test".to_string(),
            },
            required_for_production: true,
        });
        contract
    }

    #[test]
    fn escaped_defect_records_attribution_per_class() {
        let version = contract_version(&contract()).expect("version");
        let mut ledger = EscapedDefectLedger::new();
        ledger.record_certified(execution("exec-1", &version, true));
        ledger.record_certified(execution("exec-2", &version, true));
        ledger.record_certified(execution("exec-3", &version, true));
        ledger.record_certified(execution("exec-4", &version, true));
        ledger.record_certified(execution("exec-5", &version, true));
        let classes = [
            (
                "d-absent",
                "exec-1",
                MissingConditionClass::ValidatorAbsent,
                EscapeSource::PostMergeCiFailure,
            ),
            (
                "d-weak",
                "exec-2",
                MissingConditionClass::ValidatorTooWeak,
                EscapeSource::LaterAudit,
            ),
            (
                "d-trace",
                "exec-3",
                MissingConditionClass::RequirementNeverTraced,
                EscapeSource::FollowUpIssue {
                    requirement_id: RequirementId::new("REQ-1").expect("req"),
                },
            ),
            (
                "d-scope",
                "exec-4",
                MissingConditionClass::ScopeConstraintMissing,
                EscapeSource::HumanEditToMacoHunk,
            ),
            (
                "d-oracle",
                "exec-5",
                MissingConditionClass::OracleWrong,
                EscapeSource::RegressionBreakage,
            ),
        ];
        for (id, exec, class, source) in classes {
            ledger
                .record_escape(escape(id, exec, &version, class, source), None)
                .expect("escape");
        }
        let metrics = ledger.metrics(
            &cell(),
            &version,
            &[ValidatorId::new("unit").expect("val")],
            TimestampMillis::from_millis(9_000),
        );
        assert_eq!(metrics.certified_executions, 5);
        assert_eq!(metrics.escaped_defects, 5);
        assert_eq!(metrics.escaped_defect_rate_bp, 10_000);
        for class in [
            MissingConditionClass::ValidatorAbsent,
            MissingConditionClass::ValidatorTooWeak,
            MissingConditionClass::RequirementNeverTraced,
            MissingConditionClass::ScopeConstraintMissing,
            MissingConditionClass::OracleWrong,
        ] {
            assert_eq!(metrics.share_per_class_bp.get(&class).copied(), Some(2_000));
        }
    }

    #[test]
    fn metrics_are_a_pure_function_of_the_ledger_snapshot() {
        let version = contract_version(&contract()).expect("version");
        let mut ledger = EscapedDefectLedger::new();
        ledger.record_certified(execution("exec-p", &version, false));
        ledger
            .record_escape(
                escape(
                    "d-p",
                    "exec-p",
                    &version,
                    MissingConditionClass::ValidatorAbsent,
                    EscapeSource::PostRunSignal,
                ),
                None,
            )
            .expect("escape");
        let first = ledger.metrics(
            &cell(),
            &version,
            &[ValidatorId::new("unit").expect("val")],
            TimestampMillis::from_millis(8_000),
        );
        let second = metrics_from_snapshot(
            &ledger.certified,
            &ledger.escapes,
            &ledger.fired_validators,
            &cell(),
            &version,
            &[ValidatorId::new("unit").expect("val")],
            TimestampMillis::from_millis(8_000),
        );
        assert_eq!(first, second);
    }

    #[test]
    fn cheap_policy_concentration_in_a_weak_cell_triggers_the_ladder() {
        let version = contract_version(&contract()).expect("version");
        let mut ledger = EscapedDefectLedger::new();
        for index in 0..10 {
            ledger.record_certified(execution(&format!("exec-{index}"), &version, true));
        }
        for index in 0..4 {
            ledger
                .record_escape(
                    escape(
                        &format!("d-{index}"),
                        &format!("exec-{index}"),
                        &version,
                        MissingConditionClass::ValidatorAbsent,
                        EscapeSource::PostMergeCiFailure,
                    ),
                    None,
                )
                .expect("escape");
        }
        let metrics = ledger.metrics(
            &cell(),
            &version,
            &[ValidatorId::new("unit").expect("val")],
            TimestampMillis::from_millis(9_000),
        );
        let guard = selection_guard(&metrics, 8_000).expect("guard");
        assert_eq!(guard.action, GuardLadder::RestrictToSafeBaseline);
        assert!(guard.reason.contains("weak-contract"));
        assert_eq!(guard.conditions_fired, 0);
    }

    #[test]
    fn amendments_only_add_conditions() {
        let contract = contract();
        let version = contract_version(&contract).expect("version");
        let mut ledger = EscapedDefectLedger::new();
        ledger.record_certified(execution("exec-a", &version, true));
        ledger
            .record_escape(
                escape(
                    "d-a",
                    "exec-a",
                    &version,
                    MissingConditionClass::ValidatorAbsent,
                    EscapeSource::LaterAudit,
                ),
                None,
            )
            .expect("escape");
        let amendment = ledger
            .propose_amendment(
                &DefectId::new("d-a").expect("id"),
                ValidatorBinding {
                    validator_id: ValidatorId::new("mutation").expect("val"),
                    kind: ValidatorKind::MutationTest {
                        suite: "core".to_string(),
                    },
                    required_for_production: true,
                },
            )
            .expect("amendment");
        let extended = amendment.apply(&contract);
        assert_eq!(contract.mandatory_validators().len(), 1);
        assert_eq!(extended.mandatory_validators().len(), 2);
        assert_eq!(
            extended.mandatory_validators()[1].validator_id.as_str(),
            "mutation"
        );
    }

    #[test]
    fn sampling_reaudit_findings_enter_the_same_ledger() {
        let version = contract_version(&contract()).expect("version");
        let mut ledger = EscapedDefectLedger::new();
        for index in 0..6 {
            ledger.record_certified(execution(&format!("exec-{index}"), &version, false));
        }
        let sample = schedule_reaudit(
            &ledger.certified,
            ReauditBudget {
                max_samples: 2,
                max_cost_micros: 1_000_000,
            },
            7,
        );
        assert_eq!(sample.len(), 2);
        let empty = schedule_reaudit(
            &ledger.certified,
            ReauditBudget {
                max_samples: 2,
                max_cost_micros: 0,
            },
            7,
        );
        assert!(empty.is_empty());
        let sampled = sample[0].clone();
        ledger
            .record_escape(
                escape(
                    "d-re",
                    sampled.policy_execution_id.as_str(),
                    &version,
                    MissingConditionClass::ValidatorTooWeak,
                    EscapeSource::SamplingReaudit,
                ),
                None,
            )
            .expect("reaudit escape");
        assert_eq!(ledger.escapes.len(), 1);
        assert!(matches!(
            ledger.escapes[0].source,
            EscapeSource::SamplingReaudit
        ));
        assert!(cannot_certify().is_err());
    }

    #[test]
    fn escaped_defect_must_bind_a_certified_execution() {
        let version = contract_version(&contract()).expect("version");
        let mut ledger = EscapedDefectLedger::new();
        let error = ledger
            .record_escape(
                escape(
                    "d-unbound",
                    "exec-missing",
                    &version,
                    MissingConditionClass::ValidatorAbsent,
                    EscapeSource::PostRunSignal,
                ),
                None,
            )
            .expect_err("unbound");
        assert!(error.to_string().contains("certified execution"));
    }

    #[test]
    fn non_model_failures_are_not_escaped_defects() {
        let version = contract_version(&contract()).expect("version");
        let mut ledger = EscapedDefectLedger::new();
        ledger.record_certified(execution("exec-env", &version, false));
        let error = ledger
            .record_escape(
                escape(
                    "d-env",
                    "exec-env",
                    &version,
                    MissingConditionClass::OracleWrong,
                    EscapeSource::GateFinding,
                ),
                Some(TrajectoryLabel::EnvironmentFailure),
            )
            .expect_err("env");
        assert!(error.to_string().contains("non-model"));
    }
}
