use std::collections::BTreeSet;

use crate::objective_profile::{ResolvedObjectiveProfile, TradeoffWeights};
use serde::{Deserialize, Serialize};

pub use crate::objective_profile::ContextSwitchCosts;
use crate::optimizer::quota_pools::{
    ConsumptionSource, ExhaustionBehavior, PoolKind, PoolReference,
};
pub use crate::optimizer::switch_cost::{SwitchCostEstimate, TransitionClass};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Boundedness {
    TightlyBounded,
    Bounded,
    CrossCutting,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContextSize {
    Small,
    Medium,
    Large,
    Long,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskHorizon {
    Short,
    Medium,
    Long,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityRole {
    TerminalLeaf,
    Delegating,
    AcceptanceGate,
    ReviewAuditor,
    Audit,
    ConflictResolution,
    FailureClassification,
    GitPublication,
    UnknownJudgment,
}

impl AuthorityRole {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TerminalLeaf => "terminal_leaf",
            Self::Delegating => "delegating",
            Self::AcceptanceGate => "acceptance_gate",
            Self::ReviewAuditor => "review_auditor",
            Self::Audit => "audit",
            Self::ConflictResolution => "conflict_resolution",
            Self::FailureClassification => "failure_classification",
            Self::GitPublication => "git_publication",
            Self::UnknownJudgment => "unknown_judgment",
        }
    }

    pub(crate) fn requires_exact_judgment_evidence(self) -> bool {
        !matches!(self, Self::TerminalLeaf)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReasoningEffort {
    Low,
    Medium,
    High,
    Xhigh,
    Max,
    Ultra,
}

impl ReasoningEffort {
    pub(crate) fn rank(self) -> u64 {
        match self {
            Self::Low => 0,
            Self::Medium => 1,
            Self::High => 2,
            Self::Xhigh => 3,
            Self::Max => 4,
            Self::Ultra => 5,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TaskProfile {
    pub task_class: String,
    pub risk: RiskLevel,
    pub boundedness: Boundedness,
    pub context: ContextSize,
    pub horizon: TaskHorizon,
    pub authority_role: AuthorityRole,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateKey {
    pub runtime: String,
    pub model: String,
    pub effort: ReasoningEffort,
}

/// Associates the optimizer's canonical switch-cost evidence with one
/// selector candidate without copying or flattening its evidence fields.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateSwitchCostEvidence {
    pub candidate: CandidateKey,
    pub estimate: SwitchCostEstimate,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateCapabilities {
    pub task_classes: BTreeSet<String>,
    pub authority_roles: BTreeSet<AuthorityRole>,
    pub boundedness: BTreeSet<Boundedness>,
    pub maximum_risk: RiskLevel,
    pub maximum_context: ContextSize,
    pub maximum_horizon: TaskHorizon,
    pub long_context: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogModel {
    pub model: String,
    pub available: bool,
    pub supported_efforts: Vec<ReasoningEffort>,
    pub capabilities: CandidateCapabilities,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeCatalog {
    pub runtime: String,
    pub revision: String,
    pub advertised_at: String,
    pub models: Vec<CatalogModel>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimePoolState {
    pub runtime: String,
    pub admission_open: bool,
    /// Exact configured pool identity. `None` is the legacy/no-quota-config path.
    #[serde(default)]
    pub pool_reference: Option<PoolReference>,
    /// Contract kind for a configured pool. `None` is legacy admission data.
    #[serde(default)]
    pub pool_kind: Option<PoolKind>,
    /// Whether capacity and remaining units are meaningful bounded values.
    #[serde(default = "default_true")]
    pub entitlement_bounded: bool,
    pub entitlement_capacity_units: u64,
    pub entitlement_remaining_units: u64,
    pub pool_pressure_basis_points: u16,
    pub observed_consumption_units: u64,
    pub marginal_cost_microunits: u64,
    /// Explicit exhaustion observation. Unbounded metered pools remain false.
    #[serde(default)]
    pub exhausted: bool,
    /// Operator-declared behavior for a configured pool.
    #[serde(default)]
    pub exhaustion_behavior: Option<ExhaustionBehavior>,
    /// Exact configured alternatives; an empty set authorizes no degradation.
    #[serde(default)]
    pub authorized_alternatives: Vec<PoolReference>,
    pub observation_revision: String,
    /// Typed local observation source. `None` is legacy caller provenance.
    #[serde(default)]
    pub observation_source: Option<ConsumptionSource>,
    pub admission_provenance: String,
    pub failover_provenance: Option<String>,
}

const fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorConstraints {
    pub allowed_runtimes: BTreeSet<String>,
    pub allowed_models: BTreeSet<String>,
    pub forbidden_runtimes: BTreeSet<String>,
    pub forbidden_models: BTreeSet<String>,
    pub forbidden_candidates: BTreeSet<CandidateKey>,
    pub allow_debug_override: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SelectorCalibrationRef {
    pub name: String,
    pub version: u32,
    pub expected_digest: Option<String>,
}

/// Source-compatible name for the legacy selector input field.
///
/// This reference selects dated calibration/evidence thresholds. The only
/// preference-bearing objective is [`ResolvedObjectiveProfile`].
pub type ObjectiveProfileRef = SelectorCalibrationRef;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SelectorCalibration {
    pub name: String,
    pub version: u32,
    pub effective_date: String,
    pub minimum_quality_basis_points: u16,
    pub minimum_class_fit_samples: u32,
    pub minimum_authority_samples: u32,
    pub pool_pressure_full_cost_microunits: u64,
    pub observed_consumption_unit_cost_microunits: u64,
    pub entitlement_scarcity_full_cost_microunits: u64,
    pub retry_penalty_microunits: u64,
    pub degrade_effort_rank_penalty_microunits: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClassFitPrior {
    pub task_class: String,
    pub effort: ReasoningEffort,
    pub quality_basis_points: u16,
    pub sample_size: u32,
    pub execution_cost_microunits: u64,
    pub review_cost_microunits: u64,
    pub rework_cost_microunits: u64,
    pub rereview_cost_microunits: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityEvidencePrior {
    pub task_class: String,
    pub role: AuthorityRole,
    pub effort: ReasoningEffort,
    pub quality_basis_points: u16,
    pub sample_size: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OneShotEnvironmentFallback {
    pub rejection_code: String,
    pub target_runtime: String,
    pub target_model: String,
    pub target_effort: ReasoningEffort,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModelPrior {
    pub runtime: String,
    pub model: String,
    pub observed_on: String,
    pub source_id: String,
    pub prior_scope: String,
    pub limitations: Vec<String>,
    pub prohibited: bool,
    pub prohibition_reason: Option<String>,
    pub prohibited_authority_roles: BTreeSet<AuthorityRole>,
    pub long_context_eligible: bool,
    pub strong_gate_fallback_efforts: BTreeSet<ReasoningEffort>,
    pub strength_rank: u16,
    pub class_fit: Vec<ClassFitPrior>,
    pub authority_evidence: Vec<AuthorityEvidencePrior>,
    pub one_shot_environment_fallbacks: Vec<OneShotEnvironmentFallback>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PriorDataset {
    pub schema_version: u32,
    pub dataset_id: String,
    pub revision: String,
    pub published_on: String,
    /// Dated selector quality gates and cost calibration, not an objective.
    pub objective_profiles: Vec<SelectorCalibration>,
    pub models: Vec<ModelPrior>,
}

/// Dated catalog/evidence eligibility for a model/authority pair.
///
/// A static capability tier may be used only as fallback when no dated prior
/// exists. It must not authorize a slug that measured evidence marks ineligible.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MeasuredAuthorityEligibility {
    Eligible,
    Ineligible { reason: String },
    NoDatedEvidence,
}

impl ModelPrior {
    fn denial_for_authority(&self, authority: AuthorityRole) -> Option<String> {
        if self.prohibited {
            return Some(self.prohibition_reason.clone().unwrap_or_else(|| {
                format!("dated prior '{}' prohibits the model", self.source_id)
            }));
        }
        if self.prohibited_authority_roles.contains(&authority) {
            return Some(format!(
                "dated prior '{}' prohibits authority '{}'",
                self.source_id,
                authority.as_str()
            ));
        }
        if authority.requires_exact_judgment_evidence() {
            let has_exact = self
                .authority_evidence
                .iter()
                .any(|evidence| evidence.role == authority);
            let has_fallback = !self.strong_gate_fallback_efforts.is_empty();
            if !has_exact && !has_fallback {
                return Some(format!(
                    "dated prior '{}' does not establish judgment eligibility for authority '{}'",
                    self.source_id,
                    authority.as_str()
                ));
            }
        }
        None
    }
}

impl PriorDataset {
    /// Consult dated priors only. Unknown slugs are `NoDatedEvidence` so a
    /// static tier table can still act as fallback.
    pub fn measured_authority_eligibility(
        &self,
        model: &str,
        authority: AuthorityRole,
    ) -> MeasuredAuthorityEligibility {
        let matches = self
            .models
            .iter()
            .filter(|prior| prior.model == model)
            .collect::<Vec<_>>();
        if matches.is_empty() {
            return MeasuredAuthorityEligibility::NoDatedEvidence;
        }
        let deny_reasons = matches
            .iter()
            .filter_map(|prior| prior.denial_for_authority(authority))
            .collect::<Vec<_>>();
        if deny_reasons.is_empty() {
            MeasuredAuthorityEligibility::Eligible
        } else {
            MeasuredAuthorityEligibility::Ineligible {
                reason: deny_reasons.join("; "),
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OutcomeResult {
    Accepted,
    Rejected,
    Blocked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureClass {
    ModelQuality,
    Environment,
    Operator,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentFailure {
    pub code: String,
    pub evidence_id: String,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FixedCauseRelaunchEvidence {
    pub proven_failure_cause: String,
    pub exact_corrective_change: String,
    pub same_cause_fix_verification: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OutcomeRecord {
    pub attempt_id: String,
    pub task: TaskProfile,
    pub candidate: CandidateKey,
    pub result: OutcomeResult,
    pub failure_class: Option<FailureClass>,
    pub execution_cost_microunits: u64,
    pub review_cost_microunits: u64,
    pub rework_cost_microunits: u64,
    pub rereview_cost_microunits: u64,
    pub environment_cost_microunits: u64,
    pub environment_failures: Vec<EnvironmentFailure>,
    pub fixed_cause_relaunch: Option<FixedCauseRelaunchEvidence>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BudgetSignal {
    Continue,
    Degrade,
    OwnerEscalation,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DebugOverride {
    pub candidate: CandidateKey,
    pub requested_by: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentRejectionState {
    pub candidate: CandidateKey,
    pub rejection_code: String,
    pub evidence_id: String,
    pub fallback_transition_used: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DynamicSignals {
    pub retry_count: u32,
    pub budget_signal: BudgetSignal,
    pub previous_choice: Option<CandidateKey>,
    pub previous_catalog_digest: Option<String>,
    pub environment_rejections: Vec<EnvironmentRejectionState>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SelectionInput {
    pub task: TaskProfile,
    pub catalogs: Vec<RuntimeCatalog>,
    pub pools: Vec<RuntimePoolState>,
    /// Exact primary pool whose exhaustion policy governs this decision.
    ///
    /// `None` preserves the pre-quota selector behavior. Configured live quota
    /// selection must name a source rather than inferring one from catalog order.
    #[serde(default)]
    pub quota_source: Option<PoolReference>,
    pub constraints: OperatorConstraints,
    pub priors: PriorDataset,
    /// Legacy wire/source field name for dated selector calibration.
    /// Preference-bearing weights live only in `resolved_objective_profile`.
    pub objective_profile: SelectorCalibrationRef,
    pub resolved_objective_profile: ResolvedObjectiveProfile,
    pub outcomes: Vec<OutcomeRecord>,
    pub signals: DynamicSignals,
    pub debug_override: Option<DebugOverride>,
    /// Typed quota/latency/retry-rate/review-load observations from the live
    /// path. Absent means the profile axes that require them must fail closed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operational_observations: Option<LiveOperationalObservations>,
}

/// Measured operational axes consumed by preference-bearing objective weights.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LiveOperationalObservations {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quota: Option<TypedAxisObservation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latency: Option<TypedAxisObservation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_rate: Option<TypedAxisObservation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub review_load: Option<TypedAxisObservation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TypedAxisObservation {
    pub kind: TypedObservationKind,
    pub unit: String,
    /// Normalized `[0, 10000]` basis points. Lower is better for operational axes.
    pub value_basis_points: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TypedObservationKind {
    Measured,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DigestRecord {
    pub algorithm: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InputDigests {
    pub normalized_input: DigestRecord,
    pub switch_cost_evidence: DigestRecord,
    pub task: DigestRecord,
    pub catalogs: DigestRecord,
    pub pools: DigestRecord,
    pub constraints: DigestRecord,
    pub priors: DigestRecord,
    pub resolved_objective_profile: DigestRecord,
    pub outcomes: DigestRecord,
    pub signals: DigestRecord,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SelectorCalibrationProvenance {
    pub dataset_id: String,
    pub dataset_revision: String,
    pub dataset_published_on: String,
    pub profile_name: String,
    pub profile_version: u32,
    pub profile_effective_date: String,
    pub profile_digest: DigestRecord,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LedgerSummary {
    pub matching_attempts: u32,
    pub accepted: u32,
    pub rejected: u32,
    pub blocked: u32,
    pub quality_attempts: u32,
    pub environment_failure_count: u32,
    pub execution_cost_microunits: u64,
    pub review_cost_microunits: u64,
    pub rework_cost_microunits: u64,
    pub rereview_cost_microunits: u64,
    pub environment_cost_microunits: u64,
    pub total_cycle_cost_microunits: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IneligibilityCode {
    CatalogUnavailable,
    OperatorConstraint,
    RuntimeAdmissionClosed,
    EntitlementExhausted,
    QuotaFailClosed,
    QuotaAlternativeNotAuthorized,
    TaskClassNotAdvertised,
    TaskShapeNotAdvertised,
    AuthorityNotAdvertised,
    PolicyProhibited,
    LongContextProhibited,
    MissingDatedPrior,
    MissingClassFitEvidence,
    ClassFitEvidenceInsufficient,
    QualityBarNotMet,
    MissingAuthorityEvidence,
    AuthorityEvidenceInsufficient,
    AuthorityQualityBarNotMet,
    UnknownJudgmentAuthority,
    EnvironmentRejected,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IneligibilityReason {
    pub code: IneligibilityCode,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ScoreBreakdown {
    pub posterior_quality_basis_points: u16,
    pub authority_quality_basis_points: Option<u16>,
    pub expected_total_cost_per_accepted_task_microunits: u64,
    pub pool_pressure_cost_microunits: u64,
    pub entitlement_scarcity_cost_microunits: u64,
    pub observed_consumption_cost_microunits: u64,
    pub marginal_cost_microunits: u64,
    pub retry_cost_microunits: u64,
    pub degrade_cost_microunits: u64,
    /// Source-compatible scalar mirror of `switch_cost_estimate.class`.
    pub switch_transition: TransitionClass,
    pub switch_cost_origin: SwitchCostEvidenceOrigin,
    pub switch_cost_estimate: SwitchCostEstimate,
    /// Conservative estimate from the resolved objective profile.
    ///
    /// Switching arms charge at least this amount; measured or inferred
    /// optimizer evidence can raise the charged term.
    pub configured_switch_cost_microunits: u64,
    pub configured_switch_cost_origin: ConfiguredSwitchCostOrigin,
    /// Raw cost licensed for this comparison before quality normalization.
    pub applied_switch_cost_microunits: u64,
    /// Applied cost normalized per accepted task and added to the score.
    pub switch_cost_microunits: u64,
    pub routing_score_semantics: RoutingScoreSemantics,
    pub routing_tradeoff_weights: TradeoffWeights,
    pub legacy_baseline_score_microunits: u64,
    pub retry_rework_cost_proxy_microunits: u64,
    pub human_review_cost_proxy_microunits: u64,
    pub retry_rework_adjustment_microunits: u64,
    pub human_review_adjustment_microunits: u64,
    pub total_adjustment_microunits: u64,
    pub total_score_microunits: u64,
}

/// Versioned interpretation of selector objective weights.
///
/// The legacy baseline already contains complete cycle and operational score
/// components. Supported non-monetary weights intentionally add cost-proxy
/// penalties relative to that baseline; they are not a non-overlapping cost
/// decomposition, rate, load, or independent observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RoutingScoreSemantics {
    LegacyBaselinePlusCostProxyAdjustmentsV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateEvaluation {
    pub candidate: CandidateKey,
    pub prior_source_id: Option<String>,
    pub prior_observed_on: Option<String>,
    pub prior_scope: Option<String>,
    pub prior_limitations: Vec<String>,
    pub strong_gate_fallback: bool,
    pub eligible: bool,
    pub ineligibility_reasons: Vec<IneligibilityReason>,
    #[serde(default)]
    pub quota: QuotaCandidateProvenance,
    pub ledger: LedgerSummary,
    pub score: Option<ScoreBreakdown>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RankedScore {
    pub rank: u32,
    pub candidate: CandidateKey,
    pub switch_transition: TransitionClass,
    pub switch_cost_origin: SwitchCostEvidenceOrigin,
    pub switch_cost_estimate: SwitchCostEstimate,
    pub configured_switch_cost_microunits: u64,
    pub configured_switch_cost_origin: ConfiguredSwitchCostOrigin,
    pub applied_switch_cost_microunits: u64,
    pub switch_cost_microunits: u64,
    pub total_score_microunits: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SwitchCostEvidenceOrigin {
    OptimizerEstimate,
    OptimizerColdStartPrior,
    ContinueZero,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfiguredSwitchCostOrigin {
    NotApplicable,
    ResolvedProfileInferredPrior,
}

/// Source compatibility for callers that referred to the selector-local name.
/// The semantic type is now the optimizer's canonical [`TransitionClass`].
pub type ContextSwitchTransition = TransitionClass;

impl TransitionClass {
    #[allow(non_upper_case_globals)]
    pub const Initial: Self = Self::Continue;
    #[allow(non_upper_case_globals)]
    pub const Stay: Self = Self::Continue;
    #[allow(non_upper_case_globals)]
    pub const EffortChangeSameRuntimeModel: Self = Self::Continue;
    #[allow(non_upper_case_globals)]
    pub const RuntimeChange: Self = Self::RuntimeAdapterChange;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SelectionTrigger {
    Initial,
    Retry,
    BudgetDegrade,
    CatalogChange,
    EnvironmentFallback,
    DebugOverride,
    QuotaExhaustion,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChoiceReason {
    LowestExpectedTotalCostPerAcceptedTask,
    LowestLegacyBaselinePlusCostProxyAdjustments,
    StrongestNoEvidenceJudgmentFallback,
    DebugOverride,
    OneShotEnvironmentFallback,
    AuthorizedQuotaDegrade,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QuotaCandidateDisposition {
    #[default]
    LegacyUnconfigured,
    SourceAvailable,
    SourceExhausted,
    AuthorizedAlternative,
    RejectedUnauthorizedAlternative,
    FailClosed,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QuotaCandidateProvenance {
    pub source_pool: Option<PoolReference>,
    pub target_pool: Option<PoolReference>,
    pub source_exhausted: bool,
    pub configured_behavior: Option<ExhaustionBehavior>,
    pub authorized_alternative: bool,
    pub disposition: QuotaCandidateDisposition,
    pub source_observation_revision: Option<String>,
    pub source_observation: Option<ConsumptionSource>,
    pub target_marginal_cost_microunits: Option<u64>,
    pub reason: String,
}

impl Default for QuotaCandidateProvenance {
    fn default() -> Self {
        Self {
            source_pool: None,
            target_pool: None,
            source_exhausted: false,
            configured_behavior: None,
            authorized_alternative: false,
            disposition: QuotaCandidateDisposition::LegacyUnconfigured,
            source_observation_revision: None,
            source_observation: None,
            target_marginal_cost_microunits: None,
            reason: "legacy schema-v1 selector event did not carry typed quota provenance"
                .to_string(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QuotaDecisionDisposition {
    SourceAvailable,
    FailClosed,
    Degraded,
    RefusedByExplicitOverride,
    RefusedNoEligibleAlternative,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RejectedQuotaAlternative {
    pub candidate: CandidateKey,
    pub reasons: Vec<IneligibilityReason>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QuotaDecisionProvenance {
    pub source_pool: PoolReference,
    pub configured_behavior: ExhaustionBehavior,
    pub source_exhausted: bool,
    pub local_observation_revision: String,
    pub observation_source: ConsumptionSource,
    pub marginal_cost_assumption_microunits: u64,
    pub authorized_alternatives: Vec<PoolReference>,
    pub eligible_alternatives: Vec<CandidateKey>,
    pub rejected_alternatives: Vec<RejectedQuotaAlternative>,
    pub selected_alternative: Option<CandidateKey>,
    pub disposition: QuotaDecisionDisposition,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SelectedChoice {
    pub candidate: CandidateKey,
    pub switch_transition: TransitionClass,
    pub switch_cost_origin: SwitchCostEvidenceOrigin,
    pub switch_cost_estimate: SwitchCostEstimate,
    pub configured_switch_cost_microunits: u64,
    pub configured_switch_cost_origin: ConfiguredSwitchCostOrigin,
    pub applied_switch_cost_microunits: u64,
    pub switch_cost_microunits: u64,
    pub total_score_microunits: u64,
    pub reason: ChoiceReason,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DebugOverrideDisposition {
    Applied,
    Rejected,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DebugOverrideProvenance {
    pub request: DebugOverride,
    pub disposition: DebugOverrideDisposition,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentFallbackTransition {
    pub source: CandidateKey,
    pub target: CandidateKey,
    pub rejection_code: String,
    pub evidence_id: String,
    pub transition_ordinal: u8,
    pub maximum_transitions: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogRevisionProvenance {
    pub runtime: String,
    pub revision: String,
    pub advertised_at: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionStatus {
    Selected,
    FailClosed,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SelectionProvenance {
    pub schema_version: u32,
    pub status: DecisionStatus,
    pub normalized_input: SelectionInput,
    pub normalized_task: TaskProfile,
    pub input_digests: InputDigests,
    pub provided_switch_cost_evidence: Vec<CandidateSwitchCostEvidence>,
    /// Legacy wire field name retained for selection-artifact compatibility.
    pub objective_profile: SelectorCalibrationProvenance,
    pub resolved_objective_profile: ResolvedObjectiveProfile,
    pub catalog_revisions: Vec<CatalogRevisionProvenance>,
    pub runtime_operations: Vec<RuntimePoolState>,
    pub triggers: Vec<SelectionTrigger>,
    pub candidate_set: Vec<CandidateEvaluation>,
    pub choice: Option<SelectedChoice>,
    pub runner_up_scores: Vec<RankedScore>,
    pub decision_reason: String,
    pub debug_override: Option<DebugOverrideProvenance>,
    pub environment_fallback: Option<EnvironmentFallbackTransition>,
    #[serde(default)]
    pub quota: Option<QuotaDecisionProvenance>,
}
