use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

pub use crate::objective_profile::ContextSwitchCosts;

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
    pub entitlement_capacity_units: u64,
    pub entitlement_remaining_units: u64,
    pub pool_pressure_basis_points: u16,
    pub observed_consumption_units: u64,
    pub marginal_cost_microunits: u64,
    pub observation_revision: String,
    pub admission_provenance: String,
    pub failover_provenance: Option<String>,
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
pub struct ObjectiveProfileRef {
    pub name: String,
    pub version: u32,
    pub expected_digest: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectiveProfile {
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
    #[serde(default = "crate::objective_profile::historical_zero_switch_costs")]
    pub switch_costs: ContextSwitchCosts,
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
    pub objective_profiles: Vec<ObjectiveProfile>,
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
    pub constraints: OperatorConstraints,
    pub priors: PriorDataset,
    pub objective_profile: ObjectiveProfileRef,
    pub outcomes: Vec<OutcomeRecord>,
    pub signals: DynamicSignals,
    pub debug_override: Option<DebugOverride>,
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
    pub task: DigestRecord,
    pub catalogs: DigestRecord,
    pub pools: DigestRecord,
    pub constraints: DigestRecord,
    pub priors: DigestRecord,
    pub outcomes: DigestRecord,
    pub signals: DigestRecord,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectiveProfileProvenance {
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
    #[serde(default)]
    pub switch_transition: ContextSwitchTransition,
    #[serde(default)]
    pub configured_switch_cost_microunits: u64,
    #[serde(default)]
    pub switch_cost_microunits: u64,
    pub total_score_microunits: u64,
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
    pub ledger: LedgerSummary,
    pub score: Option<ScoreBreakdown>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RankedScore {
    pub rank: u32,
    pub candidate: CandidateKey,
    #[serde(default)]
    pub switch_transition: ContextSwitchTransition,
    #[serde(default)]
    pub configured_switch_cost_microunits: u64,
    #[serde(default)]
    pub switch_cost_microunits: u64,
    pub total_score_microunits: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContextSwitchTransition {
    Initial,
    Stay,
    EffortChangeSameRuntimeModel,
    ModelChangeSameRuntime,
    RuntimeChange,
}

impl Default for ContextSwitchTransition {
    fn default() -> Self {
        Self::Initial
    }
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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChoiceReason {
    LowestExpectedTotalCostPerAcceptedTask,
    StrongestNoEvidenceJudgmentFallback,
    DebugOverride,
    OneShotEnvironmentFallback,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SelectedChoice {
    pub candidate: CandidateKey,
    #[serde(default)]
    pub switch_transition: ContextSwitchTransition,
    #[serde(default)]
    pub configured_switch_cost_microunits: u64,
    #[serde(default)]
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
    pub objective_profile: ObjectiveProfileProvenance,
    pub catalog_revisions: Vec<CatalogRevisionProvenance>,
    pub runtime_operations: Vec<RuntimePoolState>,
    pub triggers: Vec<SelectionTrigger>,
    pub candidate_set: Vec<CandidateEvaluation>,
    pub choice: Option<SelectedChoice>,
    pub runner_up_scores: Vec<RankedScore>,
    pub decision_reason: String,
    pub debug_override: Option<DebugOverrideProvenance>,
    pub environment_fallback: Option<EnvironmentFallbackTransition>,
}
