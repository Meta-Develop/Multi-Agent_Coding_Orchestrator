//! Phase/model capability policy.
//!
//! Capability classification is evidence-backed configuration, not a compile-time
//! slug table. Unknown models have no judgment authority (fail closed).

use super::AgentRole;
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    sync::{Mutex, OnceLock},
};

/// Capability classes used by phase-aware model selection.
///
/// Ordering is intentional: callers may select a more capable model than
/// required, but never a less capable one. `WeakMechanical` is reserved for
/// enumerated terminal duties, not a general implementation tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelCapabilityClass {
    WeakMechanical,
    GeneralJudgment,
    CriticalJudgment,
}

impl ModelCapabilityClass {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::WeakMechanical => "weak_mechanical",
            Self::GeneralJudgment => "general_judgment",
            Self::CriticalJudgment => "critical_judgment",
        }
    }
}

/// Orchestration phases with materially different judgment requirements.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OrchestrationPhase {
    Discovery,
    Triage,
    Planning,
    MechanicalTerminal,
    Implementation,
    ValidationInterpretation,
    Merge,
    GateClassification,
    ReviewAcceptance,
    Audit,
}

impl OrchestrationPhase {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Discovery => "discovery",
            Self::Triage => "triage",
            Self::Planning => "planning",
            Self::MechanicalTerminal => "mechanical_terminal",
            Self::Implementation => "implementation",
            Self::ValidationInterpretation => "validation_interpretation",
            Self::Merge => "merge",
            Self::GateClassification => "gate_classification",
            Self::ReviewAcceptance => "review_acceptance",
            Self::Audit => "audit",
        }
    }

    pub const fn required_model_capability(self) -> ModelCapabilityClass {
        match self {
            Self::MechanicalTerminal => ModelCapabilityClass::WeakMechanical,
            Self::Discovery
            | Self::Triage
            | Self::Planning
            | Self::Implementation
            | Self::ValidationInterpretation
            | Self::Merge => ModelCapabilityClass::GeneralJudgment,
            Self::GateClassification | Self::ReviewAcceptance | Self::Audit => {
                ModelCapabilityClass::CriticalJudgment
            }
        }
    }

    pub const fn hard_excludes_weak_models(self) -> bool {
        !matches!(self, Self::MechanicalTerminal)
    }
}

/// Closed list of duties that a constrained weak-model profile may perform.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MechanicalTerminalDuty {
    ApplyExplicitTextReplacement,
    RunPreselectedCommand,
    FormatPreselectedFiles,
    EnumerateDeclaredArtifacts,
    ValidateAgainstFixedSchema,
}

impl MechanicalTerminalDuty {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ApplyExplicitTextReplacement => "apply_explicit_text_replacement",
            Self::RunPreselectedCommand => "run_preselected_command",
            Self::FormatPreselectedFiles => "format_preselected_files",
            Self::EnumerateDeclaredArtifacts => "enumerate_declared_artifacts",
            Self::ValidateAgainstFixedSchema => "validate_against_fixed_schema",
        }
    }
}

/// Auditable result of a successful phase/model policy decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PhaseModelPolicyDecision {
    pub role: AgentRole,
    pub phase: OrchestrationPhase,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mechanical_duty: Option<MechanicalTerminalDuty>,
    pub selected_capability: ModelCapabilityClass,
    pub required_capability: ModelCapabilityClass,
    pub weak_model_permitted: bool,
}

/// One evidence-backed model row in a capability policy.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModelCapabilityEvidence {
    pub model: String,
    pub capability: ModelCapabilityClass,
    #[serde(default = "default_true")]
    pub eligible: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub evidence: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub as_of: String,
}

const fn default_true() -> bool {
    true
}

/// Versioned, operator-supplied capability policy.
///
/// Unknown slugs are not guessed. A model must have an eligible row before it
/// can receive judgment authority.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModelCapabilityPolicy {
    pub id: String,
    pub version: u32,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub source: String,
    pub models: Vec<ModelCapabilityEvidence>,
}

impl ModelCapabilityPolicy {
    pub fn validate(&self) -> Result<()> {
        if self.id.trim().is_empty() {
            bail!("model capability policy id cannot be empty");
        }
        if self.version == 0 {
            bail!("model capability policy version must be greater than zero");
        }
        let mut seen = BTreeMap::new();
        for entry in &self.models {
            let model = entry.model.trim();
            if model.is_empty() || model != entry.model {
                bail!("model capability policy entries must use non-empty trimmed slugs");
            }
            if seen.insert(model, ()).is_some() {
                bail!("model capability policy repeats model '{model}'");
            }
        }
        Ok(())
    }

    pub fn content_hash(&self) -> Result<String> {
        let payload = serde_json::to_vec(self).context("failed to serialize capability policy")?;
        Ok(crate::artifacts::state_auth::sha256_hex(&payload))
    }

    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        let policy: Self =
            serde_json::from_slice(bytes).context("model capability policy is not valid JSON")?;
        policy.validate()?;
        Ok(policy)
    }

    pub fn lookup(&self, model: &str) -> Option<&ModelCapabilityEvidence> {
        self.models.iter().find(|entry| entry.model == model)
    }

    /// Eligible capability for `model`, or `None` when the slug is unknown or
    /// explicitly ineligible.
    pub fn capability_for(&self, model: &str) -> Option<ModelCapabilityClass> {
        self.lookup(model)
            .and_then(|entry| entry.eligible.then_some(entry.capability))
    }
}

/// Shipped default: dated 2026-08 priors from agent-registry#38.
///
/// `gpt-5.6-sol` is the judgment/planner tier. `gpt-5.6-luna` is a capable
/// worker for tightly specified leaves, not a weak-mechanical-only model.
/// `gpt-5.6-terra` is recorded as ineligible: weaker than luna on agentic
/// coding and more expensive per solved task.
pub fn default_model_capability_policy() -> ModelCapabilityPolicy {
    ModelCapabilityPolicy {
        id: "maco-default-model-capability-v1".to_string(),
        version: 1,
        source: "agent-registry#38 dated 2026-07/08 priors; cost per accepted task".to_string(),
        models: vec![
            ModelCapabilityEvidence {
                model: super::FRONTIER_PROFILE_MODEL.to_string(),
                capability: ModelCapabilityClass::CriticalJudgment,
                eligible: true,
                evidence: "repo-task pass 63.7%; SWE-Bench Pro 64.6%; planner/gate tier".to_string(),
                as_of: "2026-08-17".to_string(),
            },
            ModelCapabilityEvidence {
                model: super::ECONOMY_PROFILE_MODEL.to_string(),
                capability: ModelCapabilityClass::GeneralJudgment,
                eligible: true,
                evidence: "Coding Agent Index 75 at ~20% of Sol per-task cost; Terminal-Bench 2.1 84.7%; SWE-Bench Pro 62.7%; tightly specified leaves only".to_string(),
                as_of: "2026-08-17".to_string(),
            },
            ModelCapabilityEvidence {
                model: super::BALANCED_PROFILE_MODEL.to_string(),
                capability: ModelCapabilityClass::WeakMechanical,
                eligible: false,
                evidence: "agentic rank #112/302; repo-task pass 40.7%; ~2.65x tokens/solved task so higher cost per accepted task than Sol; do not use".to_string(),
                as_of: "2026-08-17".to_string(),
            },
        ],
    }
}

fn installed_policy() -> &'static Mutex<Option<ModelCapabilityPolicy>> {
    static POLICY: OnceLock<Mutex<Option<ModelCapabilityPolicy>>> = OnceLock::new();
    POLICY.get_or_init(|| Mutex::new(None))
}

pub fn current_model_capability_policy() -> ModelCapabilityPolicy {
    installed_policy()
        .lock()
        .ok()
        .and_then(|guard| guard.clone())
        .unwrap_or_else(default_model_capability_policy)
}

pub fn install_model_capability_policy(
    policy: ModelCapabilityPolicy,
) -> Result<InstalledModelCapabilityPolicy> {
    policy.validate()?;
    let mut guard = installed_policy()
        .lock()
        .expect("model capability policy lock");
    let previous = guard.replace(policy);
    Ok(InstalledModelCapabilityPolicy { previous })
}

/// Restores the previous installed policy when dropped.
pub struct InstalledModelCapabilityPolicy {
    previous: Option<ModelCapabilityPolicy>,
}

impl Drop for InstalledModelCapabilityPolicy {
    fn drop(&mut self) {
        if let Ok(mut guard) = installed_policy().lock() {
            *guard = self.previous.take();
        }
    }
}

pub fn trusted_model_capability(model: &str) -> Option<ModelCapabilityClass> {
    current_model_capability_policy().capability_for(model)
}

pub const fn role_minimum_model_capability(role: AgentRole) -> ModelCapabilityClass {
    match role {
        AgentRole::Supervisor | AgentRole::ChildOrchestrator => {
            ModelCapabilityClass::GeneralJudgment
        }
        AgentRole::Worker => ModelCapabilityClass::WeakMechanical,
        AgentRole::GateClassifier | AgentRole::Auditor => ModelCapabilityClass::CriticalJudgment,
    }
}

pub fn role_default_phase(role: AgentRole) -> Option<OrchestrationPhase> {
    match role {
        AgentRole::Supervisor => Some(OrchestrationPhase::Planning),
        AgentRole::ChildOrchestrator => Some(OrchestrationPhase::Implementation),
        AgentRole::Worker => None,
        AgentRole::GateClassifier => Some(OrchestrationPhase::GateClassification),
        AgentRole::Auditor => Some(OrchestrationPhase::Audit),
    }
}

/// Validate an explicit phase/model binding before dispatch or budget
/// degradation.
pub fn validate_phase_model_binding(
    role: AgentRole,
    phase: OrchestrationPhase,
    mechanical_duty: Option<MechanicalTerminalDuty>,
    selected_capability: ModelCapabilityClass,
) -> Result<PhaseModelPolicyDecision> {
    match (phase, mechanical_duty) {
        (OrchestrationPhase::MechanicalTerminal, None) => {
            bail!("mechanical_terminal phase requires an enumerated mechanical duty")
        }
        (OrchestrationPhase::MechanicalTerminal, Some(_)) => {}
        (_, Some(_)) => {
            bail!("mechanical duties may only be bound to the mechanical_terminal phase")
        }
        (_, None) => {}
    }

    let phase_requirement = phase.required_model_capability();
    let role_requirement = role.minimum_model_capability();
    let required_capability = phase_requirement.max(role_requirement);
    let weak_model_permitted = role == AgentRole::Worker
        && phase == OrchestrationPhase::MechanicalTerminal
        && mechanical_duty.is_some();

    if selected_capability == ModelCapabilityClass::WeakMechanical && !weak_model_permitted {
        bail!(
            "weak-model binding is forbidden for role '{}' in phase '{}'; only enumerated mechanical terminal worker duties are eligible",
            role.as_str(),
            phase.as_str()
        );
    }
    if selected_capability < required_capability {
        bail!(
            "model capability '{selected}' is below the '{required}' floor for role '{}' in phase '{}'",
            role.as_str(),
            phase.as_str(),
            selected = selected_capability.as_str(),
            required = required_capability.as_str(),
        );
    }

    Ok(PhaseModelPolicyDecision {
        role,
        phase,
        mechanical_duty,
        selected_capability,
        required_capability,
        weak_model_permitted,
    })
}

/// Budget degradation uses the same fail-closed phase policy as initial model
/// binding.
pub fn validate_budget_model_degradation(
    role: AgentRole,
    phase: OrchestrationPhase,
    mechanical_duty: Option<MechanicalTerminalDuty>,
    target_capability: ModelCapabilityClass,
) -> Result<PhaseModelPolicyDecision> {
    validate_phase_model_binding(role, phase, mechanical_duty, target_capability).with_context(
        || {
            format!(
                "budget model degradation is not permitted for role '{}' in phase '{}'",
                role.as_str(),
                phase.as_str()
            )
        },
    )
}

/// Fail-closed authority check for a resolved role/model pair.
///
/// Missing model identity and unknown/ineligible slugs cannot grant judgment
/// authority. Workers are not granted weak-mechanical authority here; that
/// requires a future typed executor.
pub fn validate_known_judgment_role_model(role: AgentRole, model: Option<&str>) -> Result<()> {
    let Some(model) = model else {
        bail!(
            "role '{}' resolved without an authoritative trusted model identity; runtime-default model selection is not capability evidence",
            role.as_str()
        );
    };
    let Some(capability) = trusted_model_capability(model) else {
        bail!("model '{model}' has no trusted capability policy");
    };
    let Some(phase) = role_default_phase(role) else {
        if capability == ModelCapabilityClass::WeakMechanical {
            bail!(
                "real-runtime weak_mechanical Worker model '{model}' is unavailable: no trusted typed planner/runtime authority or exact-operation executor exists"
            );
        }
        return Ok(());
    };
    validate_phase_model_binding(role, phase, None, capability)
        .map(|_| ())
        .with_context(|| {
            format!(
                "policy model '{}' does not satisfy role '{}' judgment floor",
                model,
                role.as_str()
            )
        })
}

/// Whether `model` is an eligible degrade target for `role`.
pub fn model_is_eligible_degrade_target(role: AgentRole, model: &str) -> bool {
    validate_known_judgment_role_model(role, Some(model)).is_ok()
}

#[cfg(test)]
pub fn install_test_fixture_models(
    models: &[(&str, ModelCapabilityClass)],
) -> Result<InstalledModelCapabilityPolicy> {
    let mut policy = default_model_capability_policy();
    policy.id = "maco-test-fixture-capability-v1".to_string();
    policy.source = "test fixture overlay; not production evidence".to_string();
    for (model, capability) in models {
        policy.models.retain(|entry| entry.model != *model);
        policy.models.push(ModelCapabilityEvidence {
            model: (*model).to_string(),
            capability: *capability,
            eligible: true,
            evidence: "test fixture model; expresses pricing/degrade intent without colliding with shipped slugs".to_string(),
            as_of: "test".to_string(),
        });
    }
    install_model_capability_policy(policy)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_policy_ranks_luna_above_ineligible_terra() {
        let policy = default_model_capability_policy();
        policy.validate().expect("default policy");
        assert_eq!(
            policy.capability_for("gpt-5.6-sol"),
            Some(ModelCapabilityClass::CriticalJudgment)
        );
        assert_eq!(
            policy.capability_for("gpt-5.6-luna"),
            Some(ModelCapabilityClass::GeneralJudgment)
        );
        assert_eq!(policy.capability_for("gpt-5.6-terra"), None);
        assert!(policy
            .lookup("gpt-5.6-terra")
            .is_some_and(|entry| !entry.eligible));
        assert_eq!(policy.capability_for("unknown-model"), None);
        assert!(!policy.content_hash().expect("hash").is_empty());
    }

    #[test]
    fn unknown_and_ineligible_models_fail_closed_for_judgment_roles() {
        let error =
            validate_known_judgment_role_model(AgentRole::ChildOrchestrator, Some("priced-model"))
                .expect_err("unknown model");
        assert!(error
            .to_string()
            .contains("has no trusted capability policy"));

        let terra =
            validate_known_judgment_role_model(AgentRole::ChildOrchestrator, Some("gpt-5.6-terra"))
                .expect_err("ineligible terra");
        assert!(terra
            .to_string()
            .contains("has no trusted capability policy"));

        validate_known_judgment_role_model(AgentRole::ChildOrchestrator, Some("gpt-5.6-luna"))
            .expect("luna is general judgment");
        validate_known_judgment_role_model(AgentRole::Auditor, Some("gpt-5.6-sol"))
            .expect("sol is critical judgment");
        let auditor_luna =
            validate_known_judgment_role_model(AgentRole::Auditor, Some("gpt-5.6-luna"))
                .expect_err("luna is below auditor floor");
        assert!(auditor_luna.to_string().contains("judgment floor"));
    }

    #[test]
    fn weak_models_cannot_take_judgment_phases() {
        let error = validate_phase_model_binding(
            AgentRole::ChildOrchestrator,
            OrchestrationPhase::Implementation,
            None,
            ModelCapabilityClass::WeakMechanical,
        )
        .expect_err("weak child");
        assert!(error
            .to_string()
            .contains("weak-model binding is forbidden"));

        validate_phase_model_binding(
            AgentRole::Worker,
            OrchestrationPhase::MechanicalTerminal,
            Some(MechanicalTerminalDuty::RunPreselectedCommand),
            ModelCapabilityClass::WeakMechanical,
        )
        .expect("enumerated mechanical worker duty");

        validate_budget_model_degradation(
            AgentRole::Auditor,
            OrchestrationPhase::Audit,
            None,
            ModelCapabilityClass::GeneralJudgment,
        )
        .expect_err("auditor cannot degrade below critical");
    }

    #[test]
    fn fixture_overlay_restores_previous_policy() {
        let _guard =
            install_test_fixture_models(&[("priced-model", ModelCapabilityClass::GeneralJudgment)])
                .expect("install fixture");
        validate_known_judgment_role_model(AgentRole::ChildOrchestrator, Some("priced-model"))
            .expect("fixture model is authorized");
        drop(_guard);
        validate_known_judgment_role_model(AgentRole::ChildOrchestrator, Some("priced-model"))
            .expect_err("overlay must not leak");
    }
}
