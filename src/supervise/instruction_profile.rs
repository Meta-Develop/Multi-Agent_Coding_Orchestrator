//! Named instruction profiles attached at supervise prompt build.
//!
//! First #91 slice: low-tier and high-effort-mismatch models receive a
//! condensed mechanical instruction shape. Optimizer weights and phase
//! admission stay outside this module.

use super::{current_model_capability_policy, ModelCapabilityClass};

pub const WEAK_MECHANICAL_INSTRUCTION_PROFILE_ID: &str = "maco-weak-mechanical-lite-v1";

const WEAK_MECHANICAL_INSTRUCTION_PROFILE_BODY: &str = "\
This session uses the weak-mechanical instruction profile.
- Execute only the assigned mechanical steps. Do not invent scope, policy, or extra work.
- Prefer the exact command, path, schema, or helper already named in this prompt.
- One instruction at a time. Do not stack compound judgment.
- If a required helper, schema, path, or command is missing or fails, stop and report the block. Do not fall back to open-ended judgment.
- Discovery, triage, merge, and acceptance decisions are out of scope. Report them upward instead of taking them over.
- Do not relax ownership, journaling, validation, or audit requirements.";

/// Why a named instruction profile was attached.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstructionProfileReason {
    LowTierCapability,
    HighEffortMismatch,
}

impl InstructionProfileReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LowTierCapability => "low_tier_capability",
            Self::HighEffortMismatch => "high_effort_mismatch",
        }
    }
}

/// Auditable decision to attach one named instruction profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstructionProfileAttachment {
    pub profile_id: &'static str,
    pub reason: InstructionProfileReason,
}

/// Select a named instruction profile from the bound model and effort.
///
/// `WeakMechanical` always receives the lite profile. High or greater
/// reasoning effort on any non-critical model is treated as a mismatch.
pub fn select_instruction_profile(
    model: Option<&str>,
    reasoning_effort: Option<&str>,
) -> Option<InstructionProfileAttachment> {
    let capability = model.and_then(recorded_model_capability);
    if capability == Some(ModelCapabilityClass::WeakMechanical) {
        return Some(InstructionProfileAttachment {
            profile_id: WEAK_MECHANICAL_INSTRUCTION_PROFILE_ID,
            reason: InstructionProfileReason::LowTierCapability,
        });
    }
    if effort_is_high_or_above(reasoning_effort)
        && capability != Some(ModelCapabilityClass::CriticalJudgment)
    {
        return Some(InstructionProfileAttachment {
            profile_id: WEAK_MECHANICAL_INSTRUCTION_PROFILE_ID,
            reason: InstructionProfileReason::HighEffortMismatch,
        });
    }
    None
}

/// Render the attached profile, or an empty string when none applies.
pub fn instruction_profile_prompt_section(
    model: Option<&str>,
    reasoning_effort: Option<&str>,
) -> String {
    match select_instruction_profile(model, reasoning_effort) {
        Some(attachment) => render_instruction_profile_section(&attachment),
        None => String::new(),
    }
}

fn render_instruction_profile_section(attachment: &InstructionProfileAttachment) -> String {
    format!(
        "\nINSTRUCTION_PROFILE: {}\nReason: {}\n\n{}\n",
        attachment.profile_id,
        attachment.reason.as_str(),
        WEAK_MECHANICAL_INSTRUCTION_PROFILE_BODY
    )
}

fn recorded_model_capability(model: &str) -> Option<ModelCapabilityClass> {
    current_model_capability_policy()
        .lookup(model)
        .map(|entry| entry.capability)
}

fn effort_is_high_or_above(reasoning_effort: Option<&str>) -> bool {
    matches!(
        reasoning_effort.map(str::trim),
        Some("high" | "xhigh" | "max" | "ultra")
    )
}

#[cfg(test)]
mod tests {
    use super::super::{
        install_test_fixture_models, BALANCED_PROFILE_MODEL, ECONOMY_PROFILE_MODEL,
        FRONTIER_PROFILE_MODEL,
    };
    use super::*;

    #[test]
    fn frontier_model_keeps_the_standard_prompt_shape() {
        assert_eq!(
            select_instruction_profile(Some(FRONTIER_PROFILE_MODEL), Some("xhigh")),
            None
        );
        assert!(
            instruction_profile_prompt_section(Some(FRONTIER_PROFILE_MODEL), Some("xhigh"))
                .is_empty()
        );
        assert!(instruction_profile_prompt_section(None, None).is_empty());
    }

    #[test]
    fn recorded_weak_mechanical_model_attaches_the_named_lite_profile() {
        let attachment = select_instruction_profile(Some(BALANCED_PROFILE_MODEL), Some("medium"))
            .expect("terra is recorded weak-mechanical");
        assert_eq!(
            attachment.profile_id,
            WEAK_MECHANICAL_INSTRUCTION_PROFILE_ID
        );
        assert_eq!(
            attachment.reason,
            InstructionProfileReason::LowTierCapability
        );
        let section =
            instruction_profile_prompt_section(Some(BALANCED_PROFILE_MODEL), Some("medium"));
        assert!(section.contains("INSTRUCTION_PROFILE: maco-weak-mechanical-lite-v1"));
        assert!(section.contains("Reason: low_tier_capability"));
        assert!(section.contains("stop and report the block"));
        assert!(
            section.contains("Discovery, triage, merge, and acceptance decisions are out of scope")
        );
    }

    #[test]
    fn general_judgment_model_at_xhigh_is_a_high_effort_mismatch() {
        let attachment = select_instruction_profile(Some(ECONOMY_PROFILE_MODEL), Some("xhigh"))
            .expect("luna at planner effort is a mismatch");
        assert_eq!(
            attachment.profile_id,
            WEAK_MECHANICAL_INSTRUCTION_PROFILE_ID
        );
        assert_eq!(
            attachment.reason,
            InstructionProfileReason::HighEffortMismatch
        );
        assert!(
            instruction_profile_prompt_section(Some(ECONOMY_PROFILE_MODEL), Some("medium"))
                .is_empty()
        );
    }

    #[test]
    fn unknown_model_attaches_only_when_effort_is_high() {
        assert_eq!(
            select_instruction_profile(Some("unknown-local-model"), Some("low")),
            None
        );
        let attachment = select_instruction_profile(Some("unknown-local-model"), Some("high"))
            .expect("unknown model at high effort is a mismatch");
        assert_eq!(
            attachment.reason,
            InstructionProfileReason::HighEffortMismatch
        );
    }

    #[test]
    fn fixture_overlay_weak_model_is_selected_as_low_tier() {
        let _guard = install_test_fixture_models(&[(
            "lite-fixture-model",
            ModelCapabilityClass::WeakMechanical,
        )])
        .expect("install weak fixture");
        let attachment = select_instruction_profile(Some("lite-fixture-model"), Some("low"))
            .expect("overlay weak model");
        assert_eq!(
            attachment.reason,
            InstructionProfileReason::LowTierCapability
        );
    }
}
