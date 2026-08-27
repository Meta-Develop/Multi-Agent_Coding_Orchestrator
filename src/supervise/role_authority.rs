//! Role categories as authority boundaries (#221).
//!
//! Delegation, write, and judgment attach to a category, not to a launch-time
//! tier name. This slice records auto-selected (or operator-overridden) role
//! categories on assignment. It does not run the optimizer, emit variable-depth
//! plans, or change weak-model capability floors.

use super::{AgentRole, ModelCapabilityClass};
use crate::orchestration_event::OrchestrationEvent;
use crate::selection::{
    measured_authority_eligibility, AuthorityRole, MeasuredAuthorityEligibility,
};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const ROLE_ASSIGNMENT_FIELD: &str = "role_assignment";

/// Authority primitive. Launch-time tier names map onto these categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RoleCategory {
    DelegatingCoordinator,
    NonDelegatingTerminalWorker,
    ReadOnlyResearcher,
    ReadOnlyReviewAuditor,
}

impl RoleCategory {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DelegatingCoordinator => "delegating_coordinator",
            Self::NonDelegatingTerminalWorker => "non_delegating_terminal_worker",
            Self::ReadOnlyResearcher => "read_only_researcher",
            Self::ReadOnlyReviewAuditor => "read_only_review_auditor",
        }
    }

    pub const fn may_delegate(self) -> bool {
        matches!(self, Self::DelegatingCoordinator)
    }

    pub const fn may_write(self) -> bool {
        matches!(
            self,
            Self::DelegatingCoordinator | Self::NonDelegatingTerminalWorker
        )
    }

    pub const fn may_judge_acceptance(self) -> bool {
        matches!(self, Self::ReadOnlyReviewAuditor)
    }

    pub const fn may_judge_role_transition(self) -> bool {
        matches!(self, Self::ReadOnlyReviewAuditor)
    }

    pub const fn is_read_only(self) -> bool {
        matches!(self, Self::ReadOnlyResearcher | Self::ReadOnlyReviewAuditor)
    }

    pub const fn is_non_delegating_terminal_worker(self) -> bool {
        matches!(self, Self::NonDelegatingTerminalWorker)
    }

    /// Capability floor a subject must already meet before receiving this category.
    pub const fn subject_capability_floor(self) -> ModelCapabilityClass {
        match self {
            Self::DelegatingCoordinator => ModelCapabilityClass::GeneralJudgment,
            Self::ReadOnlyReviewAuditor => ModelCapabilityClass::CriticalJudgment,
            Self::NonDelegatingTerminalWorker | Self::ReadOnlyResearcher => {
                ModelCapabilityClass::WeakMechanical
            }
        }
    }

    /// Measured-authority role used at admission. Coordinator and auditor
    /// categories never collapse to a terminal-leaf check.
    pub const fn measured_authority_role(self) -> AuthorityRole {
        match self {
            Self::DelegatingCoordinator => AuthorityRole::Delegating,
            Self::NonDelegatingTerminalWorker | Self::ReadOnlyResearcher => {
                AuthorityRole::TerminalLeaf
            }
            Self::ReadOnlyReviewAuditor => AuthorityRole::ReviewAuditor,
        }
    }

    const fn authority_bits(self) -> u8 {
        const DELEGATE: u8 = 0b001;
        const WRITE: u8 = 0b010;
        const JUDGE: u8 = 0b100;
        match self {
            Self::DelegatingCoordinator => DELEGATE | WRITE,
            Self::NonDelegatingTerminalWorker => WRITE,
            Self::ReadOnlyResearcher => 0,
            Self::ReadOnlyReviewAuditor => JUDGE,
        }
    }
}

/// How a category was chosen for an assignment. Manual designation is an
/// override; the default is derived from the plan role, not a launch tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RoleAssignmentSource {
    DerivedFromPlanRole,
    OperatorOverride,
}

/// Spawn/assignment provenance matching the transition-record shape.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct RoleAssignmentProvenance {
    pub requester_agent_id: String,
    pub judge_agent_id: String,
    pub evidence: RoleTransitionEvidence,
    pub decision: RoleTransitionDecisionKind,
}

impl RoleAssignmentProvenance {
    pub fn granted_by(parent_agent_id: impl Into<String>) -> Self {
        let id = parent_agent_id.into();
        Self {
            requester_agent_id: id.clone(),
            judge_agent_id: id,
            evidence: RoleTransitionEvidence {
                acceptance_grade: false,
                recorded: true,
                uncertain: false,
            },
            decision: RoleTransitionDecisionKind::Granted,
        }
    }

    pub fn operator_override() -> Self {
        Self::granted_by("operator")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RoleAssignmentRecord {
    pub agent_id: String,
    pub category: RoleCategory,
    pub legacy_role: String,
    pub source: RoleAssignmentSource,
    pub requester_agent_id: String,
    pub judge_agent_id: String,
    #[serde(default)]
    pub evidence: RoleTransitionEvidence,
    pub decision: RoleTransitionDecisionKind,
    pub reason: String,
}

/// Classify a transition by whether it grants or removes authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RoleTransitionKind {
    Promotion,
    Demotion,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RoleTransitionDecisionKind {
    #[default]
    Granted,
    Refused,
}

/// Acceptance-grade evidence required to execute a promotion.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RoleTransitionEvidence {
    pub acceptance_grade: bool,
    pub recorded: bool,
    pub uncertain: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RoleTransitionRequest {
    pub agent_id: String,
    pub from: RoleCategory,
    pub to: RoleCategory,
    pub requester_agent_id: String,
    pub parent_agent_id: String,
    pub judge_agent_id: String,
    pub judge_category: RoleCategory,
    pub judge_capability: ModelCapabilityClass,
    pub subject_capability: ModelCapabilityClass,
    pub evidence: RoleTransitionEvidence,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RoleTransitionDecision {
    pub kind: RoleTransitionKind,
    pub decision: RoleTransitionDecisionKind,
    pub agent_id: String,
    pub from: RoleCategory,
    pub to: RoleCategory,
    pub requester_agent_id: String,
    pub judge_agent_id: String,
    pub reason: String,
}

impl RoleAssignmentRecord {
    fn validate(&self) -> Result<()> {
        require_identifier("agent_id", &self.agent_id)?;
        require_identifier("legacy_role", &self.legacy_role)?;
        require_identifier("requester_agent_id", &self.requester_agent_id)?;
        require_identifier("judge_agent_id", &self.judge_agent_id)?;
        require_reason(&self.reason)?;
        Ok(())
    }
}

impl RoleTransitionRequest {
    fn validate_identifiers(&self) -> Result<()> {
        require_identifier("agent_id", &self.agent_id)?;
        require_identifier("requester_agent_id", &self.requester_agent_id)?;
        require_identifier("parent_agent_id", &self.parent_agent_id)?;
        require_identifier("judge_agent_id", &self.judge_agent_id)?;
        require_reason(&self.reason)?;
        Ok(())
    }
}

/// Derive the authority category for a plan role. An explicit override is
/// recorded; it is never inferred from a launch-time tier name.
pub fn assign_role_category(
    agent_id: impl Into<String>,
    role: AgentRole,
    category_override: Option<RoleCategory>,
) -> Result<RoleAssignmentRecord> {
    assign_role_category_with_provenance(
        agent_id,
        role,
        category_override,
        RoleAssignmentProvenance::granted_by("supervisor"),
    )
}

pub fn assign_role_category_with_provenance(
    agent_id: impl Into<String>,
    role: AgentRole,
    category_override: Option<RoleCategory>,
    provenance: RoleAssignmentProvenance,
) -> Result<RoleAssignmentRecord> {
    let derived = role.authority_category();
    let (category, source, reason, provenance) = match category_override {
        Some(requested) if requested != derived => (
            requested,
            RoleAssignmentSource::OperatorOverride,
            format!(
                "operator override from {} ({}) to {}",
                role.as_str(),
                derived.as_str(),
                requested.as_str()
            ),
            if provenance.requester_agent_id == "supervisor" {
                RoleAssignmentProvenance::operator_override()
            } else {
                provenance
            },
        ),
        _ => (
            derived,
            RoleAssignmentSource::DerivedFromPlanRole,
            format!(
                "derived from plan role {} without a launch-tier designation",
                role.as_str()
            ),
            provenance,
        ),
    };
    let record = RoleAssignmentRecord {
        agent_id: agent_id.into(),
        category,
        legacy_role: role.as_str().to_string(),
        source,
        requester_agent_id: provenance.requester_agent_id,
        judge_agent_id: provenance.judge_agent_id,
        evidence: provenance.evidence,
        decision: provenance.decision,
        reason,
    };
    record.validate()?;
    Ok(record)
}

/// Fail closed so a weak or unproven model cannot hold coordinator or auditor
/// authority at execution time.
pub fn admit_role_category(category: RoleCategory, model: Option<&str>) -> Result<()> {
    let floor = category.subject_capability_floor();
    let Some(model) = model else {
        if floor > ModelCapabilityClass::WeakMechanical {
            bail!(
                "role category '{}' requires '{}' capability evidence; refusing unproven model",
                category.as_str(),
                floor.as_str()
            );
        }
        return Ok(());
    };

    match measured_authority_eligibility(model, category.measured_authority_role()) {
        Ok(MeasuredAuthorityEligibility::Ineligible { reason }) => {
            bail!(
                "model '{model}' is ineligible by measured catalog/evidence for category '{}': {reason}",
                category.as_str()
            );
        }
        Ok(
            MeasuredAuthorityEligibility::Eligible | MeasuredAuthorityEligibility::NoDatedEvidence,
        ) => {}
        Err(error) => {
            bail!(
                "measured catalog/evidence eligibility could not be loaded for model '{model}': {error}"
            );
        }
    }

    match super::trusted_model_capability(model) {
        Some(capability) if capability < floor => {
            bail!(
                "weak model cannot hold {} authority: capability '{}' is below floor '{}'",
                category.as_str(),
                capability.as_str(),
                floor.as_str()
            );
        }
        Some(_) => Ok(()),
        None if floor > ModelCapabilityClass::WeakMechanical => {
            bail!(
                "model '{model}' has no trusted capability policy for category '{}'",
                category.as_str()
            );
        }
        None => Ok(()),
    }
}

pub fn insert_role_assignment(payload: &mut Value, record: &RoleAssignmentRecord) -> Result<()> {
    record.validate()?;
    let object = payload
        .as_object_mut()
        .context("orchestration payload must be an object to record a role assignment")?;
    object.insert(
        ROLE_ASSIGNMENT_FIELD.to_string(),
        serde_json::to_value(record).context("failed to encode role assignment")?,
    );
    Ok(())
}

pub fn collect_role_assignments(
    events: &[OrchestrationEvent],
) -> Result<Vec<RoleAssignmentRecord>> {
    let mut records = Vec::new();
    for event in events {
        let Some(value) = event.payload.get(ROLE_ASSIGNMENT_FIELD) else {
            continue;
        };
        let record: RoleAssignmentRecord = serde_json::from_value(value.clone())
            .context("role assignment payload is not a valid ledger record")?;
        record.validate()?;
        if record.agent_id != event.node {
            bail!(
                "role assignment agent_id '{}' does not match event node '{}'",
                record.agent_id,
                event.node
            );
        }
        records.push(record);
    }
    Ok(records)
}

/// Adapter-launched runtimes may only host a non-delegating terminal worker.
pub fn authorize_bounded_leaf_runtime_role(role: AgentRole) -> Result<RoleCategory> {
    let category = role.authority_category();
    if !category.is_non_delegating_terminal_worker() {
        bail!(
            "selected runtime cannot launch judgment or delegating role '{}'",
            role.as_str()
        );
    }
    Ok(category)
}

/// Fail-closed promotion/demotion gate. Promotion never passes by default.
pub fn evaluate_role_transition(request: &RoleTransitionRequest) -> Result<RoleTransitionDecision> {
    request.validate_identifiers()?;
    if request.from == request.to {
        return Ok(refuse(
            request,
            RoleTransitionKind::Promotion,
            "same-category transition is not an authority change",
        ));
    }
    let kind = transition_kind(request.from, request.to);

    if request.judge_agent_id == request.agent_id {
        return Ok(refuse(
            request,
            kind,
            "role transition cannot be self-judged",
        ));
    }
    if request.evidence.uncertain {
        return Ok(refuse(
            request,
            kind,
            "role transition fails closed on uncertain evidence",
        ));
    }
    if !request.evidence.recorded {
        return Ok(refuse(
            request,
            kind,
            "role transition requires recorded gate evidence",
        ));
    }

    match kind {
        RoleTransitionKind::Promotion => authorize_promotion(request),
        RoleTransitionKind::Demotion => authorize_demotion(request),
    }
}

fn authorize_promotion(request: &RoleTransitionRequest) -> Result<RoleTransitionDecision> {
    if request.judge_agent_id == request.requester_agent_id {
        return Ok(refuse(
            request,
            RoleTransitionKind::Promotion,
            "role transition cannot be judged by the requester",
        ));
    }
    if request.judge_agent_id == request.parent_agent_id {
        return Ok(refuse(
            request,
            RoleTransitionKind::Promotion,
            "promotion cannot be decided by the direct parent alone",
        ));
    }
    if !request.judge_category.may_judge_role_transition() {
        return Ok(refuse(
            request,
            RoleTransitionKind::Promotion,
            "promotion judge must be a read-only review-auditor",
        ));
    }
    if request.judge_capability < ModelCapabilityClass::CriticalJudgment {
        return Ok(refuse(
            request,
            RoleTransitionKind::Promotion,
            "promotion judge lacks critical-judgment capability; weak-model authority is forbidden",
        ));
    }
    if !request.evidence.acceptance_grade {
        return Ok(refuse(
            request,
            RoleTransitionKind::Promotion,
            "promotion requires acceptance-grade gate evidence",
        ));
    }
    let floor = request.to.subject_capability_floor();
    if request.subject_capability < floor {
        return Ok(refuse(
            request,
            RoleTransitionKind::Promotion,
            "subject model is below the capability floor for the target category",
        ));
    }
    Ok(grant(
        request,
        RoleTransitionKind::Promotion,
        "third-party auditor granted promotion on acceptance-grade evidence",
    ))
}

fn authorize_demotion(request: &RoleTransitionRequest) -> Result<RoleTransitionDecision> {
    let judge_is_parent = request.judge_agent_id == request.parent_agent_id;
    let judge_is_auditor = request.judge_category.may_judge_role_transition()
        && request.judge_capability >= ModelCapabilityClass::CriticalJudgment;
    if !judge_is_parent && !judge_is_auditor {
        return Ok(refuse(
            request,
            RoleTransitionKind::Demotion,
            "demotion judge must be the parent coordinator or a critical-judgment auditor",
        ));
    }
    if judge_is_parent && !request.judge_category.may_delegate() {
        return Ok(refuse(
            request,
            RoleTransitionKind::Demotion,
            "parent demotion judge must currently hold coordinator authority",
        ));
    }
    Ok(grant(
        request,
        RoleTransitionKind::Demotion,
        "demotion granted after recorded third-party or parent judgment",
    ))
}

fn transition_kind(from: RoleCategory, to: RoleCategory) -> RoleTransitionKind {
    let gained = to.authority_bits() & !from.authority_bits();
    if gained != 0 {
        RoleTransitionKind::Promotion
    } else {
        RoleTransitionKind::Demotion
    }
}

fn grant(
    request: &RoleTransitionRequest,
    kind: RoleTransitionKind,
    reason: &str,
) -> RoleTransitionDecision {
    RoleTransitionDecision {
        kind,
        decision: RoleTransitionDecisionKind::Granted,
        agent_id: request.agent_id.clone(),
        from: request.from,
        to: request.to,
        requester_agent_id: request.requester_agent_id.clone(),
        judge_agent_id: request.judge_agent_id.clone(),
        reason: reason.to_string(),
    }
}

fn refuse(
    request: &RoleTransitionRequest,
    kind: RoleTransitionKind,
    reason: &str,
) -> RoleTransitionDecision {
    RoleTransitionDecision {
        kind,
        decision: RoleTransitionDecisionKind::Refused,
        agent_id: request.agent_id.clone(),
        from: request.from,
        to: request.to,
        requester_agent_id: request.requester_agent_id.clone(),
        judge_agent_id: request.judge_agent_id.clone(),
        reason: reason.to_string(),
    }
}

fn require_identifier(field: &str, value: &str) -> Result<()> {
    if value.is_empty() || value != value.trim() {
        bail!("{field} must be a non-empty trimmed identifier");
    }
    Ok(())
}

fn require_reason(reason: &str) -> Result<()> {
    if reason.is_empty() || reason != reason.trim() {
        bail!("role authority reason must be a non-empty trimmed string");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn promotion_request() -> RoleTransitionRequest {
        RoleTransitionRequest {
            agent_id: "worker-a".into(),
            from: RoleCategory::NonDelegatingTerminalWorker,
            to: RoleCategory::DelegatingCoordinator,
            requester_agent_id: "parent-o1".into(),
            parent_agent_id: "parent-o1".into(),
            judge_agent_id: "auditor-1".into(),
            judge_category: RoleCategory::ReadOnlyReviewAuditor,
            judge_capability: ModelCapabilityClass::CriticalJudgment,
            subject_capability: ModelCapabilityClass::GeneralJudgment,
            evidence: RoleTransitionEvidence {
                acceptance_grade: true,
                recorded: true,
                uncertain: false,
            },
            reason: "task graph needs another coordination layer".into(),
        }
    }

    #[test]
    fn plan_roles_map_onto_the_four_authority_categories() {
        assert_eq!(
            AgentRole::Supervisor.authority_category(),
            RoleCategory::DelegatingCoordinator
        );
        assert_eq!(
            AgentRole::ChildOrchestrator.authority_category(),
            RoleCategory::DelegatingCoordinator
        );
        assert_eq!(
            AgentRole::Worker.authority_category(),
            RoleCategory::NonDelegatingTerminalWorker
        );
        assert_eq!(
            AgentRole::GateClassifier.authority_category(),
            RoleCategory::ReadOnlyReviewAuditor
        );
        assert_eq!(
            AgentRole::Auditor.authority_category(),
            RoleCategory::ReadOnlyReviewAuditor
        );
        assert!(RoleCategory::DelegatingCoordinator.may_delegate());
        assert!(RoleCategory::DelegatingCoordinator.may_write());
        assert!(!RoleCategory::DelegatingCoordinator.may_judge_acceptance());
        assert!(!RoleCategory::NonDelegatingTerminalWorker.may_delegate());
        assert!(RoleCategory::NonDelegatingTerminalWorker.may_write());
        assert!(!RoleCategory::ReadOnlyResearcher.may_write());
        assert!(!RoleCategory::ReadOnlyResearcher.may_delegate());
        assert!(RoleCategory::ReadOnlyReviewAuditor.is_read_only());
        assert!(RoleCategory::ReadOnlyReviewAuditor.may_judge_role_transition());
    }

    #[test]
    fn launch_without_tier_designation_derives_category_from_the_plan_role() -> Result<()> {
        let record = assign_role_category("child-1", AgentRole::ChildOrchestrator, None)?;
        assert_eq!(record.category, RoleCategory::DelegatingCoordinator);
        assert_eq!(record.source, RoleAssignmentSource::DerivedFromPlanRole);
        assert!(record.reason.contains("without a launch-tier designation"));
        assert_eq!(record.legacy_role, "child_orchestrator");
        assert_eq!(record.requester_agent_id, "supervisor");
        assert_eq!(record.judge_agent_id, "supervisor");
        assert_eq!(record.decision, RoleTransitionDecisionKind::Granted);
        assert!(record.evidence.recorded);
        Ok(())
    }

    #[test]
    fn role_assignment_round_trips_through_an_orchestration_payload() -> Result<()> {
        let record = assign_role_category("child-1", AgentRole::ChildOrchestrator, None)?;
        let mut payload = serde_json::json!({"attempt": 1});
        insert_role_assignment(&mut payload, &record)?;
        let event = crate::orchestration_event::OrchestrationEvent {
            ts: "2026-08-22T00:00:00Z".into(),
            repo: "repo".into(),
            run: "run-1".into(),
            node: "child-1".into(),
            parent: Some("run-1".into()),
            role: crate::orchestration_event::OrchestrationRole::Orchestrator,
            kind: crate::orchestration_event::OrchestrationEventKind::Spawn,
            payload,
        };
        let collected = collect_role_assignments(&[event])?;
        assert_eq!(collected, vec![record]);
        assert_eq!(
            collected[0].source,
            RoleAssignmentSource::DerivedFromPlanRole
        );
        assert!(collected[0]
            .reason
            .contains("without a launch-tier designation"));
        Ok(())
    }

    #[test]
    fn operator_override_is_recorded_and_does_not_become_the_silent_default() -> Result<()> {
        let record = assign_role_category(
            "worker-1",
            AgentRole::Worker,
            Some(RoleCategory::ReadOnlyResearcher),
        )?;
        assert_eq!(record.category, RoleCategory::ReadOnlyResearcher);
        assert_eq!(record.source, RoleAssignmentSource::OperatorOverride);
        assert!(record.reason.contains("operator override"));
        assert_eq!(record.requester_agent_id, "operator");
        assert_eq!(record.judge_agent_id, "operator");
        assert_eq!(record.decision, RoleTransitionDecisionKind::Granted);
        assert!(record.evidence.recorded);
        assert!(!record.evidence.uncertain);
        Ok(())
    }

    #[test]
    fn spawn_records_bind_requester_judge_typed_evidence_decision_and_reason() -> Result<()> {
        let record = assign_role_category_with_provenance(
            "child-1",
            AgentRole::ChildOrchestrator,
            None,
            RoleAssignmentProvenance::granted_by("run-1"),
        )?;
        assert_eq!(record.requester_agent_id, "run-1");
        assert_eq!(record.judge_agent_id, "run-1");
        assert_eq!(record.decision, RoleTransitionDecisionKind::Granted);
        assert_eq!(
            record.evidence,
            RoleTransitionEvidence {
                acceptance_grade: false,
                recorded: true,
                uncertain: false,
            }
        );
        assert!(record.reason.contains("derived from plan role"));
        Ok(())
    }

    #[test]
    fn admission_refuses_luna_for_coordinator_and_auditor_categories() -> Result<()> {
        let coordinator =
            admit_role_category(RoleCategory::DelegatingCoordinator, Some("gpt-5.6-luna"))
                .expect_err("luna cannot hold coordinator authority");
        assert!(
            coordinator
                .to_string()
                .contains("ineligible by measured catalog/evidence")
                || coordinator.to_string().contains("cannot hold"),
            "{coordinator:#}"
        );
        let auditor =
            admit_role_category(RoleCategory::ReadOnlyReviewAuditor, Some("gpt-5.6-luna"))
                .expect_err("luna cannot hold auditor authority");
        assert!(
            auditor
                .to_string()
                .contains("ineligible by measured catalog/evidence")
                || auditor.to_string().contains("cannot hold")
                || auditor.to_string().contains("below floor"),
            "{auditor:#}"
        );
        admit_role_category(
            RoleCategory::NonDelegatingTerminalWorker,
            Some("gpt-5.6-luna"),
        )?;
        admit_role_category(RoleCategory::DelegatingCoordinator, Some("gpt-5.6-sol"))?;
        admit_role_category(RoleCategory::ReadOnlyReviewAuditor, Some("gpt-5.6-sol"))?;
        Ok(())
    }

    #[test]
    fn adapter_runtimes_refuse_judgment_and_delegating_categories() {
        authorize_bounded_leaf_runtime_role(AgentRole::Worker).expect("worker leaf");
        let child = authorize_bounded_leaf_runtime_role(AgentRole::ChildOrchestrator)
            .expect_err("child orchestrator");
        assert!(child
            .to_string()
            .contains("cannot launch judgment or delegating role"));
        let auditor = authorize_bounded_leaf_runtime_role(AgentRole::Auditor).expect_err("auditor");
        assert!(auditor
            .to_string()
            .contains("cannot launch judgment or delegating role"));
    }

    #[test]
    fn promotion_without_acceptance_grade_evidence_is_refused_and_recorded() -> Result<()> {
        let mut request = promotion_request();
        request.evidence.acceptance_grade = false;
        let decision = evaluate_role_transition(&request)?;
        assert_eq!(decision.decision, RoleTransitionDecisionKind::Refused);
        assert_eq!(decision.kind, RoleTransitionKind::Promotion);
        assert!(decision.reason.contains("acceptance-grade"));
        assert_eq!(decision.judge_agent_id, "auditor-1");
        Ok(())
    }

    #[test]
    fn granted_promotion_records_the_third_party_judge() -> Result<()> {
        let decision = evaluate_role_transition(&promotion_request())?;
        assert_eq!(decision.decision, RoleTransitionDecisionKind::Granted);
        assert_eq!(decision.judge_agent_id, "auditor-1");
        assert_ne!(decision.judge_agent_id, decision.requester_agent_id);
        assert_ne!(decision.judge_agent_id, decision.agent_id);
        Ok(())
    }

    #[test]
    fn parent_alone_cannot_promote_and_self_judgment_fails_closed() -> Result<()> {
        let mut parent = promotion_request();
        parent.judge_agent_id = parent.parent_agent_id.clone();
        parent.requester_agent_id = "other-req".into();
        let decision = evaluate_role_transition(&parent)?;
        assert_eq!(decision.decision, RoleTransitionDecisionKind::Refused);
        assert!(decision.reason.contains("direct parent"));

        let mut self_judge = promotion_request();
        self_judge.judge_agent_id = self_judge.agent_id.clone();
        let decision = evaluate_role_transition(&self_judge)?;
        assert_eq!(decision.decision, RoleTransitionDecisionKind::Refused);
        assert!(decision.reason.contains("self-judged"));
        Ok(())
    }

    #[test]
    fn weak_model_cannot_judge_or_receive_coordinator_promotion() -> Result<()> {
        let mut weak_judge = promotion_request();
        weak_judge.judge_capability = ModelCapabilityClass::GeneralJudgment;
        let decision = evaluate_role_transition(&weak_judge)?;
        assert_eq!(decision.decision, RoleTransitionDecisionKind::Refused);
        assert!(decision.reason.contains("weak-model"));

        let mut weak_subject = promotion_request();
        weak_subject.subject_capability = ModelCapabilityClass::WeakMechanical;
        let decision = evaluate_role_transition(&weak_subject)?;
        assert_eq!(decision.decision, RoleTransitionDecisionKind::Refused);
        assert!(decision.reason.contains("capability floor"));
        Ok(())
    }

    #[test]
    fn uncertain_or_unrecorded_evidence_fails_closed_by_default() -> Result<()> {
        let mut uncertain = promotion_request();
        uncertain.evidence.uncertain = true;
        let decision = evaluate_role_transition(&uncertain)?;
        assert_eq!(decision.decision, RoleTransitionDecisionKind::Refused);
        assert!(decision.reason.contains("uncertain"));

        let mut missing = promotion_request();
        missing.evidence.recorded = false;
        let decision = evaluate_role_transition(&missing)?;
        assert_eq!(decision.decision, RoleTransitionDecisionKind::Refused);
        assert!(decision.reason.contains("recorded"));
        Ok(())
    }

    #[test]
    fn demotion_is_cheaper_but_still_recorded_and_not_self_granted() -> Result<()> {
        let request = RoleTransitionRequest {
            agent_id: "coord-a".into(),
            from: RoleCategory::DelegatingCoordinator,
            to: RoleCategory::NonDelegatingTerminalWorker,
            requester_agent_id: "o2".into(),
            parent_agent_id: "o2".into(),
            judge_agent_id: "o2".into(),
            judge_category: RoleCategory::DelegatingCoordinator,
            judge_capability: ModelCapabilityClass::GeneralJudgment,
            subject_capability: ModelCapabilityClass::GeneralJudgment,
            evidence: RoleTransitionEvidence {
                acceptance_grade: false,
                recorded: true,
                uncertain: false,
            },
            reason: "scope collapsed to a single leaf".into(),
        };
        let decision = evaluate_role_transition(&request)?;
        assert_eq!(decision.kind, RoleTransitionKind::Demotion);
        assert_eq!(decision.decision, RoleTransitionDecisionKind::Granted);

        let mut self_demote = request;
        self_demote.judge_agent_id = self_demote.agent_id.clone();
        let decision = evaluate_role_transition(&self_demote)?;
        assert_eq!(decision.decision, RoleTransitionDecisionKind::Refused);
        Ok(())
    }

    #[test]
    fn write_grant_and_judgment_grant_are_promotions() -> Result<()> {
        let mut request = promotion_request();
        request.from = RoleCategory::ReadOnlyResearcher;
        request.to = RoleCategory::NonDelegatingTerminalWorker;
        request.subject_capability = ModelCapabilityClass::WeakMechanical;
        let decision = evaluate_role_transition(&request)?;
        assert_eq!(decision.kind, RoleTransitionKind::Promotion);
        assert_eq!(decision.decision, RoleTransitionDecisionKind::Granted);

        request.to = RoleCategory::ReadOnlyReviewAuditor;
        request.subject_capability = ModelCapabilityClass::CriticalJudgment;
        let decision = evaluate_role_transition(&request)?;
        assert_eq!(decision.kind, RoleTransitionKind::Promotion);
        assert_eq!(decision.decision, RoleTransitionDecisionKind::Granted);
        Ok(())
    }
}
