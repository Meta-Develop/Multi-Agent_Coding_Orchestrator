//! Authoritative hierarchy ledger records for supervision edges and
//! acceptance-gate ownership (#222).
//!
//! These records live in the existing orchestration-event payload so the
//! Scope stream and post-run journal remain the source of truth. Post-hoc
//! parent inference in `scope::normalize` stays only as a fallback for older
//! runs that lack these payloads.
//!
//! #221 note: this module records the four authority *categories* as ledger
//! labels mapped from the existing `AgentRole` / `OrchestrationRole` values.
//! Observed coordination depth is derived from parent links (depth as output).
//! Assignment-time role provenance stays in `supervise::role_authority`.
//! Promotion and demotion are executed by `supervise::role_transition` and
//! stored here as `RoleTransitionRecord` payloads. This module does not
//! select roles or drive the optimizer.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::orchestration_event::{OrchestrationEvent, OrchestrationRole};

pub const SUPERVISION_EDGE_FIELD: &str = "supervision_edge";
pub const GATE_OWNERSHIP_FIELD: &str = "gate_ownership";
pub const ROLE_TRANSITION_FIELD: &str = "role_transition";

/// Ledger-only authority category. Not a replacement for `AgentRole`.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
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

    pub fn from_orchestration_role(role: OrchestrationRole) -> Self {
        match role {
            OrchestrationRole::Root
            | OrchestrationRole::Supervisor
            | OrchestrationRole::Orchestrator => Self::DelegatingCoordinator,
            OrchestrationRole::Worker => Self::NonDelegatingTerminalWorker,
            OrchestrationRole::Auditor => Self::ReadOnlyReviewAuditor,
        }
    }

    pub fn from_legacy_role(role: &str) -> Result<Self> {
        match role {
            "supervisor" | "child_orchestrator" | "orchestrator" | "root" => {
                Ok(Self::DelegatingCoordinator)
            }
            "worker" => Ok(Self::NonDelegatingTerminalWorker),
            "researcher" => Ok(Self::ReadOnlyResearcher),
            "auditor" | "gate_classifier" => Ok(Self::ReadOnlyReviewAuditor),
            other => bail!("unrecognized legacy role {other:?} for hierarchy ledger category"),
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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SupervisionEdgeRecord {
    pub child_agent_id: String,
    pub parent_agent_id: String,
    pub role_category: RoleCategory,
    pub legacy_role: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub write_boundary: Vec<String>,
    pub scope_ref: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GateOwnershipAction {
    Assign,
    Transfer,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GateOwnershipRecord {
    pub action: GateOwnershipAction,
    pub task_id: String,
    pub owner_agent_id: String,
    pub owner_role_category: RoleCategory,
    pub owner_legacy_role: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_owner_agent_id: Option<String>,
    pub reason: String,
}

/// Promotion or demotion decision emitted by `supervise::role_transition`.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RoleTransitionDecision {
    Granted,
    Refused,
}

/// Typed gate evidence retained with a promotion or demotion decision.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RoleTransitionEvidenceRecord {
    pub acceptance_grade: bool,
    pub recorded: bool,
    pub uncertain: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RoleTransitionRecord {
    pub agent_id: String,
    pub from_category: RoleCategory,
    pub to_category: RoleCategory,
    pub requester_agent_id: String,
    pub judge_agent_id: String,
    #[serde(default)]
    pub evidence: RoleTransitionEvidenceRecord,
    pub decision: RoleTransitionDecision,
    pub reason: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct HierarchyLedgerSnapshot {
    pub edges: BTreeMap<String, SupervisionEdgeRecord>,
    pub effective_categories: BTreeMap<String, RoleCategory>,
    pub gate_owners: BTreeMap<String, GateOwnershipRecord>,
    pub gate_history: Vec<GateOwnershipRecord>,
    pub role_transitions: Vec<RoleTransitionRecord>,
}

impl SupervisionEdgeRecord {
    pub fn new(
        child_agent_id: impl Into<String>,
        parent_agent_id: impl Into<String>,
        role: OrchestrationRole,
        legacy_role: impl Into<String>,
        write_boundary: Vec<String>,
        scope_ref: impl Into<String>,
    ) -> Result<Self> {
        let record = Self {
            child_agent_id: child_agent_id.into(),
            parent_agent_id: parent_agent_id.into(),
            role_category: RoleCategory::from_orchestration_role(role),
            legacy_role: legacy_role.into(),
            write_boundary,
            scope_ref: scope_ref.into(),
        };
        record.validate()?;
        Ok(record)
    }

    fn validate(&self) -> Result<()> {
        require_identifier("child_agent_id", &self.child_agent_id)?;
        require_identifier("parent_agent_id", &self.parent_agent_id)?;
        require_identifier("legacy_role", &self.legacy_role)?;
        require_identifier("scope_ref", &self.scope_ref)?;
        if self.child_agent_id == self.parent_agent_id {
            bail!("supervision edge cannot make an agent its own parent");
        }
        Ok(())
    }
}

impl GateOwnershipRecord {
    pub fn assign(
        task_id: impl Into<String>,
        owner_agent_id: impl Into<String>,
        owner_role: OrchestrationRole,
        owner_legacy_role: impl Into<String>,
        reason: impl Into<String>,
    ) -> Result<Self> {
        let record = Self {
            action: GateOwnershipAction::Assign,
            task_id: task_id.into(),
            owner_agent_id: owner_agent_id.into(),
            owner_role_category: RoleCategory::from_orchestration_role(owner_role),
            owner_legacy_role: owner_legacy_role.into(),
            previous_owner_agent_id: None,
            reason: reason.into(),
        };
        record.validate()?;
        Ok(record)
    }

    pub fn transfer(
        task_id: impl Into<String>,
        owner_agent_id: impl Into<String>,
        owner_role: OrchestrationRole,
        owner_legacy_role: impl Into<String>,
        previous_owner_agent_id: impl Into<String>,
        reason: impl Into<String>,
    ) -> Result<Self> {
        let record = Self {
            action: GateOwnershipAction::Transfer,
            task_id: task_id.into(),
            owner_agent_id: owner_agent_id.into(),
            owner_role_category: RoleCategory::from_orchestration_role(owner_role),
            owner_legacy_role: owner_legacy_role.into(),
            previous_owner_agent_id: Some(previous_owner_agent_id.into()),
            reason: reason.into(),
        };
        record.validate()?;
        Ok(record)
    }

    fn validate(&self) -> Result<()> {
        require_identifier("task_id", &self.task_id)?;
        require_identifier("owner_agent_id", &self.owner_agent_id)?;
        require_identifier("owner_legacy_role", &self.owner_legacy_role)?;
        require_reason(&self.reason)?;
        match self.action {
            GateOwnershipAction::Assign => {
                if self.previous_owner_agent_id.is_some() {
                    bail!("gate-ownership assign cannot carry a previous owner");
                }
            }
            GateOwnershipAction::Transfer => {
                let previous = self
                    .previous_owner_agent_id
                    .as_deref()
                    .context("gate-ownership transfer requires previous_owner_agent_id")?;
                require_identifier("previous_owner_agent_id", previous)?;
                if previous == self.owner_agent_id {
                    bail!("gate-ownership transfer must change owner");
                }
            }
        }
        Ok(())
    }
}

impl RoleTransitionRecord {
    pub fn validate(&self) -> Result<()> {
        require_identifier("agent_id", &self.agent_id)?;
        require_identifier("requester_agent_id", &self.requester_agent_id)?;
        require_identifier("judge_agent_id", &self.judge_agent_id)?;
        require_reason(&self.reason)?;
        if self.decision == RoleTransitionDecision::Granted {
            if !self.evidence.recorded || self.evidence.uncertain {
                bail!("granted role transition requires recorded certain evidence");
            }
            let gained_authority =
                self.to_category.authority_bits() & !self.from_category.authority_bits();
            if gained_authority != 0 && !self.evidence.acceptance_grade {
                bail!("granted role promotion requires acceptance-grade evidence");
            }
        }
        if self.agent_id == self.judge_agent_id && self.decision == RoleTransitionDecision::Granted
        {
            bail!("role transition cannot be self-judged");
        }
        if self.from_category == self.to_category {
            bail!("role transition must change category");
        }
        Ok(())
    }
}

pub fn insert_supervision_edge(payload: &mut Value, edge: &SupervisionEdgeRecord) -> Result<()> {
    edge.validate()?;
    let object = payload
        .as_object_mut()
        .context("orchestration payload must be an object to record a supervision edge")?;
    object.insert(
        SUPERVISION_EDGE_FIELD.to_string(),
        serde_json::to_value(edge).context("failed to encode supervision edge")?,
    );
    Ok(())
}

pub fn gate_ownership_payload(record: &GateOwnershipRecord) -> Result<Value> {
    record.validate()?;
    Ok(json!({
        GATE_OWNERSHIP_FIELD: record,
    }))
}

pub fn role_transition_payload(record: &RoleTransitionRecord) -> Result<Value> {
    record.validate()?;
    Ok(json!({
        ROLE_TRANSITION_FIELD: record,
    }))
}

pub fn reconstruct_hierarchy_ledger(
    events: &[OrchestrationEvent],
) -> Result<HierarchyLedgerSnapshot> {
    let mut snapshot = HierarchyLedgerSnapshot::default();
    let mut granted_changes = BTreeSet::new();
    for event in events {
        if let Some(value) = event.payload.get(SUPERVISION_EDGE_FIELD) {
            let edge: SupervisionEdgeRecord = serde_json::from_value(value.clone())
                .context("supervision edge payload is not a valid ledger record")?;
            edge.validate()?;
            if edge.child_agent_id != event.node {
                bail!(
                    "supervision edge child_agent_id '{}' does not match event node '{}'",
                    edge.child_agent_id,
                    event.node
                );
            }
            if event.parent.as_deref() != Some(edge.parent_agent_id.as_str()) {
                bail!(
                    "supervision edge parent_agent_id '{}' does not match event parent {:?}",
                    edge.parent_agent_id,
                    event.parent
                );
            }
            if let Some(current) = snapshot
                .effective_categories
                .get(&edge.child_agent_id)
                .copied()
            {
                if current != edge.role_category {
                    bail!(
                        "supervision edge for agent '{}' conflicts with effective category '{}'",
                        edge.child_agent_id,
                        current.as_str()
                    );
                }
            } else {
                snapshot
                    .effective_categories
                    .insert(edge.child_agent_id.clone(), edge.role_category);
            }
            snapshot.edges.insert(edge.child_agent_id.clone(), edge);
        }
        if let Some(value) = event.payload.get(GATE_OWNERSHIP_FIELD) {
            let record: GateOwnershipRecord = serde_json::from_value(value.clone())
                .context("gate-ownership payload is not a valid ledger record")?;
            record.validate()?;
            apply_gate_ownership(&mut snapshot, record)?;
        }
        if let Some(value) = event.payload.get(ROLE_TRANSITION_FIELD) {
            let record: RoleTransitionRecord = serde_json::from_value(value.clone())
                .context("role-transition payload is not a valid ledger record")?;
            record.validate()?;
            apply_role_transition(&mut snapshot, &mut granted_changes, record)?;
        }
    }
    Ok(snapshot)
}

fn apply_role_transition(
    snapshot: &mut HierarchyLedgerSnapshot,
    granted_changes: &mut BTreeSet<String>,
    record: RoleTransitionRecord,
) -> Result<()> {
    let current = snapshot.effective_categories.get(&record.agent_id).copied();
    let next = match (current, record.decision) {
        (None, RoleTransitionDecision::Granted) => {
            granted_changes.insert(record.agent_id.clone());
            record.to_category
        }
        (None, RoleTransitionDecision::Refused) => record.from_category,
        (Some(current), RoleTransitionDecision::Granted) if current == record.from_category => {
            granted_changes.insert(record.agent_id.clone());
            record.to_category
        }
        (Some(current), RoleTransitionDecision::Granted)
            if current == record.to_category && !granted_changes.contains(&record.agent_id) =>
        {
            // Spawn already recorded the destination category. Keep the
            // journaled grant as evidence instead of treating the launch
            // role as a stale transition source.
            granted_changes.insert(record.agent_id.clone());
            current
        }
        (Some(current), RoleTransitionDecision::Refused) => current,
        (Some(current), RoleTransitionDecision::Granted) => {
            bail!(
                "role transition for agent '{}' expected effective category '{}', found stale from_category '{}'",
                record.agent_id,
                current.as_str(),
                record.from_category.as_str()
            );
        }
    };
    snapshot
        .effective_categories
        .insert(record.agent_id.clone(), next);
    snapshot.role_transitions.push(record);
    Ok(())
}

fn apply_gate_ownership(
    snapshot: &mut HierarchyLedgerSnapshot,
    record: GateOwnershipRecord,
) -> Result<()> {
    match record.action {
        GateOwnershipAction::Assign => {
            snapshot
                .gate_owners
                .insert(record.task_id.clone(), record.clone());
        }
        GateOwnershipAction::Transfer => {
            let previous = record
                .previous_owner_agent_id
                .as_deref()
                .context("gate-ownership transfer omitted previous owner")?;
            match snapshot.gate_owners.get(&record.task_id) {
                Some(current) if current.owner_agent_id == previous => {}
                Some(current) => bail!(
                    "gate-ownership transfer for task '{}' expected previous owner '{}', found '{}'",
                    record.task_id,
                    previous,
                    current.owner_agent_id
                ),
                None => bail!(
                    "gate-ownership transfer for task '{}' has no prior assignment",
                    record.task_id
                ),
            }
            snapshot
                .gate_owners
                .insert(record.task_id.clone(), record.clone());
        }
    }
    snapshot.gate_history.push(record);
    Ok(())
}

/// One node in an observed parent/child graph.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObservedHierarchyNode<'a> {
    pub id: &'a str,
    pub parent: Option<&'a str>,
    pub coordinator: bool,
}

/// Depth derived from parent links. Coordination depth is a layer count.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ObservedHierarchy {
    pub depths: BTreeMap<String, u32>,
    pub coordination_depth: u32,
}

/// Labels that count as delegating coordinators when only a role string is known.
pub fn is_coordinator_role_label(role: &str) -> bool {
    matches!(
        role,
        "supervisor" | "child_orchestrator" | "orchestrator" | "root"
    )
}

pub fn orchestration_role_is_coordinator(role: OrchestrationRole) -> bool {
    matches!(
        role,
        OrchestrationRole::Root | OrchestrationRole::Supervisor | OrchestrationRole::Orchestrator
    )
}

/// Compute per-node depth and the observed coordination-layer count.
///
/// Roots (no parent, or a parent outside the set) sit at depth 0. An unseen
/// parent still counts as one ancestor, so a listed child of a missing parent
/// is depth 1. Coordination depth is the number of coordinator layers
/// (`max(coordinator depth) + 1`). If the graph has no coordinators, the same
/// layer-count rule is applied to every node so a flat worker list still
/// reports its observed shape instead of a fixed two-tier label.
pub fn observe_hierarchy<'a, I>(nodes: I) -> ObservedHierarchy
where
    I: IntoIterator<Item = ObservedHierarchyNode<'a>>,
{
    let entries = nodes
        .into_iter()
        .map(|node| {
            (
                node.id.to_string(),
                node.parent.map(str::to_string),
                node.coordinator,
            )
        })
        .collect::<Vec<_>>();
    let parents = entries
        .iter()
        .map(|(id, parent, _)| (id.clone(), parent.clone()))
        .collect::<BTreeMap<_, _>>();
    let mut depths = BTreeMap::new();
    for id in parents.keys() {
        let _ = depth_of(id, &parents, &mut depths, &mut BTreeSet::new());
    }
    let coordinator_ids = entries
        .iter()
        .filter(|(_, _, coordinator)| *coordinator)
        .map(|(id, _, _)| id.as_str())
        .collect::<BTreeSet<_>>();
    let max = depths
        .iter()
        .filter(|(id, _)| coordinator_ids.is_empty() || coordinator_ids.contains(id.as_str()))
        .map(|(_, depth)| *depth)
        .max();
    ObservedHierarchy {
        depths,
        coordination_depth: max.map(|depth| depth.saturating_add(1)).unwrap_or(0),
    }
}

fn depth_of(
    id: &str,
    parents: &BTreeMap<String, Option<String>>,
    depths: &mut BTreeMap<String, u32>,
    visiting: &mut BTreeSet<String>,
) -> u32 {
    if let Some(depth) = depths.get(id) {
        return *depth;
    }
    if !visiting.insert(id.to_string()) {
        depths.insert(id.to_string(), 0);
        return 0;
    }
    let depth = match parents.get(id).and_then(Option::as_deref) {
        None => 0,
        Some(parent) if !parents.contains_key(parent) => 1,
        Some(parent) => depth_of(parent, parents, depths, visiting).saturating_add(1),
    };
    visiting.remove(id);
    depths.insert(id.to_string(), depth);
    depth
}

fn require_identifier(field: &str, value: &str) -> Result<()> {
    if value.is_empty() || value != value.trim() {
        bail!("{field} must be a non-empty canonical identifier");
    }
    if value.len() > 256 {
        bail!("{field} exceeds its 256-byte identifier limit");
    }
    if !value.chars().all(|character| {
        character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.' | ':')
    }) {
        bail!("{field} may only contain ASCII letters, digits, '.', '_', '-', and ':'");
    }
    Ok(())
}

fn require_reason(reason: &str) -> Result<()> {
    if reason.is_empty() || reason != reason.trim() {
        bail!("hierarchy ledger reason must be a non-empty canonical token");
    }
    if reason.len() > 256 {
        bail!("hierarchy ledger reason exceeds its 256-byte limit");
    }
    if !reason
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.'))
    {
        bail!("hierarchy ledger reason may only contain ASCII letters, digits, '.', '_', and '-'");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::orchestration_event::{OrchestrationEventKind, OrchestrationRole};

    fn event(
        node: &str,
        parent: Option<&str>,
        role: OrchestrationRole,
        kind: OrchestrationEventKind,
        payload: Value,
    ) -> OrchestrationEvent {
        OrchestrationEvent {
            ts: "2026-08-21T00:00:00Z".to_string(),
            repo: "repo-id".to_string(),
            run: "run-1".to_string(),
            node: node.to_string(),
            parent: parent.map(str::to_owned),
            role,
            kind,
            payload,
        }
    }

    fn fixture_events() -> Result<Vec<OrchestrationEvent>> {
        let child_edge = SupervisionEdgeRecord::new(
            "child-a",
            "run-1",
            OrchestrationRole::Orchestrator,
            "child_orchestrator",
            vec!["src/lib.rs".to_string()],
            "assignment:child-a",
        )?;
        let mut spawn_payload = json!({"attempt": 1, "corrective_retry": false});
        insert_supervision_edge(&mut spawn_payload, &child_edge)?;
        let assigned = GateOwnershipRecord::assign(
            "child-a",
            "run-1",
            OrchestrationRole::Supervisor,
            "supervisor",
            "initial_parent_gate",
        )?;
        let transferred = GateOwnershipRecord::transfer(
            "child-a",
            "parent-auditor",
            OrchestrationRole::Auditor,
            "auditor",
            "run-1",
            "parent_enforced_acceptance_gate",
        )?;
        let refused = RoleTransitionRecord {
            agent_id: "child-a".to_string(),
            from_category: RoleCategory::DelegatingCoordinator,
            to_category: RoleCategory::NonDelegatingTerminalWorker,
            requester_agent_id: "run-1".to_string(),
            judge_agent_id: "third-party-judge".to_string(),
            evidence: RoleTransitionEvidenceRecord {
                acceptance_grade: false,
                recorded: true,
                uncertain: false,
            },
            decision: RoleTransitionDecision::Refused,
            reason: "insufficient_gate_evidence".to_string(),
        };
        refused.validate()?;
        Ok(vec![
            event(
                "child-a",
                Some("run-1"),
                OrchestrationRole::Orchestrator,
                OrchestrationEventKind::Spawn,
                spawn_payload,
            ),
            event(
                "run-1",
                None,
                OrchestrationRole::Supervisor,
                OrchestrationEventKind::Gate,
                gate_ownership_payload(&assigned)?,
            ),
            event(
                "parent-auditor",
                Some("run-1"),
                OrchestrationRole::Auditor,
                OrchestrationEventKind::Gate,
                gate_ownership_payload(&transferred)?,
            ),
            event(
                "child-a",
                Some("run-1"),
                OrchestrationRole::Orchestrator,
                OrchestrationEventKind::Journal,
                role_transition_payload(&refused)?,
            ),
        ])
    }

    #[test]
    fn fixture_reconstructs_spawn_gate_assignment_transfer_and_role_transition() -> Result<()> {
        let snapshot = reconstruct_hierarchy_ledger(&fixture_events()?)?;
        let edge = snapshot.edges.get("child-a").context("child edge")?;
        assert_eq!(edge.parent_agent_id, "run-1");
        assert_eq!(edge.role_category, RoleCategory::DelegatingCoordinator);
        assert_eq!(edge.legacy_role, "child_orchestrator");
        assert_eq!(edge.write_boundary, vec!["src/lib.rs".to_string()]);
        assert_eq!(edge.scope_ref, "assignment:child-a");

        assert_eq!(snapshot.gate_history.len(), 2);
        assert_eq!(snapshot.gate_history[0].action, GateOwnershipAction::Assign);
        assert_eq!(
            snapshot.gate_history[1].action,
            GateOwnershipAction::Transfer
        );
        let owner = snapshot
            .gate_owners
            .get("child-a")
            .context("latest gate owner")?;
        assert_eq!(owner.owner_agent_id, "parent-auditor");
        assert_eq!(owner.previous_owner_agent_id.as_deref(), Some("run-1"));
        assert_eq!(owner.reason, "parent_enforced_acceptance_gate");

        assert_eq!(snapshot.role_transitions.len(), 1);
        assert_eq!(
            snapshot.role_transitions[0].decision,
            RoleTransitionDecision::Refused
        );
        Ok(())
    }

    #[test]
    fn transfer_without_matching_prior_assignment_fails_closed() -> Result<()> {
        let transferred = GateOwnershipRecord::transfer(
            "child-a",
            "parent-auditor",
            OrchestrationRole::Auditor,
            "auditor",
            "run-1",
            "parent_enforced_acceptance_gate",
        )?;
        let error = reconstruct_hierarchy_ledger(&[event(
            "parent-auditor",
            Some("run-1"),
            OrchestrationRole::Auditor,
            OrchestrationEventKind::Gate,
            gate_ownership_payload(&transferred)?,
        )])
        .expect_err("transfer without assign must fail");
        assert!(error.to_string().contains("no prior assignment"));
        Ok(())
    }

    #[test]
    fn supervision_edge_must_agree_with_event_parent() -> Result<()> {
        let edge = SupervisionEdgeRecord::new(
            "child-a",
            "run-1",
            OrchestrationRole::Orchestrator,
            "child_orchestrator",
            Vec::new(),
            "assignment:child-a",
        )?;
        let mut payload = json!({});
        insert_supervision_edge(&mut payload, &edge)?;
        let error = reconstruct_hierarchy_ledger(&[event(
            "child-a",
            Some("other-parent"),
            OrchestrationRole::Orchestrator,
            OrchestrationEventKind::Spawn,
            payload,
        )])
        .expect_err("mismatched parent must fail");
        assert!(error.to_string().contains("does not match event parent"));
        Ok(())
    }

    #[test]
    fn observed_hierarchy_reports_flat_and_three_layer_coordination_as_output() {
        let flat = observe_hierarchy([ObservedHierarchyNode {
            id: "run-1",
            parent: None,
            coordinator: true,
        }]);
        assert_eq!(flat.depths.get("run-1").copied(), Some(0));
        assert_eq!(flat.coordination_depth, 1);

        let three = observe_hierarchy([
            ObservedHierarchyNode {
                id: "o2",
                parent: None,
                coordinator: true,
            },
            ObservedHierarchyNode {
                id: "o1-a",
                parent: Some("o2"),
                coordinator: true,
            },
            ObservedHierarchyNode {
                id: "o1-b",
                parent: Some("o1-a"),
                coordinator: true,
            },
            ObservedHierarchyNode {
                id: "worker-a",
                parent: Some("o1-b"),
                coordinator: false,
            },
        ]);
        assert_eq!(three.depths.get("o2").copied(), Some(0));
        assert_eq!(three.depths.get("o1-a").copied(), Some(1));
        assert_eq!(three.depths.get("o1-b").copied(), Some(2));
        assert_eq!(three.depths.get("worker-a").copied(), Some(3));
        assert_eq!(three.coordination_depth, 3);

        let orphan_worker = observe_hierarchy([ObservedHierarchyNode {
            id: "worker-a",
            parent: Some("missing-parent"),
            coordinator: false,
        }]);
        assert_eq!(orphan_worker.depths.get("worker-a").copied(), Some(1));
        assert_eq!(orphan_worker.coordination_depth, 2);
    }

    #[test]
    fn refused_self_judge_transition_is_recorded() -> Result<()> {
        let refused = RoleTransitionRecord {
            agent_id: "child-a".to_string(),
            from_category: RoleCategory::NonDelegatingTerminalWorker,
            to_category: RoleCategory::DelegatingCoordinator,
            requester_agent_id: "child-a".to_string(),
            judge_agent_id: "child-a".to_string(),
            evidence: RoleTransitionEvidenceRecord {
                acceptance_grade: true,
                recorded: true,
                uncertain: false,
            },
            decision: RoleTransitionDecision::Refused,
            reason: "self_judged".to_string(),
        };
        refused.validate()?;
        let snapshot = reconstruct_hierarchy_ledger(&[event(
            "child-a",
            Some("run-1"),
            OrchestrationRole::Orchestrator,
            OrchestrationEventKind::Journal,
            role_transition_payload(&refused)?,
        )])?;
        assert_eq!(snapshot.role_transitions.len(), 1);
        assert_eq!(
            snapshot.role_transitions[0].decision,
            RoleTransitionDecision::Refused
        );
        Ok(())
    }

    #[test]
    fn granted_self_judge_transition_fails_closed() {
        let granted = RoleTransitionRecord {
            agent_id: "child-a".to_string(),
            from_category: RoleCategory::NonDelegatingTerminalWorker,
            to_category: RoleCategory::DelegatingCoordinator,
            requester_agent_id: "run-1".to_string(),
            judge_agent_id: "child-a".to_string(),
            evidence: RoleTransitionEvidenceRecord {
                acceptance_grade: true,
                recorded: true,
                uncertain: false,
            },
            decision: RoleTransitionDecision::Granted,
            reason: "granted_promotion".to_string(),
        };
        let error = granted.validate().expect_err("self-judged grant must fail");
        assert!(error.to_string().contains("self-judged"));
    }

    #[test]
    fn legacy_granted_transition_without_evidence_fails_closed() -> Result<()> {
        let legacy = serde_json::json!({
            "agent_id": "child-a",
            "from_category": "non_delegating_terminal_worker",
            "to_category": "delegating_coordinator",
            "requester_agent_id": "run-1",
            "judge_agent_id": "third-party-judge",
            "decision": "granted",
            "reason": "granted_promotion"
        });
        let record: RoleTransitionRecord = serde_json::from_value(legacy)?;
        let error = record
            .validate()
            .expect_err("legacy grant without evidence must fail closed");
        assert!(error.to_string().contains("evidence"));
        Ok(())
    }

    #[test]
    fn granted_transition_rejects_inconsistent_evidence() {
        for evidence in [
            RoleTransitionEvidenceRecord {
                acceptance_grade: true,
                recorded: false,
                uncertain: false,
            },
            RoleTransitionEvidenceRecord {
                acceptance_grade: true,
                recorded: true,
                uncertain: true,
            },
        ] {
            let granted = RoleTransitionRecord {
                agent_id: "child-a".to_string(),
                from_category: RoleCategory::NonDelegatingTerminalWorker,
                to_category: RoleCategory::DelegatingCoordinator,
                requester_agent_id: "run-1".to_string(),
                judge_agent_id: "third-party-judge".to_string(),
                evidence,
                decision: RoleTransitionDecision::Granted,
                reason: "granted_promotion".to_string(),
            };
            let error = granted
                .validate()
                .expect_err("grant with inconsistent evidence must fail closed");
            assert!(error.to_string().contains("evidence"));
        }

        let categories = [
            RoleCategory::DelegatingCoordinator,
            RoleCategory::NonDelegatingTerminalWorker,
            RoleCategory::ReadOnlyResearcher,
            RoleCategory::ReadOnlyReviewAuditor,
        ];
        for from_category in categories {
            for to_category in categories {
                let gained_authority =
                    to_category.authority_bits() & !from_category.authority_bits();
                if from_category == to_category || gained_authority == 0 {
                    continue;
                }
                let granted = RoleTransitionRecord {
                    agent_id: "child-a".to_string(),
                    from_category,
                    to_category,
                    requester_agent_id: "run-1".to_string(),
                    judge_agent_id: "third-party-judge".to_string(),
                    evidence: RoleTransitionEvidenceRecord {
                        acceptance_grade: false,
                        recorded: true,
                        uncertain: false,
                    },
                    decision: RoleTransitionDecision::Granted,
                    reason: "granted_promotion".to_string(),
                };
                let error = granted
                    .validate()
                    .expect_err("authority-gaining grant requires acceptance-grade evidence");
                assert!(error.to_string().contains("acceptance-grade evidence"));
            }
        }
    }

    #[test]
    fn granted_demotion_accepts_recorded_certain_non_acceptance_evidence() -> Result<()> {
        let granted = RoleTransitionRecord {
            agent_id: "child-a".to_string(),
            from_category: RoleCategory::DelegatingCoordinator,
            to_category: RoleCategory::NonDelegatingTerminalWorker,
            requester_agent_id: "run-1".to_string(),
            judge_agent_id: "third-party-judge".to_string(),
            evidence: RoleTransitionEvidenceRecord {
                acceptance_grade: false,
                recorded: true,
                uncertain: false,
            },
            decision: RoleTransitionDecision::Granted,
            reason: "granted_demotion".to_string(),
        };
        granted.validate()
    }

    #[test]
    fn spawn_coordinator_keeps_a_granted_promotion_journal_to_the_same_category() -> Result<()> {
        let edge = SupervisionEdgeRecord::new(
            "child-a",
            "run-1",
            OrchestrationRole::Orchestrator,
            "child_orchestrator",
            vec!["src/lib.rs".to_string()],
            "assignment:child-a",
        )?;
        let mut spawn_payload = json!({});
        insert_supervision_edge(&mut spawn_payload, &edge)?;
        let promotion = RoleTransitionRecord {
            agent_id: "child-a".to_string(),
            from_category: RoleCategory::NonDelegatingTerminalWorker,
            to_category: RoleCategory::DelegatingCoordinator,
            requester_agent_id: "run-1".to_string(),
            judge_agent_id: "third-party-auditor".to_string(),
            evidence: RoleTransitionEvidenceRecord {
                acceptance_grade: true,
                recorded: true,
                uncertain: false,
            },
            decision: RoleTransitionDecision::Granted,
            reason: "granted_promotion".to_string(),
        };
        let snapshot = reconstruct_hierarchy_ledger(&[
            event(
                "child-a",
                Some("run-1"),
                OrchestrationRole::Orchestrator,
                OrchestrationEventKind::Spawn,
                spawn_payload,
            ),
            event(
                "child-a",
                Some("run-1"),
                OrchestrationRole::Orchestrator,
                OrchestrationEventKind::Journal,
                role_transition_payload(&promotion)?,
            ),
        ])?;
        assert_eq!(
            snapshot.effective_categories.get("child-a").copied(),
            Some(RoleCategory::DelegatingCoordinator)
        );
        assert_eq!(snapshot.role_transitions.len(), 1);
        assert_eq!(
            snapshot.role_transitions[0].decision,
            RoleTransitionDecision::Granted
        );
        Ok(())
    }

    #[test]
    fn reconstructed_effective_category_rejects_a_stale_transition_source() -> Result<()> {
        let edge = SupervisionEdgeRecord::new(
            "child-a",
            "run-1",
            OrchestrationRole::Orchestrator,
            "child_orchestrator",
            vec!["src/lib.rs".to_string()],
            "assignment:child-a",
        )?;
        let mut spawn_payload = json!({});
        insert_supervision_edge(&mut spawn_payload, &edge)?;
        let demotion = RoleTransitionRecord {
            agent_id: "child-a".to_string(),
            from_category: RoleCategory::DelegatingCoordinator,
            to_category: RoleCategory::NonDelegatingTerminalWorker,
            requester_agent_id: "run-1".to_string(),
            judge_agent_id: "third-party-auditor".to_string(),
            evidence: RoleTransitionEvidenceRecord {
                acceptance_grade: false,
                recorded: true,
                uncertain: false,
            },
            decision: RoleTransitionDecision::Granted,
            reason: "granted_demotion".to_string(),
        };
        let stale = RoleTransitionRecord {
            from_category: RoleCategory::DelegatingCoordinator,
            to_category: RoleCategory::NonDelegatingTerminalWorker,
            ..demotion.clone()
        };
        let error = reconstruct_hierarchy_ledger(&[
            event(
                "child-a",
                Some("run-1"),
                OrchestrationRole::Orchestrator,
                OrchestrationEventKind::Spawn,
                spawn_payload,
            ),
            event(
                "child-a",
                Some("run-1"),
                OrchestrationRole::Orchestrator,
                OrchestrationEventKind::Journal,
                role_transition_payload(&demotion)?,
            ),
            event(
                "child-a",
                Some("run-1"),
                OrchestrationRole::Orchestrator,
                OrchestrationEventKind::Journal,
                role_transition_payload(&stale)?,
            ),
        ])
        .expect_err("stale transition source must fail closed");
        assert!(
            error.to_string().contains("effective category"),
            "{error:#}"
        );
        Ok(())
    }

    #[test]
    fn legacy_role_transition_without_evidence_uses_safe_default() -> Result<()> {
        let legacy = serde_json::json!({
            "agent_id": "child-a",
            "from_category": "non_delegating_terminal_worker",
            "to_category": "delegating_coordinator",
            "requester_agent_id": "run-1",
            "judge_agent_id": "third-party-judge",
            "decision": "refused",
            "reason": "insufficient_gate_evidence"
        });
        let record: RoleTransitionRecord = serde_json::from_value(legacy)?;
        assert_eq!(record.evidence, RoleTransitionEvidenceRecord::default());
        record.validate()
    }
}
