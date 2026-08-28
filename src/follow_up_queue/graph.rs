//! Durable typed execution-graph state for the generated follow-up queue.
//!
//! This module deliberately owns no storage. Its events are concrete serde
//! values suitable for embedding in the authenticated queue journal, and the
//! same reducer is used for candidate-event validation and replay.

#![allow(dead_code)]

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

const MAX_GRAPH_NODES: usize = 64;
const MAX_GRAPH_EDGES: usize = 256;
const MAX_GRAPH_BRANCHES: usize = 64;
const MAX_GRAPH_EVENTS: usize = 4_096;
const MAX_ID_BYTES: usize = 128;
const MAX_DURABLE_TEXT_BYTES: usize = 1_024;
const MAX_SUCCESS_WRITE_REFS: usize = 32;
const MAX_BRANCH_ATTEMPTS: u16 = 16;
const MAX_BRANCH_HISTORY_RECORDS: usize = MAX_GRAPH_EVENTS;
const MAX_LOOP_ITERATIONS: u16 = 64;
const MAX_NODE_VISITS: u16 = 1_024;

macro_rules! durable_id {
    ($name:ident, $label:literal) => {
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub(crate) struct $name(String);

        impl $name {
            pub(crate) fn new(value: impl Into<String>) -> Result<Self> {
                let value = value.into();
                validate_id(&value, $label)?;
                Ok(Self(value))
            }

            pub(crate) fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(&self.0)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                validate_id(&value, $label).map_err(serde::de::Error::custom)?;
                Ok(Self(value))
            }
        }
    };
}

durable_id!(DurableGraphId, "graph id");
durable_id!(GraphNodeId, "graph node id");
durable_id!(GraphEdgeId, "graph edge id");
durable_id!(GraphBranchId, "graph branch id");

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct DurableText(String);

impl DurableText {
    pub(crate) fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        validate_text(&value, "durable graph text", MAX_DURABLE_TEXT_BYTES)?;
        Ok(Self(value))
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl Serialize for DurableText {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for DurableText {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        validate_text(&value, "durable graph text", MAX_DURABLE_TEXT_BYTES)
            .map_err(serde::de::Error::custom)?;
        Ok(Self(value))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum FanInResult {
    AllSuccess,
    PartialSuccess,
    Failure,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum GraphTermination {
    Success,
    PartialSuccess,
    Failure,
    Cancelled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum BranchOutcomeClass {
    Success,
    RetryableFailure,
    Failure,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BranchSuccess {
    result_ref: DurableText,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    write_refs: Vec<DurableText>,
}

impl BranchSuccess {
    pub(crate) fn new(result_ref: DurableText, write_refs: Vec<DurableText>) -> Result<Self> {
        let success = Self {
            result_ref,
            write_refs,
        };
        success.validate()?;
        Ok(success)
    }

    pub(crate) fn result_ref(&self) -> &DurableText {
        &self.result_ref
    }

    pub(crate) fn write_refs(&self) -> &[DurableText] {
        &self.write_refs
    }

    fn validate(&self) -> Result<()> {
        if self.write_refs.len() > MAX_SUCCESS_WRITE_REFS {
            bail!("durable branch success exceeds its write-reference bound");
        }
        if !is_strictly_sorted(self.write_refs.iter()) {
            bail!("durable branch success write references are not canonical and unique");
        }
        Ok(())
    }
}

impl<'de> Deserialize<'de> for BranchSuccess {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct WireBranchSuccess {
            result_ref: DurableText,
            #[serde(default)]
            write_refs: Vec<DurableText>,
        }

        let wire = WireBranchSuccess::deserialize(deserializer)?;
        BranchSuccess::new(wire.result_ref, wire.write_refs).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum BranchOutcome {
    Success { success: BranchSuccess },
    RetryableFailure { error: DurableText },
    Failure { error: DurableText },
}

impl BranchOutcome {
    pub(crate) fn class(&self) -> BranchOutcomeClass {
        match self {
            Self::Success { .. } => BranchOutcomeClass::Success,
            Self::RetryableFailure { .. } => BranchOutcomeClass::RetryableFailure,
            Self::Failure { .. } => BranchOutcomeClass::Failure,
        }
    }

    fn validate(&self) -> Result<()> {
        if let Self::Success { success } = self {
            success.validate()?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum LoopDecision {
    Continue,
    Exit,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum DurableGraphNodeKind {
    Task {
        branch_id: GraphBranchId,
        max_attempts: u16,
    },
    Fork,
    Choice,
    Join {
        branches: Vec<GraphBranchId>,
    },
    Loop {
        max_iterations: u16,
    },
    Terminate {
        outcome: GraphTermination,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DurableGraphNode {
    id: GraphNodeId,
    kind: DurableGraphNodeKind,
}

impl DurableGraphNode {
    pub(crate) fn new(id: GraphNodeId, kind: DurableGraphNodeKind) -> Self {
        Self { id, kind }
    }

    pub(crate) fn id(&self) -> &GraphNodeId {
        &self.id
    }

    pub(crate) fn kind(&self) -> &DurableGraphNodeKind {
        &self.kind
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(tag = "condition", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum DurableEdgeCondition {
    Always,
    BranchLatestOutcome {
        branch_id: GraphBranchId,
        outcome: BranchOutcomeClass,
    },
    JoinResult {
        join_node_id: GraphNodeId,
        result: FanInResult,
    },
    LoopDecision {
        loop_node_id: GraphNodeId,
        decision: LoopDecision,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum DurableGraphEdgeKind {
    Forward,
    JoinArrival { branch_id: GraphBranchId },
    LoopBody { loop_node_id: GraphNodeId },
    LoopBack { loop_node_id: GraphNodeId },
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DurableGraphEdge {
    id: GraphEdgeId,
    from: GraphNodeId,
    to: GraphNodeId,
    kind: DurableGraphEdgeKind,
    condition: DurableEdgeCondition,
}

impl DurableGraphEdge {
    pub(crate) fn new(
        id: GraphEdgeId,
        from: GraphNodeId,
        to: GraphNodeId,
        kind: DurableGraphEdgeKind,
        condition: DurableEdgeCondition,
    ) -> Self {
        Self {
            id,
            from,
            to,
            kind,
            condition,
        }
    }

    pub(crate) fn id(&self) -> &GraphEdgeId {
        &self.id
    }

    pub(crate) fn from(&self) -> &GraphNodeId {
        &self.from
    }

    pub(crate) fn to(&self) -> &GraphNodeId {
        &self.to
    }

    pub(crate) fn kind(&self) -> &DurableGraphEdgeKind {
        &self.kind
    }

    pub(crate) fn condition(&self) -> &DurableEdgeCondition {
        &self.condition
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DurableGraphDefinition {
    graph_id: DurableGraphId,
    entry_node_id: GraphNodeId,
    nodes: Vec<DurableGraphNode>,
    edges: Vec<DurableGraphEdge>,
}

impl DurableGraphDefinition {
    pub(crate) fn new(
        graph_id: DurableGraphId,
        entry_node_id: GraphNodeId,
        nodes: Vec<DurableGraphNode>,
        edges: Vec<DurableGraphEdge>,
    ) -> Result<Self> {
        let definition = Self {
            graph_id,
            entry_node_id,
            nodes,
            edges,
        };
        definition.validate()?;
        Ok(definition)
    }

    pub(crate) fn graph_id(&self) -> &DurableGraphId {
        &self.graph_id
    }

    pub(crate) fn entry_node_id(&self) -> &GraphNodeId {
        &self.entry_node_id
    }

    pub(crate) fn nodes(&self) -> &[DurableGraphNode] {
        &self.nodes
    }

    pub(crate) fn edges(&self) -> &[DurableGraphEdge] {
        &self.edges
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if self.nodes.is_empty() || self.nodes.len() > MAX_GRAPH_NODES {
            bail!("durable graph node count is empty or exceeds its fixed bound");
        }
        if self.edges.len() > MAX_GRAPH_EDGES {
            bail!("durable graph edge count exceeds its fixed bound");
        }

        if !is_strictly_sorted(self.nodes.iter().map(|node| &node.id))
            || !is_strictly_sorted(self.edges.iter().map(|edge| &edge.id))
        {
            bail!("durable graph nodes or edges are not in canonical id order");
        }

        let nodes = self
            .nodes
            .iter()
            .map(|node| (node.id.clone(), node))
            .collect::<BTreeMap<_, _>>();
        if nodes.len() != self.nodes.len() {
            bail!("durable graph repeats a node id");
        }
        if !nodes.contains_key(&self.entry_node_id) {
            bail!("durable graph entry node is unknown");
        }

        let mut branches = BTreeMap::new();
        let mut joins = BTreeSet::new();
        let mut loops = BTreeMap::new();
        let mut termination_count = 0_usize;
        for node in &self.nodes {
            match &node.kind {
                DurableGraphNodeKind::Task {
                    branch_id,
                    max_attempts,
                } => {
                    if *max_attempts == 0 || *max_attempts > MAX_BRANCH_ATTEMPTS {
                        bail!("durable graph task attempt bound is unsupported");
                    }
                    if branches
                        .insert(branch_id.clone(), (node.id.clone(), *max_attempts))
                        .is_some()
                    {
                        bail!("durable graph repeats a branch id");
                    }
                }
                DurableGraphNodeKind::Join { branches: required } => {
                    if required.len() < 2 || required.len() > MAX_GRAPH_BRANCHES {
                        bail!("durable graph join branch count is unsupported");
                    }
                    if !is_strictly_sorted(required.iter()) {
                        bail!("durable graph join branches are not canonical and unique");
                    }
                    joins.insert(node.id.clone());
                }
                DurableGraphNodeKind::Loop { max_iterations } => {
                    if *max_iterations == 0 || *max_iterations > MAX_LOOP_ITERATIONS {
                        bail!("durable graph loop iteration bound is unsupported");
                    }
                    loops.insert(node.id.clone(), *max_iterations);
                }
                DurableGraphNodeKind::Terminate { .. } => termination_count += 1,
                DurableGraphNodeKind::Fork | DurableGraphNodeKind::Choice => {}
            }
        }
        if branches.len() > MAX_GRAPH_BRANCHES {
            bail!("durable graph branch count exceeds its fixed bound");
        }
        if termination_count == 0 {
            bail!("durable graph has no explicit termination node");
        }
        for node in &self.nodes {
            if let DurableGraphNodeKind::Join { branches: required } = &node.kind {
                if required.iter().any(|branch| !branches.contains_key(branch)) {
                    bail!("durable graph join references an unknown branch");
                }
            }
        }

        self.validate_edges(&nodes, &branches, &joins, &loops)?;
        Ok(())
    }

    fn node(&self, node_id: &GraphNodeId) -> Result<&DurableGraphNode> {
        self.nodes
            .iter()
            .find(|node| &node.id == node_id)
            .context("durable graph node is unknown")
    }

    fn edge(&self, edge_id: &GraphEdgeId) -> Result<&DurableGraphEdge> {
        self.edges
            .iter()
            .find(|edge| &edge.id == edge_id)
            .context("durable graph edge is unknown")
    }

    fn validate_edges(
        &self,
        nodes: &BTreeMap<GraphNodeId, &DurableGraphNode>,
        branches: &BTreeMap<GraphBranchId, (GraphNodeId, u16)>,
        joins: &BTreeSet<GraphNodeId>,
        loops: &BTreeMap<GraphNodeId, u16>,
    ) -> Result<()> {
        let edge_ids = self
            .edges
            .iter()
            .map(|edge| edge.id.clone())
            .collect::<BTreeSet<_>>();
        if edge_ids.len() != self.edges.len() {
            bail!("durable graph repeats an edge id");
        }
        let structural_edges = self
            .edges
            .iter()
            .map(|edge| (&edge.from, &edge.to, &edge.kind, &edge.condition))
            .collect::<BTreeSet<_>>();
        if structural_edges.len() != self.edges.len() {
            bail!("durable graph repeats a structural edge under another id");
        }

        let mut incoming = nodes
            .keys()
            .cloned()
            .map(|id| (id, 0_usize))
            .collect::<BTreeMap<_, _>>();
        let mut outgoing = nodes
            .keys()
            .cloned()
            .map(|id| (id, Vec::new()))
            .collect::<BTreeMap<_, Vec<&DurableGraphEdge>>>();
        let mut body_membership = BTreeMap::<GraphNodeId, GraphNodeId>::new();

        for edge in &self.edges {
            if edge.from == edge.to {
                bail!("durable graph self-edges are unsupported");
            }
            if !nodes.contains_key(&edge.from) || !nodes.contains_key(&edge.to) {
                bail!("durable graph edge references an unknown node");
            }
            *incoming
                .get_mut(&edge.to)
                .context("durable graph incoming-edge index is incomplete")? += 1;
            outgoing
                .get_mut(&edge.from)
                .context("durable graph outgoing-edge index is incomplete")?
                .push(edge);

            match &edge.condition {
                DurableEdgeCondition::Always => {}
                DurableEdgeCondition::BranchLatestOutcome { branch_id, .. } => {
                    if !branches.contains_key(branch_id) {
                        bail!("durable graph condition references an unknown branch");
                    }
                }
                DurableEdgeCondition::JoinResult { join_node_id, .. } => {
                    if join_node_id != &edge.from || !joins.contains(join_node_id) {
                        bail!("join-result edges must originate at their referenced join");
                    }
                }
                DurableEdgeCondition::LoopDecision { loop_node_id, .. } => {
                    if loop_node_id != &edge.from || !loops.contains_key(loop_node_id) {
                        bail!("loop-decision edges must originate at their referenced loop");
                    }
                }
            }

            match &edge.kind {
                DurableGraphEdgeKind::Forward => {}
                DurableGraphEdgeKind::JoinArrival { branch_id } => {
                    let (branch_node_id, _) = branches
                        .get(branch_id)
                        .context("durable graph join arrival names an unknown branch")?;
                    if branch_node_id != &edge.from
                        || !matches!(
                            nodes.get(&edge.to).map(|node| &node.kind),
                            Some(DurableGraphNodeKind::Join { branches })
                                if branches.contains(branch_id)
                        )
                        || !matches!(edge.condition, DurableEdgeCondition::Always)
                    {
                        bail!(
                            "durable graph join arrival is not uniquely bound to its task and join"
                        );
                    }
                }
                DurableGraphEdgeKind::LoopBody { loop_node_id } => {
                    if !loops.contains_key(loop_node_id) || &edge.to == loop_node_id {
                        bail!("loop-body edge has an invalid loop binding");
                    }
                    bind_loop_member(&mut body_membership, &edge.to, loop_node_id)?;
                    if &edge.from != loop_node_id {
                        bind_loop_member(&mut body_membership, &edge.from, loop_node_id)?;
                    }
                }
                DurableGraphEdgeKind::LoopBack { loop_node_id } => {
                    if !loops.contains_key(loop_node_id)
                        || &edge.to != loop_node_id
                        || !matches!(edge.condition, DurableEdgeCondition::Always)
                    {
                        bail!("loop-back edge is not an unconditional edge to its loop node");
                    }
                    bind_loop_member(&mut body_membership, &edge.from, loop_node_id)?;
                }
            }
        }

        for edge in &self.edges {
            match &edge.kind {
                DurableGraphEdgeKind::Forward | DurableGraphEdgeKind::JoinArrival { .. } => {
                    if body_membership.contains_key(&edge.from)
                        || body_membership.contains_key(&edge.to)
                    {
                        bail!("loop-body nodes may only use explicitly loop-scoped edges");
                    }
                }
                DurableGraphEdgeKind::LoopBody { loop_node_id }
                | DurableGraphEdgeKind::LoopBack { loop_node_id } => {
                    if body_membership
                        .get(&edge.from)
                        .is_some_and(|bound| bound != loop_node_id)
                        || body_membership
                            .get(&edge.to)
                            .is_some_and(|bound| bound != loop_node_id)
                    {
                        bail!("durable graph overlaps two loop bodies");
                    }
                }
            }
        }

        for node in &self.nodes {
            let edges = outgoing
                .get(&node.id)
                .context("durable graph outgoing-edge index is incomplete")?;
            match &node.kind {
                DurableGraphNodeKind::Terminate { .. } if !edges.is_empty() => {
                    bail!("durable graph termination node has outgoing edges")
                }
                DurableGraphNodeKind::Terminate { .. } => {}
                DurableGraphNodeKind::Fork if edges.len() < 2 => {
                    bail!("durable graph fork requires at least two outgoing edges")
                }
                DurableGraphNodeKind::Fork
                    if edges
                        .iter()
                        .any(|edge| !matches!(edge.condition, DurableEdgeCondition::Always)) =>
                {
                    bail!("durable graph fork must use unconditional outgoing edges")
                }
                DurableGraphNodeKind::Fork
                    if edges
                        .iter()
                        .map(|edge| &edge.to)
                        .collect::<BTreeSet<_>>()
                        .len()
                        != edges.len() =>
                {
                    bail!("durable graph fork repeats an outgoing destination")
                }
                DurableGraphNodeKind::Choice => {
                    validate_choice_edges(edges)?;
                }
                DurableGraphNodeKind::Task { branch_id, .. } => {
                    validate_task_edges(branch_id, edges)?;
                }
                DurableGraphNodeKind::Join { .. } => {
                    let results = edges
                        .iter()
                        .filter_map(|edge| match edge.condition {
                            DurableEdgeCondition::JoinResult { result, .. } => Some(result),
                            _ => None,
                        })
                        .collect::<BTreeSet<_>>();
                    let expected = [
                        FanInResult::AllSuccess,
                        FanInResult::PartialSuccess,
                        FanInResult::Failure,
                    ]
                    .into_iter()
                    .collect::<BTreeSet<_>>();
                    if results != expected || edges.len() != expected.len() {
                        bail!("durable graph join must route every distinct fan-in result");
                    }
                }
                DurableGraphNodeKind::Loop { .. } => {
                    let decisions = edges
                        .iter()
                        .filter_map(|edge| match edge.condition {
                            DurableEdgeCondition::LoopDecision { decision, .. } => Some(decision),
                            _ => None,
                        })
                        .collect::<BTreeSet<_>>();
                    let expected = [LoopDecision::Continue, LoopDecision::Exit]
                        .into_iter()
                        .collect::<BTreeSet<_>>();
                    if decisions != expected || edges.len() != expected.len() {
                        bail!("durable graph loop requires distinct continue and exit routes");
                    }
                    for edge in edges {
                        match (&edge.condition, &edge.kind) {
                            (
                                DurableEdgeCondition::LoopDecision {
                                    decision: LoopDecision::Continue,
                                    loop_node_id,
                                },
                                DurableGraphEdgeKind::LoopBody {
                                    loop_node_id: body_loop,
                                },
                            ) if loop_node_id == body_loop => {}
                            (
                                DurableEdgeCondition::LoopDecision {
                                    decision: LoopDecision::Exit,
                                    ..
                                },
                                DurableGraphEdgeKind::Forward,
                            ) => {}
                            _ => bail!("durable graph loop route kind contradicts its decision"),
                        }
                    }
                }
                _ if edges.is_empty() => bail!("durable graph node has no outgoing edge"),
                _ => {}
            }
        }

        for (node_id, count) in &incoming {
            if *count > 1
                && !matches!(
                    nodes.get(node_id).map(|node| &node.kind),
                    Some(DurableGraphNodeKind::Join { .. } | DurableGraphNodeKind::Loop { .. })
                )
            {
                bail!("only join and loop nodes may have multiple incoming edges");
            }
        }

        for node in &self.nodes {
            let DurableGraphNodeKind::Join { branches: required } = &node.kind else {
                continue;
            };
            let arrivals = self
                .edges
                .iter()
                .filter(|edge| edge.to == node.id)
                .map(|edge| match &edge.kind {
                    DurableGraphEdgeKind::JoinArrival { branch_id } => Ok(branch_id),
                    DurableGraphEdgeKind::Forward
                    | DurableGraphEdgeKind::LoopBody { .. }
                    | DurableGraphEdgeKind::LoopBack { .. } => {
                        bail!("durable graph join has an unbound incoming edge")
                    }
                })
                .collect::<Result<Vec<_>>>()?;
            if arrivals.len() != required.len()
                || arrivals.into_iter().collect::<BTreeSet<_>>()
                    != required.iter().collect::<BTreeSet<_>>()
            {
                bail!("durable graph join arrivals do not exactly cover its required branches");
            }
        }

        validate_acyclic_without_loop_backs(nodes, &self.edges)?;
        validate_reachability(&self.entry_node_id, nodes, &self.edges)?;
        validate_loop_scopes(loops, &body_membership, &self.edges)?;
        validate_worst_case_event_bound(&self.nodes, loops, &body_membership)?;
        Ok(())
    }
}

fn validate_task_edges(task_branch_id: &GraphBranchId, edges: &[&DurableGraphEdge]) -> Result<()> {
    if edges.len() == 1 && matches!(edges[0].condition, DurableEdgeCondition::Always) {
        return Ok(());
    }
    let outcomes = edges
        .iter()
        .map(|edge| match &edge.condition {
            DurableEdgeCondition::BranchLatestOutcome { branch_id, outcome }
                if branch_id == task_branch_id && *outcome != BranchOutcomeClass::RetryableFailure =>
            {
                Ok(*outcome)
            }
            _ => bail!("durable graph task routes must be one unconditional edge or exhaustive terminal outcome edges"),
        })
        .collect::<Result<BTreeSet<_>>>()?;
    let expected = [BranchOutcomeClass::Success, BranchOutcomeClass::Failure]
        .into_iter()
        .collect::<BTreeSet<_>>();
    if edges.len() != expected.len() || outcomes != expected {
        bail!("durable graph task terminal outcome routes are ambiguous or incomplete");
    }
    Ok(())
}

fn validate_choice_edges(edges: &[&DurableGraphEdge]) -> Result<()> {
    let mut discriminator: Option<&GraphBranchId> = None;
    let outcomes = edges
        .iter()
        .map(|edge| match &edge.condition {
            DurableEdgeCondition::BranchLatestOutcome { branch_id, outcome } => {
                if discriminator.is_some_and(|existing| existing != branch_id) {
                    bail!("durable graph choice mixes branch discriminators");
                }
                discriminator = Some(branch_id);
                Ok(*outcome)
            }
            _ => bail!("durable graph choice requires branch-outcome conditional edges"),
        })
        .collect::<Result<BTreeSet<_>>>()?;
    let expected = [BranchOutcomeClass::Success, BranchOutcomeClass::Failure]
        .into_iter()
        .collect::<BTreeSet<_>>();
    if edges.len() != expected.len() || outcomes != expected {
        bail!("durable graph choice routes are ambiguous or incomplete");
    }
    Ok(())
}

impl<'de> Deserialize<'de> for DurableGraphDefinition {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct WireDefinition {
            graph_id: DurableGraphId,
            entry_node_id: GraphNodeId,
            nodes: Vec<DurableGraphNode>,
            edges: Vec<DurableGraphEdge>,
        }

        let wire = WireDefinition::deserialize(deserializer)?;
        DurableGraphDefinition::new(wire.graph_id, wire.entry_node_id, wire.nodes, wire.edges)
            .map_err(serde::de::Error::custom)
    }
}

fn bind_loop_member(
    membership: &mut BTreeMap<GraphNodeId, GraphNodeId>,
    node_id: &GraphNodeId,
    loop_node_id: &GraphNodeId,
) -> Result<()> {
    if let Some(existing) = membership.insert(node_id.clone(), loop_node_id.clone()) {
        if &existing != loop_node_id {
            bail!("durable graph node belongs to overlapping loop bodies");
        }
    }
    Ok(())
}

fn validate_acyclic_without_loop_backs(
    nodes: &BTreeMap<GraphNodeId, &DurableGraphNode>,
    edges: &[DurableGraphEdge],
) -> Result<()> {
    let mut indegree = nodes
        .keys()
        .cloned()
        .map(|id| (id, 0_usize))
        .collect::<BTreeMap<_, _>>();
    let mut adjacency = BTreeMap::<GraphNodeId, Vec<GraphNodeId>>::new();
    for edge in edges {
        if matches!(edge.kind, DurableGraphEdgeKind::LoopBack { .. }) {
            continue;
        }
        *indegree
            .get_mut(&edge.to)
            .context("durable graph cycle index is incomplete")? += 1;
        adjacency
            .entry(edge.from.clone())
            .or_default()
            .push(edge.to.clone());
    }
    let mut ready = indegree
        .iter()
        .filter_map(|(id, degree)| (*degree == 0).then_some(id.clone()))
        .collect::<VecDeque<_>>();
    let mut visited = 0_usize;
    while let Some(node_id) = ready.pop_front() {
        visited += 1;
        if let Some(destinations) = adjacency.get(&node_id) {
            for destination in destinations {
                let degree = indegree
                    .get_mut(destination)
                    .context("durable graph cycle index lost a node")?;
                *degree = degree
                    .checked_sub(1)
                    .context("durable graph cycle index underflowed")?;
                if *degree == 0 {
                    ready.push_back(destination.clone());
                }
            }
        }
    }
    if visited != nodes.len() {
        bail!("durable graph contains a cycle without an explicit bounded loop back-edge");
    }
    Ok(())
}

fn validate_reachability(
    entry: &GraphNodeId,
    nodes: &BTreeMap<GraphNodeId, &DurableGraphNode>,
    edges: &[DurableGraphEdge],
) -> Result<()> {
    let mut reached = BTreeSet::from([entry.clone()]);
    let mut pending = VecDeque::from([entry.clone()]);
    while let Some(node_id) = pending.pop_front() {
        for edge in edges.iter().filter(|edge| edge.from == node_id) {
            if reached.insert(edge.to.clone()) {
                pending.push_back(edge.to.clone());
            }
        }
    }
    if reached.len() != nodes.len() {
        bail!("durable graph contains an unreachable node");
    }
    Ok(())
}

fn validate_loop_scopes(
    loops: &BTreeMap<GraphNodeId, u16>,
    membership: &BTreeMap<GraphNodeId, GraphNodeId>,
    edges: &[DurableGraphEdge],
) -> Result<()> {
    for loop_node_id in loops.keys() {
        let mut reached = BTreeSet::from([loop_node_id.clone()]);
        let mut pending = VecDeque::from([loop_node_id.clone()]);
        while let Some(node_id) = pending.pop_front() {
            for edge in edges.iter().filter(|edge| {
                edge.from == node_id
                    && matches!(
                        &edge.kind,
                        DurableGraphEdgeKind::LoopBody { loop_node_id: bound }
                            if bound == loop_node_id
                    )
            }) {
                if reached.insert(edge.to.clone()) {
                    pending.push_back(edge.to.clone());
                }
            }
        }
        for member in membership
            .iter()
            .filter_map(|(node, bound)| (bound == loop_node_id).then_some(node))
        {
            if !reached.contains(member) {
                bail!("durable graph loop body is not reachable from its loop node");
            }
        }
        let back_edge_count = edges
            .iter()
            .filter(|edge| {
                matches!(
                    &edge.kind,
                    DurableGraphEdgeKind::LoopBack { loop_node_id: bound }
                        if bound == loop_node_id && reached.contains(&edge.from)
                )
            })
            .count();
        if back_edge_count != 1 {
            bail!("durable graph loop must have exactly one explicit back-edge");
        }
    }
    Ok(())
}

fn validate_worst_case_event_bound(
    nodes: &[DurableGraphNode],
    loops: &BTreeMap<GraphNodeId, u16>,
    body_membership: &BTreeMap<GraphNodeId, GraphNodeId>,
) -> Result<()> {
    let mut upper_bound = 1_usize;
    for node in nodes {
        let visits = if let Some(loop_node_id) = body_membership.get(&node.id) {
            usize::from(
                *loops
                    .get(loop_node_id)
                    .context("durable graph event bound lost a loop body binding")?,
            )
        } else {
            1
        };
        let per_visit = match node.kind {
            DurableGraphNodeKind::Task { max_attempts, .. } => usize::from(max_attempts)
                .checked_mul(3)
                .context("durable graph task event bound overflowed")?,
            DurableGraphNodeKind::Loop { max_iterations } => {
                if body_membership.contains_key(&node.id) {
                    bail!("durable graph nested loops are unsupported");
                }
                upper_bound = upper_bound
                    .checked_add(
                        usize::from(max_iterations)
                            .checked_mul(2)
                            .context("durable graph loop event bound overflowed")?,
                    )
                    .context("durable graph event bound overflowed")?;
                continue;
            }
            DurableGraphNodeKind::Join { .. } => {
                if body_membership.contains_key(&node.id) {
                    bail!("durable graph joins inside loop bodies are unsupported");
                }
                2
            }
            DurableGraphNodeKind::Fork | DurableGraphNodeKind::Choice => 1,
            DurableGraphNodeKind::Terminate { .. } => 1,
        };
        upper_bound = upper_bound
            .checked_add(
                visits
                    .checked_mul(per_visit)
                    .context("durable graph node event bound overflowed")?,
            )
            .context("durable graph event bound overflowed")?;
    }
    if upper_bound > MAX_GRAPH_EVENTS {
        bail!("durable graph worst-case transition history exceeds its fixed event bound");
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BranchAttemptRecord {
    visit: u16,
    attempt: u16,
    outcome: BranchOutcome,
}

impl BranchAttemptRecord {
    pub(crate) fn visit(&self) -> u16 {
        self.visit
    }

    pub(crate) fn attempt(&self) -> u16 {
        self.attempt
    }

    pub(crate) fn outcome(&self) -> &BranchOutcome {
        &self.outcome
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
struct BranchAttemptCursor {
    visit: u16,
    attempt: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BranchRuntimeState {
    node_id: GraphNodeId,
    max_attempts: u16,
    attempts: Vec<BranchAttemptRecord>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    attempt_in_progress: Option<BranchAttemptCursor>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    retry_scheduled: Option<BranchAttemptCursor>,
}

impl BranchRuntimeState {
    pub(crate) fn attempts(&self) -> &[BranchAttemptRecord] {
        &self.attempts
    }

    pub(crate) fn attempt_in_progress(&self) -> Option<u16> {
        self.attempt_in_progress.map(|cursor| cursor.attempt)
    }

    pub(crate) fn retry_scheduled(&self) -> bool {
        self.retry_scheduled.is_some()
    }

    pub(crate) fn successful_outcome(&self) -> Option<&BranchSuccess> {
        self.attempts
            .last()
            .and_then(|attempt| match &attempt.outcome {
                BranchOutcome::Success { success } => Some(success),
                BranchOutcome::RetryableFailure { .. } | BranchOutcome::Failure { .. } => None,
            })
    }

    fn is_terminal_for_visit(&self, visit: u16) -> bool {
        self.attempt_in_progress.is_none()
            && self.retry_scheduled.is_none()
            && self.attempts.last().is_some_and(|attempt| {
                attempt.visit == visit
                    && matches!(
                        attempt.outcome,
                        BranchOutcome::Success { .. } | BranchOutcome::Failure { .. }
                    )
            })
    }

    fn route_class_for_visit(&self, visit: u16) -> Option<BranchOutcomeClass> {
        if self.attempt_in_progress.is_some() || self.retry_scheduled.is_some() {
            return None;
        }
        self.attempts
            .last()
            .filter(|attempt| attempt.visit == visit)
            .map(|attempt| attempt.outcome.class())
    }

    fn validate(&self) -> Result<()> {
        if self.max_attempts == 0
            || self.max_attempts > MAX_BRANCH_ATTEMPTS
            || self.attempts.len() > MAX_BRANCH_HISTORY_RECORDS
        {
            bail!("durable branch runtime exceeds its attempt or history bound");
        }
        let mut previous: Option<&BranchAttemptRecord> = None;
        for attempt in &self.attempts {
            if attempt.visit == 0 || attempt.attempt == 0 || attempt.attempt > self.max_attempts {
                bail!("durable branch attempt history exceeds a visit attempt bound");
            }
            attempt.outcome.validate()?;
            if let Some(previous_attempt) = previous {
                let expected = if matches!(
                    previous_attempt.outcome,
                    BranchOutcome::RetryableFailure { .. }
                ) {
                    BranchAttemptCursor {
                        visit: previous_attempt.visit,
                        attempt: previous_attempt
                            .attempt
                            .checked_add(1)
                            .context("durable branch retry attempt overflowed")?,
                    }
                } else {
                    BranchAttemptCursor {
                        visit: previous_attempt
                            .visit
                            .checked_add(1)
                            .context("durable branch visit history overflowed")?,
                        attempt: 1,
                    }
                };
                if attempt.visit != expected.visit || attempt.attempt != expected.attempt {
                    bail!("durable branch attempt history is not contiguous by visit");
                }
            } else if attempt.visit != 1 || attempt.attempt != 1 {
                bail!("durable branch attempt history does not begin at visit one");
            }
            previous = Some(attempt);
        }
        if self.attempts.last().is_some_and(|attempt| {
            matches!(attempt.outcome, BranchOutcome::RetryableFailure { .. })
                && attempt.attempt == self.max_attempts
        }) {
            bail!("durable branch ends with retryable failure at its hard attempt bound");
        }
        if let Some(in_progress) = self.attempt_in_progress {
            let expected = next_attempt_cursor(&self.attempts)?;
            if in_progress != expected
                || in_progress.attempt > self.max_attempts
                || self.retry_scheduled.is_some()
            {
                bail!("durable branch in-progress attempt is contradictory");
            }
        }
        if let Some(retry) = self.retry_scheduled {
            if self.attempt_in_progress.is_some()
                || retry != next_attempt_cursor(&self.attempts)?
                || !self.attempts.last().is_some_and(|attempt| {
                    matches!(attempt.outcome, BranchOutcome::RetryableFailure { .. })
                })
            {
                bail!("durable branch retry marker has no matching retryable failure");
            }
        }
        Ok(())
    }
}

fn next_attempt_cursor(attempts: &[BranchAttemptRecord]) -> Result<BranchAttemptCursor> {
    let Some(previous) = attempts.last() else {
        return Ok(BranchAttemptCursor {
            visit: 1,
            attempt: 1,
        });
    };
    if matches!(previous.outcome, BranchOutcome::RetryableFailure { .. }) {
        Ok(BranchAttemptCursor {
            visit: previous.visit,
            attempt: previous
                .attempt
                .checked_add(1)
                .context("durable branch retry attempt overflowed")?,
        })
    } else {
        Ok(BranchAttemptCursor {
            visit: previous
                .visit
                .checked_add(1)
                .context("durable branch visit overflowed")?,
            attempt: 1,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
struct LoopRuntimeState {
    completed_iterations: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    current_decision: Option<LoopDecisionRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
struct LoopDecisionRecord {
    iteration: u16,
    decision: LoopDecision,
    routed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DurableGraphRuntimeState {
    definition: DurableGraphDefinition,
    event_count: usize,
    node_visits: BTreeMap<GraphNodeId, u16>,
    routed_visits: BTreeMap<GraphNodeId, u16>,
    active_nodes: BTreeSet<GraphNodeId>,
    edge_traversals: BTreeMap<GraphEdgeId, u16>,
    branches: BTreeMap<GraphBranchId, BranchRuntimeState>,
    joins: BTreeMap<GraphNodeId, FanInResult>,
    join_arrivals: BTreeMap<GraphNodeId, BTreeSet<GraphBranchId>>,
    loops: BTreeMap<GraphNodeId, LoopRuntimeState>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    termination: Option<GraphTerminationRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
struct GraphTerminationRecord {
    node_id: GraphNodeId,
    outcome: GraphTermination,
}

impl DurableGraphRuntimeState {
    pub(crate) fn definition(&self) -> &DurableGraphDefinition {
        &self.definition
    }

    pub(crate) fn branch(&self, branch_id: &GraphBranchId) -> Option<&BranchRuntimeState> {
        self.branches.get(branch_id)
    }

    pub(crate) fn join_result(&self, node_id: &GraphNodeId) -> Option<FanInResult> {
        self.joins.get(node_id).copied()
    }

    pub(crate) fn loop_iterations(&self, node_id: &GraphNodeId) -> Option<u16> {
        self.loops
            .get(node_id)
            .map(|runtime| runtime.completed_iterations)
    }

    pub(crate) fn termination(&self) -> Option<GraphTermination> {
        self.termination.as_ref().map(|record| record.outcome)
    }

    pub(crate) fn reached(&self, node_id: &GraphNodeId) -> bool {
        self.node_visits.get(node_id).copied().unwrap_or(0) > 0
    }

    pub(crate) fn node_visit(&self, node_id: &GraphNodeId) -> Option<u16> {
        self.node_visits.get(node_id).copied()
    }

    pub(crate) fn active_node_ids(&self) -> impl Iterator<Item = &GraphNodeId> {
        self.active_nodes.iter()
    }

    pub(crate) fn eligible_edge_ids(
        &self,
        source_node_id: &GraphNodeId,
    ) -> Result<Vec<GraphEdgeId>> {
        let visit = self
            .node_visits
            .get(source_node_id)
            .copied()
            .context("durable graph edge query names an unknown source node")?;
        let routed = self
            .routed_visits
            .get(source_node_id)
            .copied()
            .context("durable graph edge query source has no routed state")?;
        if routed.checked_add(1) != Some(visit) {
            bail!("durable graph edge query source is not at an unrouted visit");
        }
        ensure_source_visit_complete(self, source_node_id, visit)?;
        compute_eligible_edge_ids(self, source_node_id)
    }

    pub(crate) fn expected_join_result(&self, join_node_id: &GraphNodeId) -> Result<FanInResult> {
        let node = self.definition.node(join_node_id)?;
        let DurableGraphNodeKind::Join { branches } = &node.kind else {
            bail!("durable graph fan-in query names a non-join node");
        };
        let arrivals = self
            .join_arrivals
            .get(join_node_id)
            .context("durable graph fan-in query has no arrival frontier")?;
        if arrivals != &branches.iter().cloned().collect::<BTreeSet<_>>() {
            bail!("durable graph fan-in query occurs before every required branch arrives");
        }
        derive_fan_in_result(self, branches)
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.definition.validate()?;
        if self.event_count == 0 || self.event_count > MAX_GRAPH_EVENTS {
            bail!("durable graph runtime event history count is out of bounds");
        }
        if self.node_visits.len() != self.definition.nodes.len()
            || self.routed_visits.len() != self.definition.nodes.len()
            || self.edge_traversals.len() > self.definition.edges.len()
        {
            bail!("durable graph runtime indexes do not match its definition");
        }
        let mut expected_active = BTreeSet::new();
        for node in &self.definition.nodes {
            let visits = self
                .node_visits
                .get(&node.id)
                .context("durable graph runtime has no node-visit entry")?;
            let routed = self
                .routed_visits
                .get(&node.id)
                .context("durable graph runtime has no routed-visit entry")?;
            if *visits > MAX_NODE_VISITS || routed > visits {
                bail!("durable graph runtime node visits are malformed or out of bounds");
            }
            if visits > routed {
                expected_active.insert(node.id.clone());
            }
        }
        if self.active_nodes != expected_active {
            bail!("durable graph runtime active frontier contradicts its visit history");
        }
        for edge_id in self.edge_traversals.keys() {
            if !self.definition.edges.iter().any(|edge| &edge.id == edge_id) {
                bail!("durable graph runtime traversed an unknown edge");
            }
        }
        for edge in &self.definition.edges {
            let traversals = self.edge_traversals.get(&edge.id).copied().unwrap_or(0);
            if self.edge_traversals.contains_key(&edge.id) && traversals == 0 {
                bail!("durable graph runtime stores a zero-count edge traversal");
            }
            match &edge.kind {
                DurableGraphEdgeKind::Forward | DurableGraphEdgeKind::JoinArrival { .. }
                    if traversals > 1 =>
                {
                    bail!("durable graph forward edge repeated")
                }
                DurableGraphEdgeKind::LoopBody { loop_node_id }
                | DurableGraphEdgeKind::LoopBack { loop_node_id } => {
                    let max_iterations = match self.definition.node(loop_node_id)?.kind {
                        DurableGraphNodeKind::Loop { max_iterations } => max_iterations,
                        _ => bail!("durable graph loop-scoped edge lost its loop"),
                    };
                    if traversals > max_iterations {
                        bail!("durable graph loop-scoped edge exceeds its loop bound");
                    }
                }
                DurableGraphEdgeKind::Forward | DurableGraphEdgeKind::JoinArrival { .. } => {}
            }
        }
        for (branch_id, branch) in &self.branches {
            branch.validate()?;
            let node = self.definition.node(&branch.node_id)?;
            let DurableGraphNodeKind::Task {
                branch_id: expected_branch_id,
                max_attempts,
            } = &node.kind
            else {
                bail!("durable graph runtime branch names a non-task node");
            };
            if branch_id != expected_branch_id || branch.max_attempts != *max_attempts {
                bail!("durable graph runtime branch binding contradicts its definition");
            }
            let visits = self.node_visits.get(&branch.node_id).copied().unwrap_or(0);
            let routed = self
                .routed_visits
                .get(&branch.node_id)
                .copied()
                .unwrap_or(0);
            let last_history_visit = branch
                .attempts
                .last()
                .map(|attempt| attempt.visit)
                .unwrap_or(0);
            if last_history_visit > visits
                || visits > last_history_visit.saturating_add(1)
                || last_history_visit < routed
                || routed.checked_add(1).is_none_or(|next| next < visits)
                || branch
                    .attempt_in_progress
                    .is_some_and(|attempt| attempt.visit != visits || routed >= visits)
                || branch
                    .retry_scheduled
                    .is_some_and(|attempt| attempt.visit != visits || routed >= visits)
            {
                bail!("durable graph runtime branch history exceeds its reached visit frontier");
            }
        }
        for (node_id, result) in &self.joins {
            let node = self.definition.node(node_id)?;
            let DurableGraphNodeKind::Join { branches } = &node.kind else {
                bail!("durable graph runtime join result names a non-join node");
            };
            if self.join_arrivals.get(node_id)
                != Some(&branches.iter().cloned().collect::<BTreeSet<_>>())
                || derive_fan_in_result(self, branches)? != *result
            {
                bail!("durable graph runtime join result is not derived from its branches");
            }
        }
        for (join_node_id, arrivals) in &self.join_arrivals {
            let node = self.definition.node(join_node_id)?;
            let DurableGraphNodeKind::Join { branches } = &node.kind else {
                bail!("durable graph runtime join arrival names a non-join node");
            };
            if !arrivals.is_subset(&branches.iter().cloned().collect()) {
                bail!("durable graph runtime join arrival names an unrelated branch");
            }
        }
        for edge in &self.definition.edges {
            let DurableGraphEdgeKind::JoinArrival { branch_id } = &edge.kind else {
                continue;
            };
            let traversed = self.edge_traversals.get(&edge.id).copied().unwrap_or(0) == 1;
            let arrived = self
                .join_arrivals
                .get(&edge.to)
                .is_some_and(|arrivals| arrivals.contains(branch_id));
            if traversed != arrived {
                bail!("durable graph runtime join arrival contradicts edge traversal history");
            }
        }
        for (loop_node_id, runtime) in &self.loops {
            let node = self.definition.node(loop_node_id)?;
            let DurableGraphNodeKind::Loop { max_iterations } = node.kind else {
                bail!("durable graph runtime loop state names a non-loop node");
            };
            if runtime.completed_iterations > max_iterations {
                bail!("durable graph runtime loop exceeds its hard bound");
            }
            if let Some(decision) = &runtime.current_decision {
                if decision.iteration != runtime.completed_iterations {
                    bail!("durable graph runtime loop decision is out of sequence");
                }
                if decision.decision == LoopDecision::Continue
                    && decision.iteration >= max_iterations
                {
                    bail!("durable graph runtime continues at its hard loop bound");
                }
            }
        }
        if self.branches.len()
            != self
                .definition
                .nodes
                .iter()
                .filter(|node| matches!(node.kind, DurableGraphNodeKind::Task { .. }))
                .count()
            || self.loops.len()
                != self
                    .definition
                    .nodes
                    .iter()
                    .filter(|node| matches!(node.kind, DurableGraphNodeKind::Loop { .. }))
                    .count()
        {
            bail!("durable graph runtime branch or loop index is incomplete");
        }
        if self.join_arrivals.len()
            != self
                .definition
                .nodes
                .iter()
                .filter(|node| matches!(node.kind, DurableGraphNodeKind::Join { .. }))
                .count()
        {
            bail!("durable graph runtime join-arrival index is incomplete");
        }
        if let Some(termination) = &self.termination {
            let node = self.definition.node(&termination.node_id)?;
            if !matches!(
                &node.kind,
                DurableGraphNodeKind::Terminate { outcome }
                    if *outcome == termination.outcome
            ) || self.node_visits.get(&termination.node_id)
                != self.routed_visits.get(&termination.node_id)
                || !self.active_nodes.is_empty()
            {
                bail!("durable graph runtime termination provenance is invalid");
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(tag = "event", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum DurableGraphEvent {
    Defined {
        definition: DurableGraphDefinition,
    },
    BranchAttemptStarted {
        branch_id: GraphBranchId,
        visit: u16,
        attempt: u16,
    },
    BranchAttemptCompleted {
        branch_id: GraphBranchId,
        visit: u16,
        attempt: u16,
        outcome: BranchOutcome,
    },
    BranchRetryScheduled {
        branch_id: GraphBranchId,
        visit: u16,
        next_attempt: u16,
    },
    JoinResolved {
        join_node_id: GraphNodeId,
        result: FanInResult,
    },
    LoopIterationCompleted {
        loop_node_id: GraphNodeId,
        iteration: u16,
        decision: LoopDecision,
    },
    EdgesSelected {
        source_node_id: GraphNodeId,
        visit: u16,
        edge_ids: Vec<GraphEdgeId>,
    },
    Terminated {
        node_id: GraphNodeId,
        outcome: GraphTermination,
    },
}

impl DurableGraphEvent {
    pub(crate) fn phase(&self) -> &'static str {
        match self {
            Self::Defined { .. } => "graph_defined",
            Self::BranchAttemptStarted { .. } => "graph_branch_attempt_started",
            Self::BranchAttemptCompleted { .. } => "graph_branch_attempt_completed",
            Self::BranchRetryScheduled { .. } => "graph_branch_retry_scheduled",
            Self::JoinResolved { .. } => "graph_join_resolved",
            Self::LoopIterationCompleted { .. } => "graph_loop_iteration_completed",
            Self::EdgesSelected { .. } => "graph_edges_selected",
            Self::Terminated { .. } => "graph_terminated",
        }
    }

    pub(crate) fn subject(&self) -> Option<&str> {
        match self {
            Self::Defined { .. } => None,
            Self::BranchAttemptStarted { branch_id, .. }
            | Self::BranchAttemptCompleted { branch_id, .. }
            | Self::BranchRetryScheduled { branch_id, .. } => Some(branch_id.as_str()),
            Self::JoinResolved { join_node_id, .. } => Some(join_node_id.as_str()),
            Self::LoopIterationCompleted { loop_node_id, .. } => Some(loop_node_id.as_str()),
            Self::EdgesSelected { source_node_id, .. } => Some(source_node_id.as_str()),
            Self::Terminated { node_id, .. } => Some(node_id.as_str()),
        }
    }
}

pub(crate) fn replay_graph_events(
    events: &[DurableGraphEvent],
) -> Result<DurableGraphRuntimeState> {
    if events.is_empty() {
        bail!("durable graph replay has no definition event");
    }
    if events.len() > MAX_GRAPH_EVENTS {
        bail!("durable graph replay exceeds its fixed event bound");
    }
    let mut state = None;
    for event in events {
        state = Some(apply_graph_event(state.as_ref(), event)?);
    }
    state.context("durable graph replay produced no runtime state")
}

pub(crate) fn apply_graph_event(
    state: Option<&DurableGraphRuntimeState>,
    event: &DurableGraphEvent,
) -> Result<DurableGraphRuntimeState> {
    match (state, event) {
        (None, DurableGraphEvent::Defined { definition }) => initialize_state(definition.clone()),
        (None, _) => bail!("durable graph must begin with its definition event"),
        (Some(_), DurableGraphEvent::Defined { .. }) => {
            bail!("durable graph definition event cannot repeat")
        }
        (Some(state), event) => {
            if state.termination.is_some() {
                bail!("durable graph cannot transition after explicit termination");
            }
            if state.event_count >= MAX_GRAPH_EVENTS {
                bail!("durable graph transition exceeds its fixed event-history bound");
            }
            let mut next = state.clone();
            apply_initialized_event(&mut next, event)?;
            next.event_count = next
                .event_count
                .checked_add(1)
                .context("durable graph event-history count overflowed")?;
            next.validate()?;
            Ok(next)
        }
    }
}

fn initialize_state(definition: DurableGraphDefinition) -> Result<DurableGraphRuntimeState> {
    definition.validate()?;
    let mut node_visits = BTreeMap::new();
    let mut routed_visits = BTreeMap::new();
    let mut branches = BTreeMap::new();
    let mut join_arrivals = BTreeMap::new();
    let mut loops = BTreeMap::new();
    for node in &definition.nodes {
        node_visits.insert(node.id.clone(), 0);
        routed_visits.insert(node.id.clone(), 0);
        match &node.kind {
            DurableGraphNodeKind::Task {
                branch_id,
                max_attempts,
            } => {
                branches.insert(
                    branch_id.clone(),
                    BranchRuntimeState {
                        node_id: node.id.clone(),
                        max_attempts: *max_attempts,
                        attempts: Vec::new(),
                        attempt_in_progress: None,
                        retry_scheduled: None,
                    },
                );
            }
            DurableGraphNodeKind::Loop { .. } => {
                loops.insert(
                    node.id.clone(),
                    LoopRuntimeState {
                        completed_iterations: 0,
                        current_decision: None,
                    },
                );
            }
            DurableGraphNodeKind::Join { .. } => {
                join_arrivals.insert(node.id.clone(), BTreeSet::new());
            }
            DurableGraphNodeKind::Fork
            | DurableGraphNodeKind::Choice
            | DurableGraphNodeKind::Terminate { .. } => {}
        }
    }
    node_visits.insert(definition.entry_node_id.clone(), 1);
    let entry_node_id = definition.entry_node_id.clone();
    let state = DurableGraphRuntimeState {
        definition,
        event_count: 1,
        node_visits,
        routed_visits,
        active_nodes: BTreeSet::from([entry_node_id]),
        edge_traversals: BTreeMap::new(),
        branches,
        joins: BTreeMap::new(),
        join_arrivals,
        loops,
        termination: None,
    };
    state.validate()?;
    Ok(state)
}

fn apply_initialized_event(
    state: &mut DurableGraphRuntimeState,
    event: &DurableGraphEvent,
) -> Result<()> {
    match event {
        DurableGraphEvent::Defined { .. } => {
            bail!("durable graph definition event cannot repeat")
        }
        DurableGraphEvent::BranchAttemptStarted {
            branch_id,
            visit,
            attempt,
        } => start_branch_attempt(state, branch_id, *visit, *attempt),
        DurableGraphEvent::BranchAttemptCompleted {
            branch_id,
            visit,
            attempt,
            outcome,
        } => complete_branch_attempt(state, branch_id, *visit, *attempt, outcome),
        DurableGraphEvent::BranchRetryScheduled {
            branch_id,
            visit,
            next_attempt,
        } => schedule_branch_retry(state, branch_id, *visit, *next_attempt),
        DurableGraphEvent::JoinResolved {
            join_node_id,
            result,
        } => resolve_join(state, join_node_id, *result),
        DurableGraphEvent::LoopIterationCompleted {
            loop_node_id,
            iteration,
            decision,
        } => complete_loop_iteration(state, loop_node_id, *iteration, *decision),
        DurableGraphEvent::EdgesSelected {
            source_node_id,
            visit,
            edge_ids,
        } => select_edges(state, source_node_id, *visit, edge_ids),
        DurableGraphEvent::Terminated { node_id, outcome } => {
            terminate_graph(state, node_id, *outcome)
        }
    }
}

fn start_branch_attempt(
    state: &mut DurableGraphRuntimeState,
    branch_id: &GraphBranchId,
    visit: u16,
    attempt: u16,
) -> Result<()> {
    let branch = state
        .branches
        .get_mut(branch_id)
        .context("durable graph branch attempt names an unknown branch")?;
    let observed = BranchAttemptCursor { visit, attempt };
    let expected = next_attempt_cursor(&branch.attempts)?;
    if observed != expected || attempt == 0 || attempt > branch.max_attempts {
        bail!("durable graph branch attempt skips or repeats a visit or attempt number");
    }
    if branch.attempt_in_progress.is_some() {
        bail!("durable graph branch already has an attempt in progress");
    }
    if attempt == 1 && branch.retry_scheduled.is_some() {
        bail!("durable graph initial visit attempt contradicts a retry marker");
    }
    if attempt > 1 && branch.retry_scheduled != Some(observed) {
        bail!("durable graph branch retry was not durably scheduled");
    }
    let visits = state
        .node_visits
        .get(&branch.node_id)
        .copied()
        .context("durable graph branch node has no visit state")?;
    let routed = state
        .routed_visits
        .get(&branch.node_id)
        .copied()
        .context("durable graph branch node has no routed-visit state")?;
    if visits != visit || routed.checked_add(1) != Some(visit) {
        bail!("durable graph branch attempt starts before its task node is reached");
    }
    branch.retry_scheduled = None;
    branch.attempt_in_progress = Some(observed);
    Ok(())
}

fn complete_branch_attempt(
    state: &mut DurableGraphRuntimeState,
    branch_id: &GraphBranchId,
    visit: u16,
    attempt: u16,
    outcome: &BranchOutcome,
) -> Result<()> {
    outcome.validate()?;
    let branch = state
        .branches
        .get_mut(branch_id)
        .context("durable graph branch completion names an unknown branch")?;
    if branch.attempt_in_progress != Some(BranchAttemptCursor { visit, attempt }) {
        bail!("durable graph branch completion skips, repeats, or contradicts its start");
    }
    if matches!(outcome, BranchOutcome::RetryableFailure { .. }) && attempt >= branch.max_attempts {
        bail!("durable graph retryable failure reached the hard attempt bound");
    }
    branch.attempts.push(BranchAttemptRecord {
        visit,
        attempt,
        outcome: outcome.clone(),
    });
    branch.attempt_in_progress = None;
    Ok(())
}

fn schedule_branch_retry(
    state: &mut DurableGraphRuntimeState,
    branch_id: &GraphBranchId,
    visit: u16,
    next_attempt: u16,
) -> Result<()> {
    let branch = state
        .branches
        .get_mut(branch_id)
        .context("durable graph retry names an unknown branch")?;
    if branch.attempt_in_progress.is_some() || branch.retry_scheduled.is_some() {
        bail!("durable graph retry transition repeats or overlaps another attempt");
    }
    let observed = BranchAttemptCursor {
        visit,
        attempt: next_attempt,
    };
    if observed != next_attempt_cursor(&branch.attempts)? || next_attempt > branch.max_attempts {
        bail!("durable graph retry skips a visit or attempt or exceeds its hard bound");
    }
    if !branch
        .attempts
        .last()
        .is_some_and(|attempt| matches!(attempt.outcome, BranchOutcome::RetryableFailure { .. }))
    {
        bail!("durable graph retry does not follow a retryable failure");
    }
    let routed = state
        .routed_visits
        .get(&branch.node_id)
        .copied()
        .context("durable graph branch node has no routed-visit state")?;
    let visits = state
        .node_visits
        .get(&branch.node_id)
        .copied()
        .context("durable graph branch node has no visit state")?;
    if visits != visit || routed.checked_add(1) != Some(visit) {
        bail!("durable graph retry does not belong to the active task visit");
    }
    branch.retry_scheduled = Some(observed);
    Ok(())
}

fn resolve_join(
    state: &mut DurableGraphRuntimeState,
    join_node_id: &GraphNodeId,
    observed: FanInResult,
) -> Result<()> {
    if state.joins.contains_key(join_node_id) {
        bail!("durable graph join resolution repeated");
    }
    if !state.reached(join_node_id) {
        bail!("durable graph join resolved before it was reached");
    }
    let node = state.definition.node(join_node_id)?;
    let DurableGraphNodeKind::Join { branches } = &node.kind else {
        bail!("durable graph join resolution names a non-join node");
    };
    let arrivals = state
        .join_arrivals
        .get(join_node_id)
        .context("durable graph join has no arrival frontier")?;
    if arrivals != &branches.iter().cloned().collect::<BTreeSet<_>>() {
        bail!("durable graph join cannot resolve before every required branch arrives");
    }
    let derived = derive_fan_in_result(state, branches)?;
    if observed != derived {
        bail!("durable graph join result contradicts immutable branch outcomes");
    }
    state.joins.insert(join_node_id.clone(), derived);
    Ok(())
}

fn complete_loop_iteration(
    state: &mut DurableGraphRuntimeState,
    loop_node_id: &GraphNodeId,
    iteration: u16,
    decision: LoopDecision,
) -> Result<()> {
    if !state.reached(loop_node_id) {
        bail!("durable graph loop decision occurs before the loop is reached");
    }
    let max_iterations = match state.definition.node(loop_node_id)?.kind {
        DurableGraphNodeKind::Loop { max_iterations } => max_iterations,
        _ => bail!("durable graph loop decision names a non-loop node"),
    };
    let runtime = state
        .loops
        .get_mut(loop_node_id)
        .context("durable graph loop has no runtime state")?;
    if runtime
        .current_decision
        .as_ref()
        .is_some_and(|record| !record.routed)
    {
        bail!("durable graph loop decision repeats before its route is selected");
    }
    let expected = runtime
        .completed_iterations
        .checked_add(1)
        .context("durable graph loop iteration overflowed")?;
    if iteration != expected || iteration > max_iterations {
        bail!("durable graph loop iteration skips, repeats, or exceeds its bound");
    }
    if decision == LoopDecision::Continue && iteration >= max_iterations {
        bail!("durable graph loop cannot continue at its hard iteration bound");
    }
    let visits = state
        .node_visits
        .get(loop_node_id)
        .copied()
        .context("durable graph loop has no visit state")?;
    if visits != iteration {
        bail!("durable graph loop iteration does not match its durable visit");
    }
    runtime.completed_iterations = iteration;
    runtime.current_decision = Some(LoopDecisionRecord {
        iteration,
        decision,
        routed: false,
    });
    Ok(())
}

fn select_edges(
    state: &mut DurableGraphRuntimeState,
    source_node_id: &GraphNodeId,
    visit: u16,
    observed_edge_ids: &[GraphEdgeId],
) -> Result<()> {
    if observed_edge_ids.is_empty() || observed_edge_ids.len() > MAX_GRAPH_EDGES {
        bail!("durable graph edge selection is empty or exceeds its bound");
    }
    let visits = state
        .node_visits
        .get(source_node_id)
        .copied()
        .context("durable graph edge selection names an unknown source node")?;
    let routed = state
        .routed_visits
        .get(source_node_id)
        .copied()
        .context("durable graph source node has no routed-visit state")?;
    let expected_visit = routed
        .checked_add(1)
        .context("durable graph routed-visit count overflowed")?;
    if visit != expected_visit || visit > visits {
        bail!("durable graph edge selection skips or repeats a source visit");
    }
    ensure_source_visit_complete(state, source_node_id, visit)?;

    let expected_edge_ids = compute_eligible_edge_ids(state, source_node_id)?;
    if observed_edge_ids != expected_edge_ids {
        bail!("durable graph edge selection is partial, repeated, or condition-mismatched");
    }

    let selected_edges = observed_edge_ids
        .iter()
        .map(|edge_id| state.definition.edge(edge_id).cloned())
        .collect::<Result<Vec<_>>>()?;
    for edge in &selected_edges {
        let count = state.edge_traversals.get(&edge.id).copied().unwrap_or(0);
        match &edge.kind {
            DurableGraphEdgeKind::Forward | DurableGraphEdgeKind::JoinArrival { .. }
                if count != 0 =>
            {
                bail!("durable graph forward edge transition repeated")
            }
            DurableGraphEdgeKind::LoopBody { loop_node_id }
            | DurableGraphEdgeKind::LoopBack { loop_node_id } => {
                let iterations = state
                    .loops
                    .get(loop_node_id)
                    .map(|runtime| runtime.completed_iterations)
                    .context("durable graph loop-scoped edge has no loop runtime")?;
                if count >= iterations {
                    bail!("durable graph loop-scoped edge skips or repeats an iteration");
                }
            }
            DurableGraphEdgeKind::Forward | DurableGraphEdgeKind::JoinArrival { .. } => {}
        }
    }

    for edge in selected_edges {
        let count = state.edge_traversals.entry(edge.id.clone()).or_insert(0);
        *count = count
            .checked_add(1)
            .context("durable graph edge traversal count overflowed")?;
        reach_destination(state, &edge)?;
    }
    state.routed_visits.insert(source_node_id.clone(), visit);
    let remaining_visits = state
        .node_visits
        .get(source_node_id)
        .copied()
        .context("durable graph routed source lost its visit state")?;
    if remaining_visits == visit {
        state.active_nodes.remove(source_node_id);
    }
    if let Some(runtime) = state.loops.get_mut(source_node_id) {
        let decision = runtime
            .current_decision
            .as_mut()
            .context("durable graph loop route has no decision")?;
        if decision.routed {
            bail!("durable graph loop decision route repeated");
        }
        decision.routed = true;
    }
    Ok(())
}

fn ensure_source_visit_complete(
    state: &DurableGraphRuntimeState,
    source_node_id: &GraphNodeId,
    visit: u16,
) -> Result<()> {
    let node = state.definition.node(source_node_id)?;
    match &node.kind {
        DurableGraphNodeKind::Task { branch_id, .. } => {
            let branch = state
                .branches
                .get(branch_id)
                .context("durable graph task has no branch runtime")?;
            if !branch.is_terminal_for_visit(visit) {
                bail!("durable graph task routes before its exact attempt completes");
            }
        }
        DurableGraphNodeKind::Join { .. } => {
            if visit != 1 || !state.joins.contains_key(source_node_id) {
                bail!("durable graph join routes before its immutable result is resolved");
            }
        }
        DurableGraphNodeKind::Loop { .. } => {
            let runtime = state
                .loops
                .get(source_node_id)
                .context("durable graph loop has no runtime state")?;
            if runtime
                .current_decision
                .as_ref()
                .is_none_or(|decision| decision.iteration != visit || decision.routed)
            {
                bail!("durable graph loop routes before its exact decision is recorded");
            }
        }
        DurableGraphNodeKind::Terminate { .. } => {
            bail!("durable graph termination node cannot select edges")
        }
        DurableGraphNodeKind::Fork | DurableGraphNodeKind::Choice => {}
    }
    Ok(())
}

fn compute_eligible_edge_ids(
    state: &DurableGraphRuntimeState,
    source_node_id: &GraphNodeId,
) -> Result<Vec<GraphEdgeId>> {
    let mut edge_ids = Vec::new();
    for edge in state
        .definition
        .edges
        .iter()
        .filter(|edge| &edge.from == source_node_id)
    {
        if condition_matches(state, &edge.condition)? {
            edge_ids.push(edge.id.clone());
        }
    }
    edge_ids.sort();
    if edge_ids.is_empty() {
        bail!("durable graph reached a node with no currently valid route");
    }
    Ok(edge_ids)
}

fn condition_matches(
    state: &DurableGraphRuntimeState,
    condition: &DurableEdgeCondition,
) -> Result<bool> {
    match condition {
        DurableEdgeCondition::Always => Ok(true),
        DurableEdgeCondition::BranchLatestOutcome { branch_id, outcome } => Ok(state
            .branches
            .get(branch_id)
            .map(|branch| {
                let visit = state.node_visits.get(&branch.node_id).copied().unwrap_or(0);
                branch.route_class_for_visit(visit)
            })
            .context("durable graph edge condition lost its branch runtime")?
            == Some(*outcome)),
        DurableEdgeCondition::JoinResult {
            join_node_id,
            result,
        } => Ok(state.joins.get(join_node_id).copied() == Some(*result)),
        DurableEdgeCondition::LoopDecision {
            loop_node_id,
            decision,
        } => Ok(state
            .loops
            .get(loop_node_id)
            .context("durable graph edge condition lost its loop runtime")?
            .current_decision
            .as_ref()
            .is_some_and(|record| !record.routed && record.decision == *decision)),
    }
}

fn reach_destination(state: &mut DurableGraphRuntimeState, edge: &DurableGraphEdge) -> Result<()> {
    if let DurableGraphEdgeKind::JoinArrival { branch_id } = &edge.kind {
        let arrivals = state
            .join_arrivals
            .get_mut(&edge.to)
            .context("durable graph join arrival has no destination frontier")?;
        if !arrivals.insert(branch_id.clone()) {
            bail!("durable graph join branch arrival repeated");
        }
    }
    let destination = state.definition.node(&edge.to)?;
    let visits = state
        .node_visits
        .get_mut(&edge.to)
        .context("durable graph destination has no visit state")?;
    match destination.kind {
        DurableGraphNodeKind::Join { .. } => {
            *visits = 1;
        }
        DurableGraphNodeKind::Loop { .. }
            if matches!(edge.kind, DurableGraphEdgeKind::LoopBack { .. }) =>
        {
            *visits = visits
                .checked_add(1)
                .context("durable graph loop visit count overflowed")?;
        }
        _ => {
            if matches!(
                edge.kind,
                DurableGraphEdgeKind::Forward | DurableGraphEdgeKind::JoinArrival { .. }
            ) && *visits != 0
            {
                bail!("durable graph forward transition repeats a reached node");
            }
            *visits = visits
                .checked_add(1)
                .context("durable graph node visit count overflowed")?;
        }
    }
    if *visits > MAX_NODE_VISITS {
        bail!("durable graph node visit count exceeds its fixed bound");
    }
    state.active_nodes.insert(edge.to.clone());
    Ok(())
}

fn terminate_graph(
    state: &mut DurableGraphRuntimeState,
    node_id: &GraphNodeId,
    observed: GraphTermination,
) -> Result<()> {
    if !state.reached(node_id) {
        bail!("durable graph terminates before its termination node is reached");
    }
    let node = state.definition.node(node_id)?;
    let DurableGraphNodeKind::Terminate { outcome } = node.kind else {
        bail!("durable graph termination event names a non-termination node");
    };
    if outcome != observed {
        bail!("durable graph termination outcome contradicts its definition");
    }
    if state.active_nodes != BTreeSet::from([node_id.clone()]) {
        bail!("durable graph cannot terminate while another graph visit remains active");
    }
    let visits = state
        .node_visits
        .get(node_id)
        .copied()
        .context("durable graph termination node lost its visit state")?;
    state.routed_visits.insert(node_id.clone(), visits);
    state.active_nodes.remove(node_id);
    state.termination = Some(GraphTerminationRecord {
        node_id: node_id.clone(),
        outcome: observed,
    });
    Ok(())
}

fn derive_fan_in_result(
    state: &DurableGraphRuntimeState,
    branch_ids: &[GraphBranchId],
) -> Result<FanInResult> {
    let mut success_count = 0_usize;
    for branch_id in branch_ids {
        let branch = state
            .branches
            .get(branch_id)
            .context("durable graph join lost a required branch")?;
        let visit = state
            .node_visits
            .get(&branch.node_id)
            .copied()
            .context("durable graph join branch lost its visit state")?;
        let routed = state
            .routed_visits
            .get(&branch.node_id)
            .copied()
            .context("durable graph join branch lost its routed state")?;
        if !branch.is_terminal_for_visit(visit) || routed != visit {
            bail!("durable graph join cannot resolve while a branch is retryable or in progress");
        }
        if branch.successful_outcome().is_some() {
            success_count += 1;
        }
    }
    if success_count == branch_ids.len() {
        Ok(FanInResult::AllSuccess)
    } else if success_count == 0 {
        Ok(FanInResult::Failure)
    } else {
        Ok(FanInResult::PartialSuccess)
    }
}

fn is_strictly_sorted<'a, T>(mut values: impl Iterator<Item = &'a T>) -> bool
where
    T: Ord + 'a,
{
    let Some(mut previous) = values.next() else {
        return true;
    };
    for value in values {
        if previous >= value {
            return false;
        }
        previous = value;
    }
    true
}

fn validate_id(value: &str, label: &str) -> Result<()> {
    validate_text(value, label, MAX_ID_BYTES)?;
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        bail!("{label} contains an unsupported character");
    }
    Ok(())
}

fn validate_text(value: &str, label: &str, max_bytes: usize) -> Result<()> {
    if value.is_empty()
        || value.len() > max_bytes
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        bail!("{label} is empty, untrimmed, contains control text, or exceeds its byte bound");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn graph_id(value: &str) -> DurableGraphId {
        DurableGraphId::new(value).expect("valid graph id")
    }

    fn node_id(value: &str) -> GraphNodeId {
        GraphNodeId::new(value).expect("valid node id")
    }

    fn edge_id(value: &str) -> GraphEdgeId {
        GraphEdgeId::new(value).expect("valid edge id")
    }

    fn branch_id(value: &str) -> GraphBranchId {
        GraphBranchId::new(value).expect("valid branch id")
    }

    fn text(value: &str) -> DurableText {
        DurableText::new(value).expect("valid durable text")
    }

    fn node(value: &str, kind: DurableGraphNodeKind) -> DurableGraphNode {
        DurableGraphNode::new(node_id(value), kind)
    }

    fn edge(
        value: &str,
        from: &str,
        to: &str,
        kind: DurableGraphEdgeKind,
        condition: DurableEdgeCondition,
    ) -> DurableGraphEdge {
        DurableGraphEdge::new(edge_id(value), node_id(from), node_id(to), kind, condition)
    }

    fn success(result_ref: &str, write_refs: &[&str]) -> BranchOutcome {
        BranchOutcome::Success {
            success: BranchSuccess::new(
                text(result_ref),
                write_refs.iter().map(|value| text(value)).collect(),
            )
            .expect("valid success"),
        }
    }

    fn retryable(error: &str) -> BranchOutcome {
        BranchOutcome::RetryableFailure { error: text(error) }
    }

    fn failure(error: &str) -> BranchOutcome {
        BranchOutcome::Failure { error: text(error) }
    }

    #[derive(Default)]
    struct Trace {
        events: Vec<DurableGraphEvent>,
        state: Option<DurableGraphRuntimeState>,
    }

    impl Trace {
        fn apply(&mut self, event: DurableGraphEvent) {
            let canonical = serde_json::to_vec(&event).expect("serialize graph event");
            let decoded: DurableGraphEvent =
                serde_json::from_slice(&canonical).expect("strictly decode graph event");
            assert_eq!(
                serde_json::to_vec(&decoded).expect("re-serialize graph event"),
                canonical
            );
            let next = apply_graph_event(self.state.as_ref(), &decoded).expect("apply graph event");
            self.events.push(decoded);
            let replayed = replay_graph_events(&self.events).expect("replay after transition");
            assert_eq!(
                replayed,
                next,
                "replay diverged after event {}",
                self.events.len()
            );
            self.state = Some(next);
        }

        fn reject(&self, event: &DurableGraphEvent) {
            let before = self.state.clone();
            assert!(apply_graph_event(before.as_ref(), event).is_err());
            assert_eq!(
                self.state, before,
                "invalid transition mutated caller state"
            );
            if !self.events.is_empty() {
                assert_eq!(
                    replay_graph_events(&self.events).expect("replay unchanged trace"),
                    before.expect("state for non-empty trace")
                );
            }
        }

        fn state(&self) -> &DurableGraphRuntimeState {
            self.state.as_ref().expect("trace has state")
        }
    }

    fn conditional_definition() -> DurableGraphDefinition {
        let branch = branch_id("branch-main");
        DurableGraphDefinition::new(
            graph_id("graph-conditional"),
            node_id("n00-task"),
            vec![
                node(
                    "n00-task",
                    DurableGraphNodeKind::Task {
                        branch_id: branch.clone(),
                        max_attempts: 3,
                    },
                ),
                node(
                    "n10-success",
                    DurableGraphNodeKind::Terminate {
                        outcome: GraphTermination::Success,
                    },
                ),
                node(
                    "n20-failure",
                    DurableGraphNodeKind::Terminate {
                        outcome: GraphTermination::Failure,
                    },
                ),
            ],
            vec![
                edge(
                    "e00-success",
                    "n00-task",
                    "n10-success",
                    DurableGraphEdgeKind::Forward,
                    DurableEdgeCondition::BranchLatestOutcome {
                        branch_id: branch.clone(),
                        outcome: BranchOutcomeClass::Success,
                    },
                ),
                edge(
                    "e10-failure",
                    "n00-task",
                    "n20-failure",
                    DurableGraphEdgeKind::Forward,
                    DurableEdgeCondition::BranchLatestOutcome {
                        branch_id: branch,
                        outcome: BranchOutcomeClass::Failure,
                    },
                ),
            ],
        )
        .expect("valid conditional graph")
    }

    fn fan_in_definition() -> DurableGraphDefinition {
        let branch_a = branch_id("branch-a");
        let branch_b = branch_id("branch-b");
        let join = node_id("n30-join");
        DurableGraphDefinition::new(
            graph_id("graph-fan-in"),
            node_id("n00-fork"),
            vec![
                node("n00-fork", DurableGraphNodeKind::Fork),
                node(
                    "n10-a",
                    DurableGraphNodeKind::Task {
                        branch_id: branch_a.clone(),
                        max_attempts: 3,
                    },
                ),
                node(
                    "n20-b",
                    DurableGraphNodeKind::Task {
                        branch_id: branch_b.clone(),
                        max_attempts: 3,
                    },
                ),
                node(
                    "n30-join",
                    DurableGraphNodeKind::Join {
                        branches: vec![branch_a.clone(), branch_b.clone()],
                    },
                ),
                node(
                    "n40-all",
                    DurableGraphNodeKind::Terminate {
                        outcome: GraphTermination::Success,
                    },
                ),
                node(
                    "n50-partial",
                    DurableGraphNodeKind::Terminate {
                        outcome: GraphTermination::PartialSuccess,
                    },
                ),
                node(
                    "n60-failure",
                    DurableGraphNodeKind::Terminate {
                        outcome: GraphTermination::Failure,
                    },
                ),
            ],
            vec![
                edge(
                    "e00-fork-a",
                    "n00-fork",
                    "n10-a",
                    DurableGraphEdgeKind::Forward,
                    DurableEdgeCondition::Always,
                ),
                edge(
                    "e01-fork-b",
                    "n00-fork",
                    "n20-b",
                    DurableGraphEdgeKind::Forward,
                    DurableEdgeCondition::Always,
                ),
                edge(
                    "e10-a-join",
                    "n10-a",
                    "n30-join",
                    DurableGraphEdgeKind::JoinArrival {
                        branch_id: branch_a,
                    },
                    DurableEdgeCondition::Always,
                ),
                edge(
                    "e20-b-join",
                    "n20-b",
                    "n30-join",
                    DurableGraphEdgeKind::JoinArrival {
                        branch_id: branch_b,
                    },
                    DurableEdgeCondition::Always,
                ),
                edge(
                    "e30-all",
                    "n30-join",
                    "n40-all",
                    DurableGraphEdgeKind::Forward,
                    DurableEdgeCondition::JoinResult {
                        join_node_id: join.clone(),
                        result: FanInResult::AllSuccess,
                    },
                ),
                edge(
                    "e31-partial",
                    "n30-join",
                    "n50-partial",
                    DurableGraphEdgeKind::Forward,
                    DurableEdgeCondition::JoinResult {
                        join_node_id: join.clone(),
                        result: FanInResult::PartialSuccess,
                    },
                ),
                edge(
                    "e32-failure",
                    "n30-join",
                    "n60-failure",
                    DurableGraphEdgeKind::Forward,
                    DurableEdgeCondition::JoinResult {
                        join_node_id: join,
                        result: FanInResult::Failure,
                    },
                ),
            ],
        )
        .expect("valid fan-in graph")
    }

    fn define_and_fork() -> Trace {
        let mut trace = Trace::default();
        trace.apply(DurableGraphEvent::Defined {
            definition: fan_in_definition(),
        });
        trace.apply(DurableGraphEvent::EdgesSelected {
            source_node_id: node_id("n00-fork"),
            visit: 1,
            edge_ids: vec![edge_id("e00-fork-a"), edge_id("e01-fork-b")],
        });
        trace
    }

    fn complete_branch(
        trace: &mut Trace,
        branch: &str,
        task_node: &str,
        arrival_edge: &str,
        outcome: BranchOutcome,
    ) {
        trace.apply(DurableGraphEvent::BranchAttemptStarted {
            branch_id: branch_id(branch),
            visit: 1,
            attempt: 1,
        });
        trace.apply(DurableGraphEvent::BranchAttemptCompleted {
            branch_id: branch_id(branch),
            visit: 1,
            attempt: 1,
            outcome,
        });
        trace.apply(DurableGraphEvent::EdgesSelected {
            source_node_id: node_id(task_node),
            visit: 1,
            edge_ids: vec![edge_id(arrival_edge)],
        });
    }

    fn finish_join(trace: &mut Trace, result: FanInResult) {
        let (edge_name, termination_node, termination) = match result {
            FanInResult::AllSuccess => ("e30-all", "n40-all", GraphTermination::Success),
            FanInResult::PartialSuccess => (
                "e31-partial",
                "n50-partial",
                GraphTermination::PartialSuccess,
            ),
            FanInResult::Failure => ("e32-failure", "n60-failure", GraphTermination::Failure),
        };
        trace.apply(DurableGraphEvent::JoinResolved {
            join_node_id: node_id("n30-join"),
            result,
        });
        trace.apply(DurableGraphEvent::EdgesSelected {
            source_node_id: node_id("n30-join"),
            visit: 1,
            edge_ids: vec![edge_id(edge_name)],
        });
        trace.apply(DurableGraphEvent::Terminated {
            node_id: node_id(termination_node),
            outcome: termination,
        });
        assert_eq!(trace.state().termination(), Some(termination));
    }

    #[test]
    fn conditional_routing_retries_without_provisional_edge_effects() {
        let branch = branch_id("branch-main");
        let mut trace = Trace::default();
        trace.apply(DurableGraphEvent::Defined {
            definition: conditional_definition(),
        });
        for attempt in [1_u16, 2] {
            trace.apply(DurableGraphEvent::BranchAttemptStarted {
                branch_id: branch.clone(),
                visit: 1,
                attempt,
            });
            trace.apply(DurableGraphEvent::BranchAttemptCompleted {
                branch_id: branch.clone(),
                visit: 1,
                attempt,
                outcome: retryable(&format!("retry-{attempt}")),
            });
            trace.reject(&DurableGraphEvent::EdgesSelected {
                source_node_id: node_id("n00-task"),
                visit: 1,
                edge_ids: vec![edge_id("e00-success")],
            });
            trace.apply(DurableGraphEvent::BranchRetryScheduled {
                branch_id: branch.clone(),
                visit: 1,
                next_attempt: attempt + 1,
            });
        }
        trace.apply(DurableGraphEvent::BranchAttemptStarted {
            branch_id: branch.clone(),
            visit: 1,
            attempt: 3,
        });
        trace.apply(DurableGraphEvent::BranchAttemptCompleted {
            branch_id: branch.clone(),
            visit: 1,
            attempt: 3,
            outcome: success("result-main", &["write-1", "write-2"]),
        });
        trace.apply(DurableGraphEvent::EdgesSelected {
            source_node_id: node_id("n00-task"),
            visit: 1,
            edge_ids: vec![edge_id("e00-success")],
        });
        assert!(trace.state().reached(&node_id("n10-success")));
        assert!(!trace.state().reached(&node_id("n20-failure")));
        let runtime = trace.state().branch(&branch).expect("branch state");
        assert_eq!(
            runtime
                .attempts()
                .iter()
                .map(|attempt| (attempt.visit(), attempt.attempt()))
                .collect::<Vec<_>>(),
            vec![(1, 1), (1, 2), (1, 3)]
        );
        trace.apply(DurableGraphEvent::Terminated {
            node_id: node_id("n10-success"),
            outcome: GraphTermination::Success,
        });
    }

    #[test]
    fn join_distinguishes_all_three_fan_in_results() {
        let cases = [
            (
                success("result-a", &["write-a"]),
                success("result-b", &["write-b"]),
                FanInResult::AllSuccess,
            ),
            (
                success("result-a", &["write-a"]),
                failure("failure-b"),
                FanInResult::PartialSuccess,
            ),
            (
                failure("failure-a"),
                failure("failure-b"),
                FanInResult::Failure,
            ),
        ];
        for (outcome_a, outcome_b, expected) in cases {
            let mut trace = define_and_fork();
            complete_branch(&mut trace, "branch-a", "n10-a", "e10-a-join", outcome_a);
            complete_branch(&mut trace, "branch-b", "n20-b", "e20-b-join", outcome_b);
            finish_join(&mut trace, expected);
            assert_eq!(
                trace.state().join_result(&node_id("n30-join")),
                Some(expected)
            );
        }
    }

    #[test]
    fn successful_sibling_results_survive_failure_retry_and_partial_join() {
        let mut trace = define_and_fork();
        let branch_a = branch_id("branch-a");
        complete_branch(
            &mut trace,
            "branch-a",
            "n10-a",
            "e10-a-join",
            success("result-a", &["write-a-1", "write-a-2"]),
        );
        let preserved = trace
            .state()
            .branch(&branch_a)
            .and_then(BranchRuntimeState::successful_outcome)
            .cloned()
            .expect("successful sibling payload");

        trace.apply(DurableGraphEvent::BranchAttemptStarted {
            branch_id: branch_id("branch-b"),
            visit: 1,
            attempt: 1,
        });
        trace.apply(DurableGraphEvent::BranchAttemptCompleted {
            branch_id: branch_id("branch-b"),
            visit: 1,
            attempt: 1,
            outcome: retryable("transient-b"),
        });
        trace.apply(DurableGraphEvent::BranchRetryScheduled {
            branch_id: branch_id("branch-b"),
            visit: 1,
            next_attempt: 2,
        });
        trace.apply(DurableGraphEvent::BranchAttemptStarted {
            branch_id: branch_id("branch-b"),
            visit: 1,
            attempt: 2,
        });
        trace.apply(DurableGraphEvent::BranchAttemptCompleted {
            branch_id: branch_id("branch-b"),
            visit: 1,
            attempt: 2,
            outcome: failure("terminal-b"),
        });
        trace.apply(DurableGraphEvent::EdgesSelected {
            source_node_id: node_id("n20-b"),
            visit: 1,
            edge_ids: vec![edge_id("e20-b-join")],
        });

        assert_eq!(
            trace
                .state()
                .branch(&branch_a)
                .and_then(BranchRuntimeState::successful_outcome),
            Some(&preserved)
        );
        assert_eq!(preserved.result_ref().as_str(), "result-a");
        assert_eq!(
            preserved
                .write_refs()
                .iter()
                .map(DurableText::as_str)
                .collect::<Vec<_>>(),
            vec!["write-a-1", "write-a-2"]
        );
        finish_join(&mut trace, FanInResult::PartialSuccess);
    }

    #[test]
    fn join_requires_every_branch_bound_arrival() {
        let mut trace = define_and_fork();
        complete_branch(
            &mut trace,
            "branch-a",
            "n10-a",
            "e10-a-join",
            success("result-a", &["write-a"]),
        );
        trace.apply(DurableGraphEvent::BranchAttemptStarted {
            branch_id: branch_id("branch-b"),
            visit: 1,
            attempt: 1,
        });
        trace.apply(DurableGraphEvent::BranchAttemptCompleted {
            branch_id: branch_id("branch-b"),
            visit: 1,
            attempt: 1,
            outcome: failure("failure-b"),
        });
        trace.reject(&DurableGraphEvent::JoinResolved {
            join_node_id: node_id("n30-join"),
            result: FanInResult::PartialSuccess,
        });
        trace.apply(DurableGraphEvent::EdgesSelected {
            source_node_id: node_id("n20-b"),
            visit: 1,
            edge_ids: vec![edge_id("e20-b-join")],
        });
        finish_join(&mut trace, FanInResult::PartialSuccess);
    }

    fn loop_definition() -> DurableGraphDefinition {
        let loop_node = node_id("n00-loop");
        DurableGraphDefinition::new(
            graph_id("graph-loop"),
            loop_node.clone(),
            vec![
                node("n00-loop", DurableGraphNodeKind::Loop { max_iterations: 3 }),
                node(
                    "n10-task",
                    DurableGraphNodeKind::Task {
                        branch_id: branch_id("branch-loop"),
                        max_attempts: 2,
                    },
                ),
                node(
                    "n20-exit",
                    DurableGraphNodeKind::Terminate {
                        outcome: GraphTermination::Success,
                    },
                ),
            ],
            vec![
                edge(
                    "e00-body",
                    "n00-loop",
                    "n10-task",
                    DurableGraphEdgeKind::LoopBody {
                        loop_node_id: loop_node.clone(),
                    },
                    DurableEdgeCondition::LoopDecision {
                        loop_node_id: loop_node.clone(),
                        decision: LoopDecision::Continue,
                    },
                ),
                edge(
                    "e10-back",
                    "n10-task",
                    "n00-loop",
                    DurableGraphEdgeKind::LoopBack {
                        loop_node_id: loop_node.clone(),
                    },
                    DurableEdgeCondition::Always,
                ),
                edge(
                    "e20-exit",
                    "n00-loop",
                    "n20-exit",
                    DurableGraphEdgeKind::Forward,
                    DurableEdgeCondition::LoopDecision {
                        loop_node_id: loop_node,
                        decision: LoopDecision::Exit,
                    },
                ),
            ],
        )
        .expect("valid bounded loop")
    }

    #[test]
    fn bounded_loop_revisits_task_and_rejects_non_termination_at_bound() {
        let mut trace = Trace::default();
        trace.apply(DurableGraphEvent::Defined {
            definition: loop_definition(),
        });
        for iteration in [1_u16, 2] {
            trace.apply(DurableGraphEvent::LoopIterationCompleted {
                loop_node_id: node_id("n00-loop"),
                iteration,
                decision: LoopDecision::Continue,
            });
            trace.apply(DurableGraphEvent::EdgesSelected {
                source_node_id: node_id("n00-loop"),
                visit: iteration,
                edge_ids: vec![edge_id("e00-body")],
            });
            trace.apply(DurableGraphEvent::BranchAttemptStarted {
                branch_id: branch_id("branch-loop"),
                visit: iteration,
                attempt: 1,
            });
            trace.apply(DurableGraphEvent::BranchAttemptCompleted {
                branch_id: branch_id("branch-loop"),
                visit: iteration,
                attempt: 1,
                outcome: success(&format!("loop-result-{iteration}"), &[]),
            });
            trace.apply(DurableGraphEvent::EdgesSelected {
                source_node_id: node_id("n10-task"),
                visit: iteration,
                edge_ids: vec![edge_id("e10-back")],
            });
        }
        trace.reject(&DurableGraphEvent::LoopIterationCompleted {
            loop_node_id: node_id("n00-loop"),
            iteration: 3,
            decision: LoopDecision::Continue,
        });
        trace.apply(DurableGraphEvent::LoopIterationCompleted {
            loop_node_id: node_id("n00-loop"),
            iteration: 3,
            decision: LoopDecision::Exit,
        });
        trace.apply(DurableGraphEvent::EdgesSelected {
            source_node_id: node_id("n00-loop"),
            visit: 3,
            edge_ids: vec![edge_id("e20-exit")],
        });
        trace.apply(DurableGraphEvent::Terminated {
            node_id: node_id("n20-exit"),
            outcome: GraphTermination::Success,
        });
        assert_eq!(trace.state().loop_iterations(&node_id("n00-loop")), Some(3));
        assert_eq!(
            trace
                .state()
                .branch(&branch_id("branch-loop"))
                .expect("loop branch")
                .attempts()
                .iter()
                .map(|attempt| (attempt.visit(), attempt.attempt()))
                .collect::<Vec<_>>(),
            vec![(1, 1), (2, 1)]
        );
    }

    #[test]
    fn explicit_immediate_termination_is_a_valid_graph() {
        let definition = DurableGraphDefinition::new(
            graph_id("graph-immediate"),
            node_id("n00-stop"),
            vec![node(
                "n00-stop",
                DurableGraphNodeKind::Terminate {
                    outcome: GraphTermination::Cancelled,
                },
            )],
            Vec::new(),
        )
        .expect("explicit immediate termination graph");
        let mut trace = Trace::default();
        trace.apply(DurableGraphEvent::Defined { definition });
        trace.apply(DurableGraphEvent::Terminated {
            node_id: node_id("n00-stop"),
            outcome: GraphTermination::Cancelled,
        });
        assert_eq!(
            trace.state().termination(),
            Some(GraphTermination::Cancelled)
        );
        assert!(trace.state().active_nodes.is_empty());
    }

    #[test]
    fn active_fork_sibling_blocks_early_termination() {
        let branch = branch_id("branch-pending");
        let definition = DurableGraphDefinition::new(
            graph_id("graph-frontier"),
            node_id("n00-fork"),
            vec![
                node("n00-fork", DurableGraphNodeKind::Fork),
                node(
                    "n10-pending",
                    DurableGraphNodeKind::Task {
                        branch_id: branch,
                        max_attempts: 1,
                    },
                ),
                node(
                    "n20-stop",
                    DurableGraphNodeKind::Terminate {
                        outcome: GraphTermination::Success,
                    },
                ),
                node(
                    "n30-pending-stop",
                    DurableGraphNodeKind::Terminate {
                        outcome: GraphTermination::Failure,
                    },
                ),
            ],
            vec![
                edge(
                    "e00-pending",
                    "n00-fork",
                    "n10-pending",
                    DurableGraphEdgeKind::Forward,
                    DurableEdgeCondition::Always,
                ),
                edge(
                    "e10-stop",
                    "n00-fork",
                    "n20-stop",
                    DurableGraphEdgeKind::Forward,
                    DurableEdgeCondition::Always,
                ),
                edge(
                    "e20-pending-stop",
                    "n10-pending",
                    "n30-pending-stop",
                    DurableGraphEdgeKind::Forward,
                    DurableEdgeCondition::Always,
                ),
            ],
        )
        .expect("valid fork frontier graph");
        let mut trace = Trace::default();
        trace.apply(DurableGraphEvent::Defined { definition });
        trace.apply(DurableGraphEvent::EdgesSelected {
            source_node_id: node_id("n00-fork"),
            visit: 1,
            edge_ids: vec![edge_id("e00-pending"), edge_id("e10-stop")],
        });
        trace.reject(&DurableGraphEvent::Terminated {
            node_id: node_id("n20-stop"),
            outcome: GraphTermination::Success,
        });
    }

    #[test]
    fn definition_and_runtime_validation_fail_closed() {
        let one_way_fork = DurableGraphDefinition::new(
            graph_id("graph-bad-fork"),
            node_id("n00-fork"),
            vec![
                node("n00-fork", DurableGraphNodeKind::Fork),
                node(
                    "n10-stop",
                    DurableGraphNodeKind::Terminate {
                        outcome: GraphTermination::Success,
                    },
                ),
            ],
            vec![edge(
                "e00-only",
                "n00-fork",
                "n10-stop",
                DurableGraphEdgeKind::Forward,
                DurableEdgeCondition::Always,
            )],
        );
        assert!(one_way_fork.is_err());

        let mut state = apply_graph_event(
            None,
            &DurableGraphEvent::Defined {
                definition: conditional_definition(),
            },
        )
        .expect("initialize runtime");
        state.edge_traversals.insert(edge_id("unknown-edge"), 1);
        assert!(state.validate().is_err());
        state.edge_traversals.clear();
        state
            .branches
            .get_mut(&branch_id("branch-main"))
            .expect("branch runtime")
            .max_attempts = 2;
        assert!(state.validate().is_err());
    }

    #[test]
    fn duplicate_reordered_skipped_and_malformed_events_are_rejected() {
        let definition_event = DurableGraphEvent::Defined {
            definition: conditional_definition(),
        };
        assert!(apply_graph_event(
            None,
            &DurableGraphEvent::BranchAttemptStarted {
                branch_id: branch_id("branch-main"),
                visit: 1,
                attempt: 1,
            },
        )
        .is_err());
        assert!(replay_graph_events(&[
            DurableGraphEvent::BranchAttemptStarted {
                branch_id: branch_id("branch-main"),
                visit: 1,
                attempt: 1,
            },
            definition_event.clone(),
        ])
        .is_err());

        let mut trace = Trace::default();
        trace.apply(definition_event.clone());
        trace.reject(&definition_event);
        let started = DurableGraphEvent::BranchAttemptStarted {
            branch_id: branch_id("branch-main"),
            visit: 1,
            attempt: 1,
        };
        trace.apply(started.clone());
        trace.reject(&started);
        trace.reject(&DurableGraphEvent::BranchAttemptCompleted {
            branch_id: branch_id("branch-main"),
            visit: 1,
            attempt: 2,
            outcome: failure("skipped-attempt"),
        });

        let mut malformed = serde_json::to_value(&definition_event).expect("event JSON");
        malformed
            .as_object_mut()
            .expect("event object")
            .insert("unknown".to_string(), json!(true));
        assert!(serde_json::from_value::<DurableGraphEvent>(malformed).is_err());

        let mut noncanonical =
            serde_json::to_value(conditional_definition()).expect("definition JSON");
        noncanonical["nodes"]
            .as_array_mut()
            .expect("node array")
            .reverse();
        assert!(serde_json::from_value::<DurableGraphDefinition>(noncanonical).is_err());
        assert!(serde_json::from_value::<BranchSuccess>(json!({
            "result_ref": "result",
            "write_refs": ["write-z", "write-a"]
        }))
        .is_err());
    }

    #[test]
    fn event_history_bound_applies_to_replay_and_incremental_reduction() {
        let loop_node = node_id("n00-loop");
        let oversized_definition = DurableGraphDefinition::new(
            graph_id("graph-event-overflow"),
            loop_node.clone(),
            vec![
                node(
                    "n00-loop",
                    DurableGraphNodeKind::Loop { max_iterations: 64 },
                ),
                node(
                    "n10-task-a",
                    DurableGraphNodeKind::Task {
                        branch_id: branch_id("branch-a"),
                        max_attempts: 16,
                    },
                ),
                node(
                    "n20-task-b",
                    DurableGraphNodeKind::Task {
                        branch_id: branch_id("branch-b"),
                        max_attempts: 16,
                    },
                ),
                node(
                    "n30-exit",
                    DurableGraphNodeKind::Terminate {
                        outcome: GraphTermination::Success,
                    },
                ),
            ],
            vec![
                edge(
                    "e00-body",
                    "n00-loop",
                    "n10-task-a",
                    DurableGraphEdgeKind::LoopBody {
                        loop_node_id: loop_node.clone(),
                    },
                    DurableEdgeCondition::LoopDecision {
                        loop_node_id: loop_node.clone(),
                        decision: LoopDecision::Continue,
                    },
                ),
                edge(
                    "e10-next",
                    "n10-task-a",
                    "n20-task-b",
                    DurableGraphEdgeKind::LoopBody {
                        loop_node_id: loop_node.clone(),
                    },
                    DurableEdgeCondition::Always,
                ),
                edge(
                    "e20-back",
                    "n20-task-b",
                    "n00-loop",
                    DurableGraphEdgeKind::LoopBack {
                        loop_node_id: loop_node.clone(),
                    },
                    DurableEdgeCondition::Always,
                ),
                edge(
                    "e30-exit",
                    "n00-loop",
                    "n30-exit",
                    DurableGraphEdgeKind::Forward,
                    DurableEdgeCondition::LoopDecision {
                        loop_node_id: loop_node,
                        decision: LoopDecision::Exit,
                    },
                ),
            ],
        );
        assert!(oversized_definition.is_err());

        let definition_event = DurableGraphEvent::Defined {
            definition: conditional_definition(),
        };
        let oversized = vec![definition_event.clone(); MAX_GRAPH_EVENTS + 1];
        assert!(replay_graph_events(&oversized).is_err());

        let mut state = apply_graph_event(None, &definition_event).expect("initialize graph");
        state.event_count = MAX_GRAPH_EVENTS;
        let before = state.clone();
        assert!(apply_graph_event(
            Some(&state),
            &DurableGraphEvent::BranchAttemptStarted {
                branch_id: branch_id("branch-main"),
                visit: 1,
                attempt: 1,
            },
        )
        .is_err());
        assert_eq!(before.event_count, MAX_GRAPH_EVENTS);
    }
}
