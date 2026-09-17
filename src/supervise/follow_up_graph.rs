//! Lowers a committed licensed follow-up enqueue batch into a durable graph definition
//! and immutable queue-item bindings.
//!
//! ## Graph shape
//!
//! Each authorized queue item becomes exactly one graph task branch with
//! [`LICENSED_FOLLOW_UP_TASK_MAX_ATTEMPTS`] (subordinate plans own internal retries).
//!
//! For a single item, the graph is a conditional task with explicit success and failure
//! termination nodes (a join would require at least two branches per graph validation).
//!
//! For two or more items, a serial task chain with per-branch `JoinArrival` edges cannot
//! pass [`DurableGraphDefinition::validate`]: a task node may expose only one
//! unconditional outgoing edge or an exhaustive success/failure pair, never a mixture
//! with join arrivals. The supported fan-in shape is therefore an entry fork so every
//! branch has a direct task→join arrival path (as in the queue/graph contract tests).
//! Enqueue-order / no-overtaking execution remains the licensed graph consumer's
//! admission policy; the fork only models independent branch lifetimes and join fan-in.

use crate::follow_up_queue::{
    graph::{
        DurableEdgeCondition, DurableGraphDefinition, DurableGraphEdge, DurableGraphEdgeKind,
        DurableGraphEvent, DurableGraphId, DurableGraphNode, DurableGraphNodeKind,
        DurableGraphRuntimeState, FanInResult, GraphBranchId, GraphEdgeId, GraphNodeId,
        GraphTermination,
    },
    DurableGraphQueueItemBinding, GeneratedFollowUpQueue, GeneratedFollowUpQueuePhase,
    GeneratedFollowUpQueueSnapshot,
};
use anyhow::{bail, Context, Result};
use std::collections::BTreeSet;

/// Graph-level attempt bound for each licensed follow-up item (one effect-fenced occurrence).
const LICENSED_FOLLOW_UP_TASK_MAX_ATTEMPTS: u16 = 1;

const GRAPH_ID_PREFIX: &str = "licensed-follow-up-graph-";
const BRANCH_ID_PREFIX: &str = "licensed-follow-up-branch-";
const NODE_ID_PREFIX: &str = "licensed-follow-up-node-";
const EDGE_ID_PREFIX: &str = "licensed-follow-up-edge-";
const GENERATED_FOLLOW_UP_QUEUE_INSTANCE_ID_PREFIX: &str = "follow-up-";

/// Derives the durable graph and canonical bindings for one authenticated enqueue snapshot.
///
/// `ordered_item_ids` must follow the queue snapshot's committed item iteration order
/// (the `BTreeMap` key order of `snapshot.items()`, not caller-supplied submission order).
pub(super) fn derive_licensed_follow_up_graph(
    queue_instance_id: &str,
    ordered_item_ids: &[String],
) -> Result<(DurableGraphDefinition, Vec<DurableGraphQueueItemBinding>)> {
    validate_queue_instance_id(queue_instance_id)?;
    validate_ordered_item_ids(ordered_item_ids)?;

    let graph_id = licensed_graph_id(queue_instance_id)?;
    let (definition, bindings) = if ordered_item_ids.len() == 1 {
        derive_single_item_graph(graph_id, queue_instance_id, &ordered_item_ids[0])?
    } else {
        derive_multi_item_fan_in_graph(graph_id, queue_instance_id, ordered_item_ids)?
    };

    definition.validate()?;
    Ok((definition, bindings))
}

/// Ensures the queue carries the licensed graph for its committed batch, or defines it on a
/// clean legacy-free enqueue snapshot. Returns `false` when legacy resume must proceed without
/// graph migration; returns `true` when the licensed graph is present afterward.
pub(super) fn ensure_licensed_follow_up_graph(queue: &mut GeneratedFollowUpQueue) -> Result<bool> {
    let snapshot = queue.snapshot();
    if snapshot.graph().is_some() {
        verify_licensed_follow_up_graph(snapshot)?;
        return Ok(true);
    }
    if snapshot.items().is_empty() {
        return Ok(false);
    }
    if !snapshot_ready_for_licensed_graph_definition(snapshot) {
        // Legacy batches with dispatch, effect, or acknowledgement evidence keep using the
        // identityless queue path until the cascade finishes or resumes them.
        return Ok(false);
    }
    let ordered_item_ids = committed_item_ids_in_snapshot_order(snapshot);
    let (definition, bindings) =
        derive_licensed_follow_up_graph(snapshot.queue_instance_id(), &ordered_item_ids)?;
    queue.define_graph(definition, bindings)?;
    Ok(true)
}

/// Applies every currently derivable non-worker graph control transition once per call.
pub(super) fn advance_licensed_follow_up_graph(queue: &mut GeneratedFollowUpQueue) -> Result<()> {
    verify_licensed_follow_up_graph(queue.snapshot())?;
    loop {
        let graph = queue
            .snapshot()
            .graph()
            .context("licensed follow-up graph driver requires defined graph state")?;
        if graph.termination().is_some() {
            return Ok(());
        }
        let event_count_before = queue.snapshot().graph_event_count();
        let Some(event) = derive_next_licensed_graph_control_event(graph)? else {
            return Ok(());
        };
        queue.apply_graph_transition(event)?;
        if queue.snapshot().graph_event_count() <= event_count_before {
            bail!("licensed follow-up graph control transition did not append authenticated graph history");
        }
    }
}

fn verify_licensed_follow_up_graph(snapshot: &GeneratedFollowUpQueueSnapshot) -> Result<()> {
    let graph = snapshot
        .graph()
        .context("licensed follow-up graph verification requires defined graph state")?;
    let ordered_item_ids = committed_item_ids_in_snapshot_order(snapshot);
    let (expected_definition, expected_bindings) =
        derive_licensed_follow_up_graph(snapshot.queue_instance_id(), &ordered_item_ids)?;
    if graph.definition() != &expected_definition {
        bail!("licensed follow-up queue graph definition does not match its committed batch");
    }
    let mut actual_bindings = Vec::with_capacity(ordered_item_ids.len());
    for item_id in &ordered_item_ids {
        let branch_id = snapshot.item_branch_id(item_id).with_context(|| {
            format!("licensed follow-up queue item {item_id} is not graph-bound")
        })?;
        actual_bindings.push(DurableGraphQueueItemBinding::new(
            branch_id.clone(),
            item_id,
        )?);
    }
    actual_bindings.sort();
    if actual_bindings != expected_bindings {
        bail!("licensed follow-up queue graph bindings do not match its committed batch");
    }
    Ok(())
}

fn snapshot_ready_for_licensed_graph_definition(snapshot: &GeneratedFollowUpQueueSnapshot) -> bool {
    snapshot.enqueue_committed()
        && snapshot.items().values().all(|item| {
            item.phase() == GeneratedFollowUpQueuePhase::Enqueued
                && item.subordinate_run_id().is_none()
                && item.observation().is_none()
                && item.external_side_effect_state().is_none()
        })
}

fn committed_item_ids_in_snapshot_order(snapshot: &GeneratedFollowUpQueueSnapshot) -> Vec<String> {
    snapshot.items().keys().cloned().collect()
}

fn derive_next_licensed_graph_control_event(
    graph: &DurableGraphRuntimeState,
) -> Result<Option<DurableGraphEvent>> {
    if graph.termination().is_some() {
        return Ok(None);
    }

    let mut active_nodes = graph.active_node_ids().cloned().collect::<Vec<_>>();
    active_nodes.sort();

    if active_nodes.len() == 1 {
        let node_id = active_nodes[0].clone();
        let node = lookup_graph_node(graph, &node_id)?;
        if let DurableGraphNodeKind::Terminate { outcome } = node.kind() {
            return Ok(Some(DurableGraphEvent::Terminated {
                node_id,
                outcome: *outcome,
            }));
        }
    }

    for join_node_id in active_nodes.iter().filter(|node_id| {
        lookup_graph_node(graph, node_id)
            .is_ok_and(|node| matches!(node.kind(), DurableGraphNodeKind::Join { .. }))
    }) {
        if graph.join_result(join_node_id).is_some() {
            continue;
        }
        if graph.join_ready(join_node_id)? {
            let result = graph.expected_join_result(join_node_id)?;
            return Ok(Some(DurableGraphEvent::JoinResolved {
                join_node_id: join_node_id.clone(),
                result,
            }));
        }
    }

    for source_node_id in &active_nodes {
        let node = lookup_graph_node(graph, source_node_id)?;
        match node.kind() {
            DurableGraphNodeKind::Loop { .. } => {
                bail!("licensed follow-up graph driver does not support loop control");
            }
            DurableGraphNodeKind::Terminate { .. } => continue,
            DurableGraphNodeKind::Join { .. } => {
                if graph.join_result(source_node_id).is_none() {
                    continue;
                }
            }
            DurableGraphNodeKind::Task {
                branch_id,
                max_attempts: _,
            } => {
                if !licensed_task_ready_to_route(graph, source_node_id, branch_id)? {
                    continue;
                }
            }
            DurableGraphNodeKind::Fork | DurableGraphNodeKind::Choice => {}
        }
        let visit = graph.node_visit(source_node_id).with_context(|| {
            format!(
                "licensed follow-up graph active node {} lost visit state",
                source_node_id.as_str()
            )
        })?;
        let edge_ids = graph.eligible_edge_ids(source_node_id)?;
        return Ok(Some(DurableGraphEvent::EdgesSelected {
            source_node_id: source_node_id.clone(),
            visit,
            edge_ids,
        }));
    }

    Ok(None)
}

fn lookup_graph_node<'a>(
    graph: &'a DurableGraphRuntimeState,
    node_id: &GraphNodeId,
) -> Result<&'a DurableGraphNode> {
    graph
        .definition()
        .nodes()
        .iter()
        .find(|node| node.id() == node_id)
        .with_context(|| {
            format!(
                "licensed follow-up graph node {} is unknown",
                node_id.as_str()
            )
        })
}

fn licensed_task_ready_to_route(
    graph: &DurableGraphRuntimeState,
    node_id: &GraphNodeId,
    branch_id: &GraphBranchId,
) -> Result<bool> {
    let visit = graph.node_visit(node_id).with_context(|| {
        format!(
            "licensed follow-up graph task node {} lost visit state",
            node_id.as_str()
        )
    })?;
    let branch = graph.branch(branch_id).with_context(|| {
        format!(
            "licensed follow-up graph branch {} lost runtime state",
            branch_id.as_str()
        )
    })?;
    if branch.attempt_in_progress().is_some() || branch.retry_scheduled() {
        return Ok(false);
    }
    Ok(branch
        .attempts()
        .last()
        .is_some_and(|attempt| attempt.visit() == visit))
}

fn validate_queue_instance_id(queue_instance_id: &str) -> Result<()> {
    let digest = queue_instance_id
        .strip_prefix(GENERATED_FOLLOW_UP_QUEUE_INSTANCE_ID_PREFIX)
        .with_context(|| {
            "licensed follow-up queue instance id does not use the follow-up- prefix"
        })?;
    validate_sha256_id(digest, "licensed follow-up queue instance id")
}

fn validate_ordered_item_ids(ordered_item_ids: &[String]) -> Result<()> {
    if ordered_item_ids.is_empty() {
        bail!("licensed follow-up graph requires a nonempty committed item batch");
    }
    let mut seen = BTreeSet::new();
    for item_id in ordered_item_ids {
        validate_sha256_id(item_id, "licensed follow-up queue item id")?;
        if !seen.insert(item_id.as_str()) {
            bail!("licensed follow-up graph rejects duplicate queue item ids");
        }
    }
    Ok(())
}

fn validate_sha256_id(value: &str, label: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("{label} is not canonical lowercase SHA-256 hex");
    }
    Ok(())
}

fn licensed_graph_id(queue_instance_id: &str) -> Result<DurableGraphId> {
    DurableGraphId::new(format!("{GRAPH_ID_PREFIX}{queue_instance_id}"))
}

fn licensed_branch_id(queue_instance_id: &str, index: usize) -> Result<GraphBranchId> {
    GraphBranchId::new(format!("{BRANCH_ID_PREFIX}{queue_instance_id}-{index:04}"))
}

fn licensed_node_id(queue_instance_id: &str, suffix: &str) -> Result<GraphNodeId> {
    GraphNodeId::new(format!("{NODE_ID_PREFIX}{queue_instance_id}-{suffix}"))
}

fn licensed_edge_id(queue_instance_id: &str, suffix: &str) -> Result<GraphEdgeId> {
    GraphEdgeId::new(format!("{EDGE_ID_PREFIX}{queue_instance_id}-{suffix}"))
}

fn sorted_snapshot_item_ids(ordered_item_ids: &[String]) -> Vec<String> {
    let mut sorted = ordered_item_ids.to_vec();
    sorted.sort();
    sorted
}

fn branch_index_for_snapshot_item(item_id: &str, sorted_item_ids: &[String]) -> Result<usize> {
    sorted_item_ids
        .iter()
        .position(|candidate| candidate == item_id)
        .with_context(|| {
            format!("licensed follow-up graph item {item_id} is missing from its batch")
        })
}

fn sort_graph_nodes_and_edges(nodes: &mut [DurableGraphNode], edges: &mut [DurableGraphEdge]) {
    nodes.sort_by(|left, right| left.id().cmp(right.id()));
    edges.sort_by(|left, right| left.id().cmp(right.id()));
}

fn derive_single_item_graph(
    graph_id: DurableGraphId,
    queue_instance_id: &str,
    item_id: &str,
) -> Result<(DurableGraphDefinition, Vec<DurableGraphQueueItemBinding>)> {
    let branch_id = licensed_branch_id(queue_instance_id, 0)?;
    let task_node = licensed_node_id(queue_instance_id, "task-0000")?;
    let success_node = licensed_node_id(queue_instance_id, "term-success")?;
    let failure_node = licensed_node_id(queue_instance_id, "term-failure")?;

    let mut nodes = vec![
        DurableGraphNode::new(
            task_node.clone(),
            DurableGraphNodeKind::Task {
                branch_id: branch_id.clone(),
                max_attempts: LICENSED_FOLLOW_UP_TASK_MAX_ATTEMPTS,
            },
        ),
        DurableGraphNode::new(
            success_node.clone(),
            DurableGraphNodeKind::Terminate {
                outcome: GraphTermination::Success,
            },
        ),
        DurableGraphNode::new(
            failure_node.clone(),
            DurableGraphNodeKind::Terminate {
                outcome: GraphTermination::Failure,
            },
        ),
    ];

    let mut edges = vec![
        DurableGraphEdge::new(
            licensed_edge_id(queue_instance_id, "task-success")?,
            task_node.clone(),
            success_node,
            DurableGraphEdgeKind::Forward,
            DurableEdgeCondition::BranchLatestOutcome {
                branch_id: branch_id.clone(),
                outcome: crate::follow_up_queue::graph::BranchOutcomeClass::Success,
            },
        ),
        DurableGraphEdge::new(
            licensed_edge_id(queue_instance_id, "task-failure")?,
            task_node,
            failure_node,
            DurableGraphEdgeKind::Forward,
            DurableEdgeCondition::BranchLatestOutcome {
                branch_id: branch_id.clone(),
                outcome: crate::follow_up_queue::graph::BranchOutcomeClass::Failure,
            },
        ),
    ];
    sort_graph_nodes_and_edges(&mut nodes, &mut edges);

    let definition = DurableGraphDefinition::new(
        graph_id,
        licensed_node_id(queue_instance_id, "task-0000")?,
        nodes,
        edges,
    )?;
    let binding = DurableGraphQueueItemBinding::new(branch_id, item_id)?;
    Ok((definition, vec![binding]))
}

fn derive_multi_item_fan_in_graph(
    graph_id: DurableGraphId,
    queue_instance_id: &str,
    ordered_item_ids: &[String],
) -> Result<(DurableGraphDefinition, Vec<DurableGraphQueueItemBinding>)> {
    let fork_node = licensed_node_id(queue_instance_id, "fork")?;
    let join_node = licensed_node_id(queue_instance_id, "join")?;
    let term_success = licensed_node_id(queue_instance_id, "term-success")?;
    let term_partial = licensed_node_id(queue_instance_id, "term-partial")?;
    let term_failure = licensed_node_id(queue_instance_id, "term-failure")?;

    let sorted_item_ids = sorted_snapshot_item_ids(ordered_item_ids);
    let join_branch_ids = (0..ordered_item_ids.len())
        .map(|index| licensed_branch_id(queue_instance_id, index))
        .collect::<Result<Vec<_>>>()?;

    let mut bindings = Vec::with_capacity(ordered_item_ids.len());
    for item_id in ordered_item_ids {
        let branch_index = branch_index_for_snapshot_item(item_id, &sorted_item_ids)?;
        let branch_id = licensed_branch_id(queue_instance_id, branch_index)?;
        bindings.push(DurableGraphQueueItemBinding::new(branch_id, item_id)?);
    }
    bindings.sort();

    let mut nodes = vec![
        DurableGraphNode::new(fork_node.clone(), DurableGraphNodeKind::Fork),
        DurableGraphNode::new(
            join_node.clone(),
            DurableGraphNodeKind::Join {
                branches: join_branch_ids.clone(),
            },
        ),
        DurableGraphNode::new(
            term_success.clone(),
            DurableGraphNodeKind::Terminate {
                outcome: GraphTermination::Success,
            },
        ),
        DurableGraphNode::new(
            term_partial.clone(),
            DurableGraphNodeKind::Terminate {
                outcome: GraphTermination::Failure,
            },
        ),
        DurableGraphNode::new(
            term_failure.clone(),
            DurableGraphNodeKind::Terminate {
                outcome: GraphTermination::Failure,
            },
        ),
    ];

    for (task_index, item_id) in ordered_item_ids.iter().enumerate() {
        let branch_index = branch_index_for_snapshot_item(item_id, &sorted_item_ids)?;
        let branch_id = licensed_branch_id(queue_instance_id, branch_index)?;
        nodes.push(DurableGraphNode::new(
            licensed_node_id(queue_instance_id, &format!("task-{task_index:04}"))?,
            DurableGraphNodeKind::Task {
                branch_id,
                max_attempts: LICENSED_FOLLOW_UP_TASK_MAX_ATTEMPTS,
            },
        ));
    }
    nodes.sort_by(|left, right| left.id().cmp(right.id()));

    let mut edges = Vec::new();
    for (task_index, item_id) in ordered_item_ids.iter().enumerate() {
        let branch_index = branch_index_for_snapshot_item(item_id, &sorted_item_ids)?;
        let branch_id = licensed_branch_id(queue_instance_id, branch_index)?;
        let task_node = licensed_node_id(queue_instance_id, &format!("task-{task_index:04}"))?;
        edges.push(DurableGraphEdge::new(
            licensed_edge_id(queue_instance_id, &format!("fork-task-{task_index:04}"))?,
            fork_node.clone(),
            task_node.clone(),
            DurableGraphEdgeKind::Forward,
            DurableEdgeCondition::Always,
        ));
        edges.push(DurableGraphEdge::new(
            licensed_edge_id(queue_instance_id, &format!("task-join-{task_index:04}"))?,
            task_node,
            join_node.clone(),
            DurableGraphEdgeKind::JoinArrival { branch_id },
            DurableEdgeCondition::Always,
        ));
    }
    edges.push(DurableGraphEdge::new(
        licensed_edge_id(queue_instance_id, "join-all-success")?,
        join_node.clone(),
        term_success,
        DurableGraphEdgeKind::Forward,
        DurableEdgeCondition::JoinResult {
            join_node_id: join_node.clone(),
            result: FanInResult::AllSuccess,
        },
    ));
    edges.push(DurableGraphEdge::new(
        licensed_edge_id(queue_instance_id, "join-partial-success")?,
        join_node.clone(),
        term_partial,
        DurableGraphEdgeKind::Forward,
        DurableEdgeCondition::JoinResult {
            join_node_id: join_node.clone(),
            result: FanInResult::PartialSuccess,
        },
    ));
    edges.push(DurableGraphEdge::new(
        licensed_edge_id(queue_instance_id, "join-failure")?,
        join_node.clone(),
        term_failure,
        DurableGraphEdgeKind::Forward,
        DurableEdgeCondition::JoinResult {
            join_node_id: join_node.clone(),
            result: FanInResult::Failure,
        },
    ));
    edges.sort_by(|left, right| left.id().cmp(right.id()));

    let definition = DurableGraphDefinition::new(graph_id, fork_node, nodes, edges)?;
    Ok((definition, bindings))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::follow_up_queue::graph::{
        replay_graph_events, BranchOutcome, BranchSuccess, DurableText,
    };

    fn sample_queue_instance_id() -> String {
        format!(
            "{}{}",
            GENERATED_FOLLOW_UP_QUEUE_INSTANCE_ID_PREFIX,
            "b".repeat(64)
        )
    }

    fn sample_item_id(digit: char) -> String {
        format!("{}{}", digit, "a".repeat(63))
    }

    fn durable_text(value: &str) -> DurableText {
        DurableText::new(value).expect("durable text")
    }

    fn graph_success(result_ref: &str, write_refs: &[&str]) -> BranchOutcome {
        BranchOutcome::Success {
            success: BranchSuccess::new(
                durable_text(result_ref),
                write_refs.iter().map(|value| durable_text(value)).collect(),
            )
            .expect("branch success"),
        }
    }

    fn graph_failure(error: &str) -> BranchOutcome {
        BranchOutcome::Failure {
            error: durable_text(error),
        }
    }

    struct ReplayTrace {
        events: Vec<DurableGraphEvent>,
        state: Option<DurableGraphRuntimeState>,
    }

    impl ReplayTrace {
        fn apply(&mut self, event: DurableGraphEvent) {
            self.events.push(event);
            self.state = Some(replay_graph_events(&self.events).expect("replay graph events"));
        }

        fn state(&self) -> &DurableGraphRuntimeState {
            self.state.as_ref().expect("trace state")
        }

        fn event_count(&self) -> usize {
            self.events.len()
        }
    }

    fn task_node_id(queue_instance_id: &str, index: usize) -> GraphNodeId {
        licensed_node_id(queue_instance_id, &format!("task-{index:04}")).expect("task node id")
    }

    fn join_edge_id(queue_instance_id: &str, index: usize) -> GraphEdgeId {
        licensed_edge_id(queue_instance_id, &format!("task-join-{index:04}")).expect("join edge")
    }

    fn apply_next_control_event(trace: &mut ReplayTrace) -> Result<bool> {
        let Some(event) = derive_next_licensed_graph_control_event(trace.state())? else {
            return Ok(false);
        };
        trace.apply(event);
        Ok(true)
    }

    fn complete_task_branch(
        trace: &mut ReplayTrace,
        branch_id: GraphBranchId,
        task_node: GraphNodeId,
        join_arrival_edge: GraphEdgeId,
        outcome: BranchOutcome,
    ) {
        trace.apply(DurableGraphEvent::BranchAttemptStarted {
            branch_id: branch_id.clone(),
            visit: 1,
            attempt: 1,
        });
        trace.apply(DurableGraphEvent::BranchAttemptCompleted {
            branch_id,
            visit: 1,
            attempt: 1,
            outcome,
        });
        trace.apply(DurableGraphEvent::EdgesSelected {
            source_node_id: task_node,
            visit: 1,
            edge_ids: vec![join_arrival_edge],
        });
    }

    fn finish_join_with_control_driver(
        trace: &mut ReplayTrace,
        queue_instance_id: &str,
        result: FanInResult,
        termination: GraphTermination,
    ) {
        assert!(apply_next_control_event(trace).expect("resolve join"));
        assert!(apply_next_control_event(trace).expect("route join"));
        assert!(apply_next_control_event(trace).expect("terminate graph"));
        assert_eq!(trace.state().termination(), Some(termination));
        assert_eq!(
            trace
                .state()
                .join_result(&licensed_node_id(queue_instance_id, "join").expect("join")),
            Some(result)
        );
    }

    #[test]
    fn derived_bindings_are_stable_and_canonical() {
        let queue = sample_queue_instance_id();
        let items = vec![sample_item_id('1'), sample_item_id('2')];
        let first = derive_licensed_follow_up_graph(&queue, &items).expect("first derive");
        let second = derive_licensed_follow_up_graph(&queue, &items).expect("second derive");
        assert_eq!(first, second);
        assert!(first.1.windows(2).all(|pair| pair[0] < pair[1]));
        assert_eq!(first.1.len(), items.len());
    }

    #[test]
    fn rejects_invalid_and_duplicate_item_ids() {
        let queue = sample_queue_instance_id();
        assert!(derive_licensed_follow_up_graph(&queue, &[]).is_err());
        assert!(derive_licensed_follow_up_graph("not-canonical", &[sample_item_id('1')]).is_err());
        assert!(derive_licensed_follow_up_graph(&"b".repeat(64), &[sample_item_id('1')]).is_err());
        assert!(derive_licensed_follow_up_graph(
            &format!(
                "{}{}",
                GENERATED_FOLLOW_UP_QUEUE_INSTANCE_ID_PREFIX,
                "b".repeat(63)
            ),
            &[sample_item_id('1')],
        )
        .is_err());
        assert!(derive_licensed_follow_up_graph(
            &format!(
                "{}{}",
                GENERATED_FOLLOW_UP_QUEUE_INSTANCE_ID_PREFIX,
                "B".repeat(64)
            ),
            &[sample_item_id('1')],
        )
        .is_err());
        let duplicate = vec![sample_item_id('1'), sample_item_id('1')];
        assert!(derive_licensed_follow_up_graph(&queue, &duplicate).is_err());
    }

    #[test]
    fn control_driver_advances_fork_without_worker_events() {
        let queue = sample_queue_instance_id();
        let items = vec![sample_item_id('1'), sample_item_id('2')];
        let (definition, _) = derive_licensed_follow_up_graph(&queue, &items).expect("derive");

        let mut trace = ReplayTrace {
            events: Vec::new(),
            state: None,
        };
        trace.apply(DurableGraphEvent::Defined { definition });
        assert!(apply_next_control_event(&mut trace).expect("advance fork"));
        assert!(!apply_next_control_event(&mut trace).expect("blocked without worker completion"));
    }

    #[test]
    fn join_ready_is_false_until_every_branch_arrives() {
        let queue = sample_queue_instance_id();
        let items = vec![sample_item_id('1'), sample_item_id('2')];
        let (definition, _) = derive_licensed_follow_up_graph(&queue, &items).expect("derive");
        let mut trace = ReplayTrace {
            events: Vec::new(),
            state: None,
        };
        trace.apply(DurableGraphEvent::Defined { definition });
        apply_next_control_event(&mut trace).expect("fork");
        complete_task_branch(
            &mut trace,
            licensed_branch_id(&queue, 0).expect("branch 0"),
            task_node_id(&queue, 0),
            join_edge_id(&queue, 0),
            graph_success("result-0", &["write-0"]),
        );
        let join = licensed_node_id(&queue, "join").expect("join");
        assert!(!trace.state().join_ready(&join).expect("join readiness"));
        assert!(trace.state().expected_join_result(&join).is_err());
    }

    #[test]
    fn blocked_task_does_not_forge_worker_completion() {
        let queue = sample_queue_instance_id();
        let items = vec![sample_item_id('1'), sample_item_id('2')];
        let (definition, _) = derive_licensed_follow_up_graph(&queue, &items).expect("derive");
        let mut trace = ReplayTrace {
            events: Vec::new(),
            state: None,
        };
        trace.apply(DurableGraphEvent::Defined { definition });
        apply_next_control_event(&mut trace).expect("fork");
        let before = trace.event_count();
        assert!(!apply_next_control_event(&mut trace).expect("still blocked"));
        assert_eq!(trace.event_count(), before);
    }

    #[test]
    fn two_item_all_success_control_driver_terminates_success() {
        let queue = sample_queue_instance_id();
        let items = vec![sample_item_id('1'), sample_item_id('2')];
        let (definition, _) = derive_licensed_follow_up_graph(&queue, &items).expect("derive");

        let mut trace = ReplayTrace {
            events: Vec::new(),
            state: None,
        };
        trace.apply(DurableGraphEvent::Defined { definition });
        apply_next_control_event(&mut trace).expect("fork");

        complete_task_branch(
            &mut trace,
            licensed_branch_id(&queue, 0).expect("branch 0"),
            task_node_id(&queue, 0),
            join_edge_id(&queue, 0),
            graph_success("result-0", &["write-0"]),
        );
        complete_task_branch(
            &mut trace,
            licensed_branch_id(&queue, 1).expect("branch 1"),
            task_node_id(&queue, 1),
            join_edge_id(&queue, 1),
            graph_success("result-1", &["write-1"]),
        );
        finish_join_with_control_driver(
            &mut trace,
            &queue,
            FanInResult::AllSuccess,
            GraphTermination::Success,
        );
    }

    #[test]
    fn partial_fan_in_preserves_success_reference_and_terminates_failure() {
        let queue = sample_queue_instance_id();
        let items = vec![sample_item_id('1'), sample_item_id('2')];
        let (definition, _) = derive_licensed_follow_up_graph(&queue, &items).expect("derive");

        let mut trace = ReplayTrace {
            events: Vec::new(),
            state: None,
        };
        trace.apply(DurableGraphEvent::Defined { definition });
        apply_next_control_event(&mut trace).expect("fork");

        let branch_a = licensed_branch_id(&queue, 0).expect("branch 0");
        complete_task_branch(
            &mut trace,
            branch_a.clone(),
            task_node_id(&queue, 0),
            join_edge_id(&queue, 0),
            graph_success("result-ok", &["write-ok"]),
        );
        let preserved = trace
            .state()
            .branch(&branch_a)
            .and_then(|branch| branch.successful_outcome())
            .cloned()
            .expect("successful sibling payload");

        complete_task_branch(
            &mut trace,
            licensed_branch_id(&queue, 1).expect("branch 1"),
            task_node_id(&queue, 1),
            join_edge_id(&queue, 1),
            graph_failure("terminal-failure"),
        );

        assert_eq!(
            trace
                .state()
                .branch(&branch_a)
                .and_then(|branch| branch.successful_outcome()),
            Some(&preserved)
        );

        finish_join_with_control_driver(
            &mut trace,
            &queue,
            FanInResult::PartialSuccess,
            GraphTermination::Failure,
        );
        let partial_term = licensed_node_id(&queue, "term-partial").expect("partial term");
        assert!(trace.state().reached(&partial_term));
    }

    #[test]
    fn repeated_control_advance_after_termination_is_idempotent() {
        let queue = sample_queue_instance_id();
        let items = vec![sample_item_id('1'), sample_item_id('2')];
        let (definition, _) = derive_licensed_follow_up_graph(&queue, &items).expect("derive");
        let mut trace = ReplayTrace {
            events: Vec::new(),
            state: None,
        };
        trace.apply(DurableGraphEvent::Defined { definition });
        apply_next_control_event(&mut trace).expect("fork");
        complete_task_branch(
            &mut trace,
            licensed_branch_id(&queue, 0).expect("branch 0"),
            task_node_id(&queue, 0),
            join_edge_id(&queue, 0),
            graph_success("result-0", &[]),
        );
        complete_task_branch(
            &mut trace,
            licensed_branch_id(&queue, 1).expect("branch 1"),
            task_node_id(&queue, 1),
            join_edge_id(&queue, 1),
            graph_success("result-1", &[]),
        );
        finish_join_with_control_driver(
            &mut trace,
            &queue,
            FanInResult::AllSuccess,
            GraphTermination::Success,
        );
        let count = trace.event_count();
        assert!(!apply_next_control_event(&mut trace).expect("terminated"));
        assert!(!apply_next_control_event(&mut trace).expect("still terminated"));
        assert_eq!(trace.event_count(), count);
    }

    #[test]
    fn branch_indices_follow_snapshot_key_order_not_submission_order() {
        let queue = sample_queue_instance_id();
        let submitted_order = vec![sample_item_id('2'), sample_item_id('1')];
        let snapshot_order = vec![sample_item_id('1'), sample_item_id('2')];
        let submitted =
            derive_licensed_follow_up_graph(&queue, &submitted_order).expect("submitted order");
        let snapshot =
            derive_licensed_follow_up_graph(&queue, &snapshot_order).expect("snapshot order");
        assert_ne!(submitted.0, snapshot.0);
    }

    #[test]
    fn single_item_graph_is_conditional_without_join() {
        let queue = sample_queue_instance_id();
        let items = vec![sample_item_id('1')];
        let (definition, bindings) =
            derive_licensed_follow_up_graph(&queue, &items).expect("derive");
        assert_eq!(bindings.len(), 1);
        assert!(!definition
            .nodes()
            .iter()
            .any(|node| matches!(node.kind(), DurableGraphNodeKind::Join { .. })));
    }
}
