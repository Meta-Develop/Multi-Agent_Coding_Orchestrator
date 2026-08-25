use crate::{
    llm::{LlmProvider, LlmRequest, LlmResponse, PromptContext, Redactor, RequestBudget, Usage},
    repo_semantic,
    safe_state::{
        BoundedTreeEntry, BoundedTreeEntryKind, BoundedTreeWalkAction, BoundedTreeWalkLimits,
        BoundedTreeWalker, DirectoryBindingGuard,
    },
    sync::normalize_repo_relative_path,
};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    fmt, fs,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

const REPOSITORY_INVENTORY_MAX_DEPTH: usize = 128;
const REPOSITORY_INVENTORY_MAX_ENTRIES: usize = 100_000;
const REPOSITORY_INVENTORY_MAX_PATH_BYTES: usize = 4096;
const REPOSITORY_INVENTORY_MAX_TOTAL_PATH_BYTES: usize = 64 * 1024 * 1024;
const TASK_SPEC_MAX_FRAGMENTS: usize = 128;
const TASK_SPEC_MAX_FRAGMENT_BYTES: usize = 16 * 1024;
const TASK_SPEC_MAX_TOTAL_BYTES: usize = 256 * 1024;
const TASK_PROPOSAL_MAX_ASSIGNMENTS: usize = 128;
const TASK_PROPOSAL_MAX_SCOPE_ITEMS_PER_ASSIGNMENT: usize = 4096;
const TASK_PROPOSAL_MAX_TOTAL_SCOPE_ITEMS: usize = 16_384;
const TASK_PROPOSAL_MAX_REPORTED_CONFLICTS: usize = 4096;
const MAX_NAMED_PATH_EXPANSION: usize = 128;
const PROVIDER_PLANNING_MAX_FEEDBACK_ITEMS: usize = 128;
const PROVIDER_PLANNING_MAX_FEEDBACK_ITEM_BYTES: usize = 16 * 1024;
const PROVIDER_PLANNING_MAX_TOTAL_FEEDBACK_BYTES: usize = 256 * 1024;
const DEFAULT_PROVIDER_MAX_CHILD_ASSIGNMENTS: usize = 8;
const DEFAULT_PROVIDER_MAX_DEPTH: usize = 4;
pub const MAX_PROVIDER_REPLANS: usize = 2;
#[cfg(not(test))]
const REPOSITORY_INVENTORY_MAX_DURATION: Duration = Duration::from_secs(30);
#[cfg(test)]
const REPOSITORY_INVENTORY_MAX_DURATION: Duration = Duration::from_secs(120);

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct TaskPathProposalDiagnostics {
    #[serde(default)]
    pub degraded: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
}

impl TaskPathProposalDiagnostics {
    pub fn is_empty(&self) -> bool {
        !self.degraded && self.notes.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct TaskPathProposal {
    pub paths: Vec<PathBuf>,
    pub diagnostics: TaskPathProposalDiagnostics,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct TaskSpecFragment {
    pub id: String,
    pub text: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskCoverageGapKind {
    UnmatchedScope,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct TaskCoverageGap {
    pub fragment_id: String,
    pub kind: TaskCoverageGapKind,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct TaskAssignmentProposal {
    pub id: String,
    pub task: String,
    pub fragment_ids: Vec<String>,
    pub assigned_paths: Vec<PathBuf>,
    pub semantic_symbols: Vec<String>,
    pub semantic_modules: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskScopeConflictKind {
    PathOverlap,
    SymbolOverlap,
    ModuleOverlap,
    ModuleHierarchyOverlap,
    ModuleSymbolOverlap,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
pub struct TaskScopeConflict {
    pub kind: TaskScopeConflictKind,
    pub left_assignment_id: String,
    pub right_assignment_id: String,
    pub left_value: String,
    pub right_value: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct TaskDisjointnessReport {
    pub disjoint: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conflicts: Vec<TaskScopeConflict>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub conflicts_truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct TaskDecompositionProposal {
    pub fragments: Vec<TaskSpecFragment>,
    pub assignments: Vec<TaskAssignmentProposal>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub coverage_gaps: Vec<TaskCoverageGap>,
    pub diagnostics: TaskPathProposalDiagnostics,
    pub disjointness: TaskDisjointnessReport,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderTaskPlan {
    pub assignments: Vec<TaskAssignmentProposal>,
}

/// One provider-proposed assignment in a recursive planning tree.
///
/// Root assignments have depth 1, their direct children have depth 2, and so
/// on. A node with no `child_assignments` is an executable leaf. Internal-node
/// fragment ids are an aggregate declaration and must exactly match the union
/// of their executable descendant leaves.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderTaskAssignmentTree {
    pub id: String,
    pub task: String,
    pub fragment_ids: Vec<String>,
    pub assigned_paths: Vec<PathBuf>,
    pub semantic_symbols: Vec<String>,
    pub semantic_modules: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub child_assignments: Vec<ProviderTaskAssignmentTree>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderRecursiveTaskPlan {
    pub assignments: Vec<ProviderTaskAssignmentTree>,
}

impl From<TaskAssignmentProposal> for ProviderTaskAssignmentTree {
    fn from(assignment: TaskAssignmentProposal) -> Self {
        Self {
            id: assignment.id,
            task: assignment.task,
            fragment_ids: assignment.fragment_ids,
            assigned_paths: assignment.assigned_paths,
            semantic_symbols: assignment.semantic_symbols,
            semantic_modules: assignment.semantic_modules,
            child_assignments: Vec::new(),
        }
    }
}

impl From<ProviderTaskPlan> for ProviderRecursiveTaskPlan {
    fn from(plan: ProviderTaskPlan) -> Self {
        Self {
            assignments: plan
                .assignments
                .into_iter()
                .map(ProviderTaskAssignmentTree::from)
                .collect(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct ProviderPlanningConfig {
    pub request_id_prefix: String,
    pub model: String,
    #[serde(default = "default_provider_max_child_assignments")]
    pub max_child_assignments: usize,
    #[serde(default = "default_provider_max_depth")]
    pub max_depth: usize,
}

impl ProviderPlanningConfig {
    pub fn new(request_id_prefix: impl Into<String>, model: impl Into<String>) -> Self {
        Self {
            request_id_prefix: request_id_prefix.into(),
            model: model.into(),
            max_child_assignments: DEFAULT_PROVIDER_MAX_CHILD_ASSIGNMENTS,
            max_depth: DEFAULT_PROVIDER_MAX_DEPTH,
        }
    }

    pub fn with_max_child_assignments(mut self, max_child_assignments: usize) -> Self {
        self.max_child_assignments = max_child_assignments;
        self
    }

    pub fn with_max_depth(mut self, max_depth: usize) -> Self {
        self.max_depth = max_depth;
        self
    }
}

const fn default_provider_max_child_assignments() -> usize {
    DEFAULT_PROVIDER_MAX_CHILD_ASSIGNMENTS
}

const fn default_provider_max_depth() -> usize {
    DEFAULT_PROVIDER_MAX_DEPTH
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct TaskExecutionFeedback {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub completed_assignment_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub failed_assignment_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub coverage_gap_fragment_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskPlanningSource {
    Heuristic,
    Provider,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskPlanningSession {
    proposal: TaskDecompositionProposal,
    source: TaskPlanningSource,
    provider_id: Option<String>,
    model: Option<String>,
    provider_usage: Usage,
    replans_used: usize,
    completed_fragment_ids: BTreeSet<String>,
    completed_assignments: Vec<TaskAssignmentProposal>,
    provider_assignment_tree: Vec<ProviderTaskAssignmentTree>,
}

impl TaskPlanningSession {
    pub fn proposal(&self) -> &TaskDecompositionProposal {
        &self.proposal
    }

    pub fn into_proposal(self) -> TaskDecompositionProposal {
        self.proposal
    }

    pub fn source(&self) -> TaskPlanningSource {
        self.source
    }

    pub fn provider_id(&self) -> Option<&str> {
        self.provider_id.as_deref()
    }

    pub fn model(&self) -> Option<&str> {
        self.model.as_deref()
    }

    pub fn provider_usage(&self) -> Usage {
        self.provider_usage
    }

    pub fn replans_used(&self) -> usize {
        self.replans_used
    }

    /// Returns the last provider assignment forest that passed deterministic
    /// validation. Heuristic-only sessions return an empty slice.
    pub fn provider_assignment_tree(&self) -> &[ProviderTaskAssignmentTree] {
        &self.provider_assignment_tree
    }

    pub fn completed_fragment_ids(&self) -> &BTreeSet<String> {
        &self.completed_fragment_ids
    }

    pub fn completed_assignments(&self) -> &[TaskAssignmentProposal] {
        &self.completed_assignments
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct FanOutWidthWarning {
    pub code: String,
    pub configured_max_child_assignments: usize,
    pub independent_scope_count: usize,
    pub message: String,
}

impl fmt::Display for FanOutWidthWarning {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

pub fn fan_out_width_warning(
    max_child_assignments: usize,
    independent_scope_count: usize,
) -> Option<FanOutWidthWarning> {
    (max_child_assignments == 1 && independent_scope_count > 1).then(|| {
        FanOutWidthWarning {
            code: "planning_width_pinned_to_one".to_string(),
            configured_max_child_assignments: max_child_assignments,
            independent_scope_count,
            message: format!(
                "max_child_assignments is pinned to 1 despite {independent_scope_count} independent scopes; this plan serializes work that can fan out"
            ),
        }
    })
}

struct NormalizedTaskScope {
    id: String,
    paths: Vec<PathBuf>,
    symbols: Vec<String>,
    modules: Vec<String>,
}

pub fn task_assignment_disjointness(
    assignments: &[TaskAssignmentProposal],
) -> Result<TaskDisjointnessReport> {
    if assignments.len() > TASK_PROPOSAL_MAX_ASSIGNMENTS {
        anyhow::bail!(
            "task proposal contains {} assignments but at most {} are allowed",
            assignments.len(),
            TASK_PROPOSAL_MAX_ASSIGNMENTS
        );
    }
    let mut ids = BTreeSet::new();
    let mut normalized = Vec::with_capacity(assignments.len());
    let mut total_scope_items = 0usize;
    for assignment in assignments {
        let id = assignment.id.trim();
        if id.is_empty() {
            anyhow::bail!("task assignment proposal id cannot be empty");
        }
        if !ids.insert(id.to_string()) {
            anyhow::bail!("duplicate task assignment proposal id '{id}'");
        }
        let scope_items = assignment
            .assigned_paths
            .len()
            .checked_add(assignment.semantic_symbols.len())
            .and_then(|count| count.checked_add(assignment.semantic_modules.len()))
            .context("task assignment proposal scope item count overflowed")?;
        if scope_items > TASK_PROPOSAL_MAX_SCOPE_ITEMS_PER_ASSIGNMENT {
            anyhow::bail!(
                "task assignment proposal '{id}' contains {scope_items} scope items but at most {} are allowed",
                TASK_PROPOSAL_MAX_SCOPE_ITEMS_PER_ASSIGNMENT
            );
        }
        total_scope_items = total_scope_items
            .checked_add(scope_items)
            .context("task proposal total scope item count overflowed")?;
        if total_scope_items > TASK_PROPOSAL_MAX_TOTAL_SCOPE_ITEMS {
            anyhow::bail!(
                "task proposal contains {total_scope_items} scope items but at most {} are allowed",
                TASK_PROPOSAL_MAX_TOTAL_SCOPE_ITEMS
            );
        }
        normalized.push(normalize_task_scope(assignment)?);
    }

    let mut conflicts = Vec::new();
    let mut conflicts_truncated = false;
    'assignments: for left_index in 0..normalized.len() {
        for right in &normalized[left_index + 1..] {
            if collect_task_scope_conflicts(&normalized[left_index], right, &mut conflicts) {
                conflicts_truncated = true;
                break 'assignments;
            }
        }
    }
    conflicts.sort();
    conflicts.dedup();
    Ok(TaskDisjointnessReport {
        disjoint: conflicts.is_empty(),
        conflicts,
        conflicts_truncated,
    })
}

pub fn validate_task_assignment_disjointness(assignments: &[TaskAssignmentProposal]) -> Result<()> {
    let report = task_assignment_disjointness(assignments)?;
    if let Some(conflict) = report.conflicts.first() {
        anyhow::bail!(
            "task assignments '{}' and '{}' are not disjoint: {:?} between '{}' and '{}'",
            conflict.left_assignment_id,
            conflict.right_assignment_id,
            conflict.kind,
            conflict.left_value,
            conflict.right_value
        );
    }
    Ok(())
}

fn normalize_task_scope(assignment: &TaskAssignmentProposal) -> Result<NormalizedTaskScope> {
    let paths = assignment
        .assigned_paths
        .iter()
        .map(normalize_repo_relative_path)
        .collect::<std::result::Result<BTreeSet<_>, _>>()
        .with_context(|| {
            format!(
                "task assignment proposal '{}' has an invalid path",
                assignment.id
            )
        })?
        .into_iter()
        .collect();
    let symbols = normalize_semantic_values(&assignment.semantic_symbols)?;
    let modules = normalize_semantic_values(&assignment.semantic_modules)?;
    Ok(NormalizedTaskScope {
        id: assignment.id.trim().to_string(),
        paths,
        symbols,
        modules,
    })
}

fn normalize_semantic_values(values: &[String]) -> Result<Vec<String>> {
    values
        .iter()
        .map(|value| normalize_semantic_value(value))
        .collect::<Result<BTreeSet<_>>>()
        .map(BTreeSet::into_iter)
        .map(Iterator::collect)
}

fn normalize_semantic_value(value: &str) -> Result<String> {
    let mut parts = value
        .trim()
        .split("::")
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .map(str::to_string)
        .collect::<Vec<_>>();
    if parts.is_empty() {
        anyhow::bail!("semantic intent cannot be empty");
    }
    if parts.first().is_some_and(|part| part != "crate") {
        parts.insert(0, "crate".to_string());
    }
    Ok(parts.join("::"))
}

fn collect_task_scope_conflicts(
    left: &NormalizedTaskScope,
    right: &NormalizedTaskScope,
    conflicts: &mut Vec<TaskScopeConflict>,
) -> bool {
    for left_path in &left.paths {
        for right_path in &right.paths {
            if paths_overlap(left_path, right_path) {
                conflicts.push(scope_conflict(
                    TaskScopeConflictKind::PathOverlap,
                    left,
                    right,
                    left_path.display().to_string(),
                    right_path.display().to_string(),
                ));
                if conflicts.len() >= TASK_PROPOSAL_MAX_REPORTED_CONFLICTS {
                    return true;
                }
            }
        }
    }
    for left_symbol in &left.symbols {
        for right_symbol in &right.symbols {
            if left_symbol == right_symbol {
                conflicts.push(scope_conflict(
                    TaskScopeConflictKind::SymbolOverlap,
                    left,
                    right,
                    left_symbol.clone(),
                    right_symbol.clone(),
                ));
                if conflicts.len() >= TASK_PROPOSAL_MAX_REPORTED_CONFLICTS {
                    return true;
                }
            }
        }
    }
    for left_module in &left.modules {
        for right_module in &right.modules {
            if left_module == right_module {
                conflicts.push(scope_conflict(
                    TaskScopeConflictKind::ModuleOverlap,
                    left,
                    right,
                    left_module.clone(),
                    right_module.clone(),
                ));
                if conflicts.len() >= TASK_PROPOSAL_MAX_REPORTED_CONFLICTS {
                    return true;
                }
            } else if semantic_path_overlaps(left_module, right_module) {
                conflicts.push(scope_conflict(
                    TaskScopeConflictKind::ModuleHierarchyOverlap,
                    left,
                    right,
                    left_module.clone(),
                    right_module.clone(),
                ));
                if conflicts.len() >= TASK_PROPOSAL_MAX_REPORTED_CONFLICTS {
                    return true;
                }
            }
        }
        for right_symbol in &right.symbols {
            if semantic_module_contains(left_module, right_symbol) {
                conflicts.push(scope_conflict(
                    TaskScopeConflictKind::ModuleSymbolOverlap,
                    left,
                    right,
                    left_module.clone(),
                    right_symbol.clone(),
                ));
                if conflicts.len() >= TASK_PROPOSAL_MAX_REPORTED_CONFLICTS {
                    return true;
                }
            }
        }
    }
    for left_symbol in &left.symbols {
        for right_module in &right.modules {
            if semantic_module_contains(right_module, left_symbol) {
                conflicts.push(scope_conflict(
                    TaskScopeConflictKind::ModuleSymbolOverlap,
                    left,
                    right,
                    left_symbol.clone(),
                    right_module.clone(),
                ));
                if conflicts.len() >= TASK_PROPOSAL_MAX_REPORTED_CONFLICTS {
                    return true;
                }
            }
        }
    }
    false
}

fn scope_conflict(
    kind: TaskScopeConflictKind,
    left: &NormalizedTaskScope,
    right: &NormalizedTaskScope,
    left_value: String,
    right_value: String,
) -> TaskScopeConflict {
    TaskScopeConflict {
        kind,
        left_assignment_id: left.id.clone(),
        right_assignment_id: right.id.clone(),
        left_value,
        right_value,
    }
}

fn semantic_path_overlaps(left: &str, right: &str) -> bool {
    let left = left.split("::").collect::<Vec<_>>();
    let right = right.split("::").collect::<Vec<_>>();
    left.starts_with(&right) || right.starts_with(&left)
}

fn semantic_module_contains(module: &str, symbol: &str) -> bool {
    let module = module.split("::").collect::<Vec<_>>();
    let symbol = symbol.split("::").collect::<Vec<_>>();
    symbol.starts_with(&module)
}

pub fn propose_task_decomposition(
    repo: &Path,
    title: &str,
    body: &str,
) -> Result<TaskDecompositionProposal> {
    let fragments = task_spec_fragments(title, body)?;
    propose_task_decomposition_from_fragments(repo, fragments, title, body)
}

fn propose_task_decomposition_from_fragments(
    repo: &Path,
    fragments: Vec<TaskSpecFragment>,
    title: &str,
    body: &str,
) -> Result<TaskDecompositionProposal> {
    let mut diagnostics = TaskPathProposalDiagnostics::default();
    let files = collect_planning_files(repo, title, body, &mut diagnostics)?;
    let file_set = files.iter().cloned().collect::<BTreeSet<_>>();
    if let Some(assignment) =
        authoritative_single_file_assignment(repo, title, body, &fragments, &files, &file_set)
    {
        diagnostics.notes.push(
            "an explicit single-file-only directive bounded the task before semantic inference"
                .to_string(),
        );
        return Ok(TaskDecompositionProposal {
            fragments,
            assignments: vec![assignment],
            coverage_gaps: Vec::new(),
            diagnostics,
            disjointness: TaskDisjointnessReport {
                disjoint: true,
                conflicts: Vec::new(),
                conflicts_truncated: false,
            },
        });
    }
    let semantic_map = match repo_semantic::scan_repository(repo) {
        Ok(map) => {
            if !map.errors.is_empty() {
                diagnostics.degraded = true;
                diagnostics.notes.push(format!(
                    "semantic scan reported {} source error(s); affected fragments may have incomplete semantic intents",
                    map.errors.len()
                ));
            }
            Some(map)
        }
        Err(_) => {
            diagnostics.degraded = true;
            diagnostics
                .notes
                .push("semantic scan failed; used filename-only Rust matching".to_string());
            None
        }
    };

    let mut candidates = Vec::new();
    let mut coverage_gaps = Vec::new();
    let mut unresolved_named_paths = Vec::new();
    for fragment in &fragments {
        let proposed =
            propose_fragment_scope(fragment, repo, &files, &file_set, semantic_map.as_ref());
        let candidate = proposed.assignment;
        if proposed.suppressed_broad_paths > 0 {
            diagnostics.notes.push(format!(
                "{} preferred exact symbol implementation scope and suppressed {} broader module/declaration path match(es)",
                fragment.id, proposed.suppressed_broad_paths
            ));
        }
        diagnostics.notes.extend(proposed.notes);
        if candidate.assigned_paths.is_empty()
            && candidate.semantic_symbols.is_empty()
            && candidate.semantic_modules.is_empty()
        {
            let message = if let Some(path) = proposed.unresolved_named_paths.first() {
                unresolved_named_paths.push(path.clone());
                format!(
                    "named repository path '{path}' is not a readable regular file in the repository"
                )
            } else {
                "no repository path (documentation, policy, script, or other file) or Rust semantic intent matched this fragment"
                    .to_string()
            };
            coverage_gaps.push(TaskCoverageGap {
                fragment_id: fragment.id.clone(),
                kind: TaskCoverageGapKind::UnmatchedScope,
                message,
            });
        } else {
            candidates.push(candidate);
        }
    }
    if !coverage_gaps.is_empty() {
        diagnostics.notes.push(format!(
            "{} of {} spec fragment(s) have no proposed repository scope",
            coverage_gaps.len(),
            fragments.len()
        ));
    }

    let mut assignments = coalesce_overlapping_assignments(candidates)?;
    for assignment in &mut assignments {
        assignment.task = assignment
            .fragment_ids
            .iter()
            .filter_map(|fragment_id| {
                fragments
                    .iter()
                    .find(|fragment| &fragment.id == fragment_id)
                    .map(|fragment| fragment.text.as_str())
            })
            .collect::<Vec<_>>()
            .join("\n");
    }
    let disjointness = task_assignment_disjointness(&assignments)?;
    if !disjointness.disjoint {
        anyhow::bail!("internal task decomposition produced overlapping assignment scopes");
    }
    if assignments.is_empty() {
        if let Some(path) = unresolved_named_paths.first() {
            anyhow::bail!(
                "named repository path '{path}' is not a readable regular file in the repository; provide an existing Git-visible or on-disk repo-relative file (documentation, policy, script, or other), or a Rust module/symbol"
            );
        }
    }

    Ok(TaskDecompositionProposal {
        fragments,
        assignments,
        coverage_gaps,
        diagnostics,
        disjointness,
    })
}

fn authoritative_single_file_assignment(
    repo: &Path,
    title: &str,
    body: &str,
    fragments: &[TaskSpecFragment],
    files: &[PathBuf],
    file_set: &BTreeSet<PathBuf>,
) -> Option<TaskAssignmentProposal> {
    let full_text = format!("{title}\n{body}");
    let named = match_named_paths_in_text(repo, &full_text, files, file_set);
    if named.resolved.len() != 1 || !named.unresolved.is_empty() {
        return None;
    }
    let only_path = named.resolved.iter().next()?.clone();
    let directive_is_tied_to_path = full_text.lines().any(|line| {
        let line_named = match_named_paths_in_text(repo, line, files, file_set);
        line_named.resolved.contains(&only_path) && is_single_file_only_directive(line)
    });
    if !directive_is_tied_to_path {
        return None;
    }

    Some(TaskAssignmentProposal {
        id: "assignment-001".to_string(),
        task: fragments
            .iter()
            .map(|fragment| fragment.text.as_str())
            .collect::<Vec<_>>()
            .join("\n"),
        fragment_ids: fragments
            .iter()
            .map(|fragment| fragment.id.clone())
            .collect(),
        assigned_paths: vec![only_path],
        semantic_symbols: Vec::new(),
        semantic_modules: Vec::new(),
    })
}

fn is_single_file_only_directive(line: &str) -> bool {
    let normalized = normalize_text(line);
    [
        "edit only",
        "modify only",
        "change only",
        "only edit",
        "only modify",
        "only change",
    ]
    .iter()
    .any(|phrase| contains_phrase(&normalized, phrase))
}

pub fn propose_task_decomposition_with_optional_provider(
    repo: &Path,
    title: &str,
    body: &str,
    provider: Option<&mut dyn LlmProvider>,
    config: &ProviderPlanningConfig,
) -> Result<TaskPlanningSession> {
    match provider {
        Some(provider) => {
            propose_task_decomposition_with_provider(repo, title, body, provider, config)
        }
        None => Ok(TaskPlanningSession {
            proposal: propose_task_decomposition(repo, title, body)?,
            source: TaskPlanningSource::Heuristic,
            provider_id: None,
            model: None,
            provider_usage: Usage::default(),
            replans_used: 0,
            completed_fragment_ids: BTreeSet::new(),
            completed_assignments: Vec::new(),
            provider_assignment_tree: Vec::new(),
        }),
    }
}

pub fn propose_task_decomposition_with_provider<P: LlmProvider + ?Sized>(
    repo: &Path,
    title: &str,
    body: &str,
    provider: &mut P,
    config: &ProviderPlanningConfig,
) -> Result<TaskPlanningSession> {
    validate_provider_planning_config(config)?;
    let fragments = task_spec_fragments(title, body)?;
    let files = collect_repo_files(repo)?;
    let allowed_fragment_ids = fragments
        .iter()
        .map(|fragment| fragment.id.clone())
        .collect::<BTreeSet<_>>();
    let semantic_inventory = collect_provider_semantic_inventory(repo);
    let payload = serde_json::json!({
        "operation": "propose",
        "response_schema": {
            "assignments": [{
                "id": "non-empty unique string",
                "task": "bounded implementation task",
                "fragment_ids": ["fragment-001"],
                "assigned_paths": ["repository/relative/file"],
                "semantic_symbols": ["crate::module::symbol"],
                "semantic_modules": ["crate::module"],
                "child_assignments": ["recursive assignment objects with this same schema"]
            }]
        },
        "bounds": {
            "max_child_assignments": config.max_child_assignments,
            "max_depth": config.max_depth,
            "depth_semantics": "root assignments are depth 1; direct children are depth 2"
        },
        "requirements": [
            "Return only the JSON object in WorkProposal.summary.",
            "Use only supplied fragment ids, repository file paths, semantic modules, and semantic symbols.",
            "Every assignment must own at least one file.",
            "Executable leaves must cover every supplied fragment exactly once.",
            "Internal fragment_ids must equal the union of descendant leaf fragment_ids.",
            "Concurrent branches must be scope-disjoint; only strict ancestor/descendant nodes may share scope."
        ],
        "fragments": fragments,
        "repository_paths": files,
        "semantic_modules": semantic_inventory.modules,
        "semantic_symbols": semantic_inventory.symbols,
    });
    let request_id = format!("{}-proposal", config.request_id_prefix.trim());
    let response = complete_provider_planning_request(
        provider,
        config,
        request_id,
        "provider task decomposition",
        payload,
    )?;
    let provider_plan = parse_provider_task_plan(&response, "provider task decomposition")?;
    let (mut proposal, provider_assignment_tree) = validated_provider_proposal(
        fragments,
        provider_plan,
        &allowed_fragment_ids,
        &files,
        &semantic_inventory,
        &[],
        config,
        "provider task decomposition",
    )?;
    append_provider_diagnostics(&mut proposal.diagnostics, &response, "initial proposal");

    Ok(TaskPlanningSession {
        proposal,
        source: TaskPlanningSource::Provider,
        provider_id: Some(response.provider_id),
        model: Some(response.model),
        provider_usage: response.usage,
        replans_used: 0,
        completed_fragment_ids: BTreeSet::new(),
        completed_assignments: Vec::new(),
        provider_assignment_tree,
    })
}

pub fn replan_task_decomposition_with_provider<P: LlmProvider + ?Sized>(
    repo: &Path,
    session: &mut TaskPlanningSession,
    feedback: &TaskExecutionFeedback,
    provider: &mut P,
    config: &ProviderPlanningConfig,
) -> Result<()> {
    validate_provider_planning_config(config)?;
    if session.replans_used >= MAX_PROVIDER_REPLANS {
        anyhow::bail!(
            "provider re-planning limit of {MAX_PROVIDER_REPLANS} attempt(s) has been exhausted"
        );
    }
    let normalized_feedback =
        normalize_execution_feedback(feedback, &session.proposal, &session.completed_fragment_ids)?;
    let newly_completed_assignments = session
        .proposal
        .assignments
        .iter()
        .filter(|assignment| {
            normalized_feedback
                .completed_assignment_ids
                .contains(&assignment.id)
        })
        .cloned()
        .collect::<Vec<_>>();
    let newly_completed_fragment_ids = newly_completed_assignments
        .iter()
        .flat_map(|assignment| assignment.fragment_ids.iter().cloned())
        .collect::<BTreeSet<_>>();
    if let Some(overlap) = newly_completed_fragment_ids
        .intersection(&normalized_feedback.coverage_gap_fragment_ids)
        .next()
    {
        anyhow::bail!(
            "execution feedback marks newly completed fragment '{overlap}' as a coverage gap"
        );
    }
    let mut next_completed_fragment_ids = session.completed_fragment_ids.clone();
    next_completed_fragment_ids.extend(newly_completed_fragment_ids);
    let mut next_completed_assignments = session.completed_assignments.clone();
    next_completed_assignments.extend(newly_completed_assignments);
    let allowed_fragment_ids = session
        .proposal
        .fragments
        .iter()
        .map(|fragment| fragment.id.clone())
        .filter(|fragment_id| !next_completed_fragment_ids.contains(fragment_id))
        .collect::<BTreeSet<_>>();
    if allowed_fragment_ids.is_empty() {
        anyhow::bail!("provider re-planning has no remaining incomplete fragments");
    }

    let files = collect_repo_files(repo)?;
    let semantic_inventory = collect_provider_semantic_inventory(repo);
    let next_attempt = session.replans_used.saturating_add(1);
    let request_id = format!(
        "{}-replan-{next_attempt:02}",
        config.request_id_prefix.trim()
    );
    let payload = serde_json::json!({
        "operation": "replan",
        "attempt": next_attempt,
        "max_attempts": MAX_PROVIDER_REPLANS,
        "bounds": {
            "max_child_assignments": config.max_child_assignments,
            "max_depth": config.max_depth,
            "depth_semantics": "root assignments are depth 1; direct children are depth 2"
        },
        "requirements": [
            "Revise only incomplete fragments using the execution feedback.",
            "Return only a recursive provider task-plan JSON object in WorkProposal.summary.",
            "Every assignment must own at least one supplied repository file.",
            "Executable leaves must cover every remaining fragment exactly once.",
            "Do not reclaim path, module, or symbol scope from completed assignments.",
            "Concurrent branches must be scope-disjoint; only strict ancestor/descendant nodes may share scope."
        ],
        "fragments": session.proposal.fragments,
        "remaining_fragment_ids": allowed_fragment_ids,
        "completed_fragment_ids": next_completed_fragment_ids,
        "completed_assignments": next_completed_assignments,
        "current_proposal": session.proposal,
        "current_provider_assignment_tree": session.provider_assignment_tree,
        "execution_feedback": normalized_feedback,
        "repository_paths": files,
        "semantic_modules": semantic_inventory.modules,
        "semantic_symbols": semantic_inventory.symbols,
    });

    session.replans_used = next_attempt;
    let response = complete_provider_planning_request(
        provider,
        config,
        request_id,
        "provider task re-planning",
        payload,
    )?;
    let provider_plan = parse_provider_task_plan(&response, "provider task re-planning")?;
    let (mut proposal, provider_assignment_tree) = validated_provider_proposal(
        session.proposal.fragments.clone(),
        provider_plan,
        &allowed_fragment_ids,
        &files,
        &semantic_inventory,
        &next_completed_assignments,
        config,
        "provider task re-planning",
    )?;
    append_provider_diagnostics(
        &mut proposal.diagnostics,
        &response,
        &format!("re-plan attempt {next_attempt}"),
    );
    session.source = TaskPlanningSource::Provider;
    session.provider_id = Some(response.provider_id);
    session.model = Some(response.model);
    session.provider_usage = session.provider_usage.saturating_add(response.usage);
    session.proposal = proposal;
    session.provider_assignment_tree = provider_assignment_tree;
    session.completed_fragment_ids = next_completed_fragment_ids;
    session.completed_assignments = next_completed_assignments;
    Ok(())
}

/// Revises remaining heuristic work from execution feedback without invoking a planner model.
///
/// Completed assignments stay frozen. Remaining fragments are rematched through the
/// existing deterministic decomposer, optionally steered by feedback notes, then
/// checked against the same disjointness and completed-scope gates as provider replans.
/// This is the first #80 slice: a bounded feedback hook, not model-driven recursive planning.
pub fn replan_task_decomposition_from_feedback(
    repo: &Path,
    session: &mut TaskPlanningSession,
    feedback: &TaskExecutionFeedback,
) -> Result<()> {
    if session.source != TaskPlanningSource::Heuristic {
        anyhow::bail!(
            "feedback re-planning without a provider requires a heuristic planning session"
        );
    }
    if !session.provider_assignment_tree.is_empty() {
        anyhow::bail!("heuristic planning session unexpectedly carries a provider assignment tree");
    }
    if session.replans_used >= MAX_PROVIDER_REPLANS {
        anyhow::bail!("re-planning limit of {MAX_PROVIDER_REPLANS} attempt(s) has been exhausted");
    }

    let normalized_feedback =
        normalize_execution_feedback(feedback, &session.proposal, &session.completed_fragment_ids)?;
    let newly_completed_assignments = session
        .proposal
        .assignments
        .iter()
        .filter(|assignment| {
            normalized_feedback
                .completed_assignment_ids
                .contains(&assignment.id)
        })
        .cloned()
        .collect::<Vec<_>>();
    let newly_completed_fragment_ids = newly_completed_assignments
        .iter()
        .flat_map(|assignment| assignment.fragment_ids.iter().cloned())
        .collect::<BTreeSet<_>>();
    if let Some(overlap) = newly_completed_fragment_ids
        .intersection(&normalized_feedback.coverage_gap_fragment_ids)
        .next()
    {
        anyhow::bail!(
            "execution feedback marks newly completed fragment '{overlap}' as a coverage gap"
        );
    }

    let mut next_completed_fragment_ids = session.completed_fragment_ids.clone();
    next_completed_fragment_ids.extend(newly_completed_fragment_ids);
    let mut next_completed_assignments = session.completed_assignments.clone();
    next_completed_assignments.extend(newly_completed_assignments);

    let remaining_fragments = session
        .proposal
        .fragments
        .iter()
        .filter(|fragment| !next_completed_fragment_ids.contains(&fragment.id))
        .cloned()
        .collect::<Vec<_>>();
    if remaining_fragments.is_empty() {
        anyhow::bail!("feedback re-planning has no remaining incomplete fragments");
    }

    let rematch_body = remaining_fragments
        .iter()
        .map(|fragment| format!("- {}", fragment.text))
        .chain(
            normalized_feedback
                .notes
                .iter()
                .map(|note| format!("- {note}")),
        )
        .collect::<Vec<_>>()
        .join("\n");
    let rematch_fragments = remaining_fragments
        .iter()
        .map(|fragment| {
            let apply_notes = normalized_feedback
                .coverage_gap_fragment_ids
                .contains(&fragment.id)
                || session.proposal.assignments.iter().any(|assignment| {
                    normalized_feedback
                        .failed_assignment_ids
                        .contains(&assignment.id)
                        && assignment.fragment_ids.contains(&fragment.id)
                })
                || (normalized_feedback.failed_assignment_ids.is_empty()
                    && normalized_feedback.coverage_gap_fragment_ids.is_empty());
            let text = if apply_notes && !normalized_feedback.notes.is_empty() {
                let mut text = fragment.text.clone();
                for note in &normalized_feedback.notes {
                    text.push(' ');
                    text.push_str(note);
                }
                text
            } else {
                fragment.text.clone()
            };
            TaskSpecFragment {
                id: fragment.id.clone(),
                text,
            }
        })
        .collect::<Vec<_>>();

    let next_attempt = session.replans_used.saturating_add(1);
    let mut proposal =
        propose_task_decomposition_from_fragments(repo, rematch_fragments, "", &rematch_body)?;
    if proposal.assignments.is_empty() {
        anyhow::bail!("feedback re-planning produced no remaining executable assignments");
    }
    for (index, assignment) in proposal.assignments.iter_mut().enumerate() {
        assignment.id = format!("assignment-replan-{next_attempt:02}-{:03}", index + 1);
        assignment.task = assignment
            .fragment_ids
            .iter()
            .filter_map(|fragment_id| {
                remaining_fragments
                    .iter()
                    .find(|fragment| &fragment.id == fragment_id)
                    .map(|fragment| fragment.text.as_str())
            })
            .collect::<Vec<_>>()
            .join("\n");
    }
    let scoped_nodes = proposal
        .assignments
        .iter()
        .enumerate()
        .map(|(index, assignment)| (vec![index], assignment.clone()))
        .collect::<Vec<_>>();
    validate_completed_scope_not_reclaimed(
        &scoped_nodes,
        &next_completed_assignments,
        "feedback re-planning",
    )?;
    validate_task_assignment_disjointness(&proposal.assignments)
        .context("feedback re-planning remaining assignments are not independently assignable")?;
    proposal.fragments = session.proposal.fragments.clone();
    proposal.diagnostics.notes.push(format!(
        "heuristic re-plan attempt {next_attempt} used execution feedback without a planner model"
    ));

    session.replans_used = next_attempt;
    session.proposal = proposal;
    session.completed_fragment_ids = next_completed_fragment_ids;
    session.completed_assignments = next_completed_assignments;
    Ok(())
}

fn validate_provider_planning_config(config: &ProviderPlanningConfig) -> Result<()> {
    if config.request_id_prefix.trim().is_empty() {
        anyhow::bail!("provider planning request_id_prefix cannot be empty");
    }
    if config.model.trim().is_empty() {
        anyhow::bail!("provider planning model cannot be empty");
    }
    if config.max_child_assignments == 0
        || config.max_child_assignments > TASK_PROPOSAL_MAX_ASSIGNMENTS
    {
        anyhow::bail!(
            "provider planning max_child_assignments must be between 1 and {TASK_PROPOSAL_MAX_ASSIGNMENTS}"
        );
    }
    if config.max_depth == 0 || config.max_depth > REPOSITORY_INVENTORY_MAX_DEPTH {
        anyhow::bail!(
            "provider planning max_depth must be between 1 and {REPOSITORY_INVENTORY_MAX_DEPTH}"
        );
    }
    Ok(())
}

fn complete_provider_planning_request<P: LlmProvider + ?Sized>(
    provider: &mut P,
    config: &ProviderPlanningConfig,
    request_id: String,
    operation: &str,
    payload: serde_json::Value,
) -> Result<LlmResponse> {
    let task = format!(
        "{operation}. Deterministic MACO validation is authoritative; do not propose commands or patches.\n{}",
        serde_json::to_string(&payload).context("failed to serialize provider planning input")?
    );
    let budget = RequestBudget::default();
    let mut context = PromptContext::new(task, "supervisor-planner");
    context.budget = budget;
    context.provider_capabilities = provider.capabilities();
    let prompt = context.assemble_prompt(&Redactor::new());
    if prompt.render().len() > budget.max_input_chars {
        anyhow::bail!(
            "{operation} prompt exceeds its {} character provider boundary",
            budget.max_input_chars
        );
    }
    let mut request =
        LlmRequest::new(request_id.clone(), config.model.trim(), prompt).with_budget(budget);
    request
        .metadata
        .insert("planning_operation".to_string(), operation.to_string());
    let response = provider.complete(request).with_context(|| {
        format!(
            "provider '{}' failed during {operation}",
            provider.provider_id()
        )
    })?;
    if response.request_id != request_id {
        anyhow::bail!(
            "{operation} response request id '{}' does not match '{}'",
            response.request_id,
            request_id
        );
    }
    if !response.proposal.commands.is_empty() || !response.proposal.patches.is_empty() {
        anyhow::bail!("{operation} response must not contain commands or patches");
    }
    Ok(response)
}

fn parse_provider_task_plan(
    response: &LlmResponse,
    operation: &str,
) -> Result<ProviderRecursiveTaskPlan> {
    let summary = &response.proposal.summary;
    if let Ok(recursive) = serde_json::from_str::<ProviderRecursiveTaskPlan>(summary) {
        return Ok(recursive);
    }
    let flat: ProviderTaskPlan = serde_json::from_str(summary).with_context(|| {
        format!("{operation} response summary is not a recursive provider task-plan JSON object")
    })?;
    Ok(flat.into())
}

#[derive(Debug, Clone, Default)]
struct ProviderSemanticInventory {
    modules: BTreeSet<String>,
    symbols: BTreeSet<String>,
}

fn collect_provider_semantic_inventory(repo: &Path) -> ProviderSemanticInventory {
    let Ok(map) = repo_semantic::scan_repository(repo) else {
        return ProviderSemanticInventory::default();
    };
    let modules = map
        .files
        .iter()
        .map(|file| file.module_path.join("::"))
        .chain(
            map.symbols
                .iter()
                .filter(|symbol| symbol.kind == repo_semantic::SemanticSymbolKind::Module)
                .map(|symbol| symbol.qualified_path.join("::")),
        )
        .filter(|module| !module.is_empty())
        .collect();
    let symbols = map
        .symbols
        .iter()
        .map(|symbol| symbol.qualified_path.join("::"))
        .filter(|symbol| !symbol.is_empty())
        .collect();
    ProviderSemanticInventory { modules, symbols }
}

struct ProviderTreeValidationState {
    ids: BTreeSet<String>,
    leaf_fragment_ids: BTreeSet<String>,
    leaf_assignments: Vec<TaskAssignmentProposal>,
    scoped_nodes: Vec<(Vec<usize>, TaskAssignmentProposal)>,
    total_nodes: usize,
    total_scope_items: usize,
    total_task_bytes: usize,
}

impl ProviderTreeValidationState {
    fn new() -> Self {
        Self {
            ids: BTreeSet::new(),
            leaf_fragment_ids: BTreeSet::new(),
            leaf_assignments: Vec::new(),
            scoped_nodes: Vec::new(),
            total_nodes: 0,
            total_scope_items: 0,
            total_task_bytes: 0,
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn validated_provider_proposal(
    fragments: Vec<TaskSpecFragment>,
    provider_plan: ProviderRecursiveTaskPlan,
    allowed_fragment_ids: &BTreeSet<String>,
    files: &[PathBuf],
    semantic_inventory: &ProviderSemanticInventory,
    completed_assignments: &[TaskAssignmentProposal],
    config: &ProviderPlanningConfig,
    operation: &str,
) -> Result<(TaskDecompositionProposal, Vec<ProviderTaskAssignmentTree>)> {
    if provider_plan.assignments.is_empty() {
        anyhow::bail!("{operation} returned no actionable assignments");
    }
    if provider_plan.assignments.len() > config.max_child_assignments {
        anyhow::bail!(
            "{operation} returned {} root assignments but at most {} are allowed",
            provider_plan.assignments.len(),
            config.max_child_assignments
        );
    }
    let file_set = files.iter().cloned().collect::<BTreeSet<_>>();
    let mut state = ProviderTreeValidationState::new();
    let mut normalized_roots = Vec::with_capacity(provider_plan.assignments.len());
    for (root_index, root) in provider_plan.assignments.into_iter().enumerate() {
        let (normalized, _) = normalize_provider_assignment_tree(
            root,
            1,
            vec![root_index],
            allowed_fragment_ids,
            &file_set,
            semantic_inventory,
            config,
            operation,
            &mut state,
        )?;
        normalized_roots.push(normalized);
    }
    if state.leaf_fragment_ids != *allowed_fragment_ids {
        let missing = allowed_fragment_ids
            .difference(&state.leaf_fragment_ids)
            .cloned()
            .collect::<Vec<_>>();
        anyhow::bail!(
            "{operation} executable leaves do not cover every incomplete fragment; missing {missing:?}"
        );
    }
    validate_concurrent_tree_disjointness(&state.scoped_nodes, operation)?;
    validate_completed_scope_not_reclaimed(&state.scoped_nodes, completed_assignments, operation)?;
    validate_task_assignment_disjointness(&state.leaf_assignments)
        .with_context(|| format!("{operation} executable leaves failed disjointness validation"))?;
    let disjointness = task_assignment_disjointness(&state.leaf_assignments)?;
    Ok((
        TaskDecompositionProposal {
            fragments,
            assignments: state.leaf_assignments,
            coverage_gaps: Vec::new(),
            diagnostics: TaskPathProposalDiagnostics::default(),
            disjointness,
        },
        normalized_roots,
    ))
}

#[allow(clippy::too_many_arguments)]
fn normalize_provider_assignment_tree(
    node: ProviderTaskAssignmentTree,
    depth: usize,
    lineage: Vec<usize>,
    allowed_fragment_ids: &BTreeSet<String>,
    file_set: &BTreeSet<PathBuf>,
    semantic_inventory: &ProviderSemanticInventory,
    config: &ProviderPlanningConfig,
    operation: &str,
    state: &mut ProviderTreeValidationState,
) -> Result<(ProviderTaskAssignmentTree, BTreeSet<String>)> {
    if depth > config.max_depth {
        anyhow::bail!(
            "{operation} assignment tree reaches depth {depth} but max_depth is {} (roots are depth 1)",
            config.max_depth
        );
    }
    if node.child_assignments.len() > config.max_child_assignments {
        anyhow::bail!(
            "{operation} assignment '{}' has {} children but at most {} are allowed",
            node.id.trim(),
            node.child_assignments.len(),
            config.max_child_assignments
        );
    }
    state.total_nodes = state
        .total_nodes
        .checked_add(1)
        .context("provider planning assignment count overflowed")?;
    if state.total_nodes > config.max_child_assignments {
        anyhow::bail!(
            "{operation} contains more than {} total flattened assignments",
            config.max_child_assignments
        );
    }
    if state.total_nodes > TASK_PROPOSAL_MAX_ASSIGNMENTS {
        anyhow::bail!(
            "{operation} contains more than {TASK_PROPOSAL_MAX_ASSIGNMENTS} total assignments"
        );
    }

    let id = node.id.trim().to_string();
    if id.is_empty() {
        anyhow::bail!("{operation} assignment id cannot be empty");
    }
    if !state.ids.insert(id.clone()) {
        anyhow::bail!("{operation} repeats assignment id '{id}'");
    }
    let task = node.task.trim().to_string();
    if task.is_empty() {
        anyhow::bail!("{operation} assignment '{id}' has an empty task");
    }
    if task.len() > TASK_SPEC_MAX_FRAGMENT_BYTES {
        anyhow::bail!(
            "{operation} assignment '{id}' task contains {} bytes but at most {} are allowed",
            task.len(),
            TASK_SPEC_MAX_FRAGMENT_BYTES
        );
    }
    state.total_task_bytes = state
        .total_task_bytes
        .checked_add(task.len())
        .context("provider planning task byte count overflowed")?;
    if state.total_task_bytes > TASK_SPEC_MAX_TOTAL_BYTES {
        anyhow::bail!(
            "{operation} assignment tasks exceed their {TASK_SPEC_MAX_TOTAL_BYTES}-byte aggregate limit"
        );
    }

    let fragment_ids =
        normalize_provider_fragment_ids(node.fragment_ids, allowed_fragment_ids, &id, operation)?;
    let assigned_paths = node
        .assigned_paths
        .iter()
        .map(normalize_repo_relative_path)
        .collect::<std::result::Result<BTreeSet<_>, _>>()
        .with_context(|| format!("{operation} assignment '{id}' has an invalid path"))?;
    if assigned_paths.is_empty() {
        anyhow::bail!("{operation} assignment '{id}' must own at least one repository file");
    }
    if let Some(unknown) = assigned_paths.iter().find(|path| !file_set.contains(*path)) {
        anyhow::bail!(
            "{operation} assignment '{id}' references repository path '{}' that is not an inventoried file",
            unknown.display()
        );
    }
    let semantic_symbols = normalize_semantic_values(&node.semantic_symbols)?;
    if let Some(unknown) = semantic_symbols
        .iter()
        .find(|symbol| !semantic_inventory.symbols.contains(*symbol))
    {
        anyhow::bail!(
            "{operation} assignment '{id}' references unknown semantic symbol '{unknown}'"
        );
    }
    let semantic_modules = normalize_semantic_values(&node.semantic_modules)?;
    if let Some(unknown) = semantic_modules
        .iter()
        .find(|module| !semantic_inventory.modules.contains(*module))
    {
        anyhow::bail!(
            "{operation} assignment '{id}' references unknown semantic module '{unknown}'"
        );
    }
    let scope_items = assigned_paths
        .len()
        .checked_add(semantic_symbols.len())
        .and_then(|count| count.checked_add(semantic_modules.len()))
        .context("provider planning scope item count overflowed")?;
    if scope_items > TASK_PROPOSAL_MAX_SCOPE_ITEMS_PER_ASSIGNMENT {
        anyhow::bail!(
            "{operation} assignment '{id}' contains {scope_items} scope items but at most {TASK_PROPOSAL_MAX_SCOPE_ITEMS_PER_ASSIGNMENT} are allowed"
        );
    }
    state.total_scope_items = state
        .total_scope_items
        .checked_add(scope_items)
        .context("provider planning total scope item count overflowed")?;
    if state.total_scope_items > TASK_PROPOSAL_MAX_TOTAL_SCOPE_ITEMS {
        anyhow::bail!(
            "{operation} contains more than {TASK_PROPOSAL_MAX_TOTAL_SCOPE_ITEMS} total scope items"
        );
    }

    let assignment = TaskAssignmentProposal {
        id: id.clone(),
        task: task.clone(),
        fragment_ids: fragment_ids.iter().cloned().collect(),
        assigned_paths: collapse_covered_paths(assigned_paths),
        semantic_symbols,
        semantic_modules,
    };
    state
        .scoped_nodes
        .push((lineage.clone(), assignment.clone()));

    let is_leaf = node.child_assignments.is_empty();
    let mut normalized_children = Vec::with_capacity(node.child_assignments.len());
    let descendant_fragment_ids = if is_leaf {
        for fragment_id in &fragment_ids {
            if !state.leaf_fragment_ids.insert(fragment_id.clone()) {
                anyhow::bail!(
                    "{operation} maps fragment '{fragment_id}' to more than one executable leaf"
                );
            }
        }
        state.leaf_assignments.push(assignment.clone());
        fragment_ids.clone()
    } else {
        let mut descendants = BTreeSet::new();
        for (child_index, child) in node.child_assignments.into_iter().enumerate() {
            let mut child_lineage = lineage.clone();
            child_lineage.push(child_index);
            let (normalized_child, child_fragments) = normalize_provider_assignment_tree(
                child,
                depth.saturating_add(1),
                child_lineage,
                allowed_fragment_ids,
                file_set,
                semantic_inventory,
                config,
                operation,
                state,
            )?;
            descendants.extend(child_fragments);
            normalized_children.push(normalized_child);
        }
        if fragment_ids != descendants {
            anyhow::bail!(
                "{operation} internal assignment '{id}' fragment_ids must exactly match its descendant executable leaves"
            );
        }
        descendants
    };

    Ok((
        ProviderTaskAssignmentTree {
            id,
            task,
            fragment_ids: fragment_ids.into_iter().collect(),
            assigned_paths: assignment.assigned_paths,
            semantic_symbols: assignment.semantic_symbols,
            semantic_modules: assignment.semantic_modules,
            child_assignments: normalized_children,
        },
        descendant_fragment_ids,
    ))
}

fn normalize_provider_fragment_ids(
    fragment_ids: Vec<String>,
    allowed_fragment_ids: &BTreeSet<String>,
    assignment_id: &str,
    operation: &str,
) -> Result<BTreeSet<String>> {
    if fragment_ids.is_empty() {
        anyhow::bail!(
            "{operation} assignment '{assignment_id}' must reference at least one fragment"
        );
    }
    let mut normalized = BTreeSet::new();
    for fragment_id in fragment_ids {
        let fragment_id = fragment_id.trim().to_string();
        if !allowed_fragment_ids.contains(&fragment_id) {
            anyhow::bail!(
                "{operation} assignment '{assignment_id}' references unavailable fragment '{fragment_id}'"
            );
        }
        if !normalized.insert(fragment_id.clone()) {
            anyhow::bail!(
                "{operation} assignment '{assignment_id}' repeats fragment '{fragment_id}'"
            );
        }
    }
    Ok(normalized)
}

fn validate_concurrent_tree_disjointness(
    scoped_nodes: &[(Vec<usize>, TaskAssignmentProposal)],
    operation: &str,
) -> Result<()> {
    let normalized = scoped_nodes
        .iter()
        .map(|(lineage, assignment)| Ok((lineage, normalize_task_scope(assignment)?)))
        .collect::<Result<Vec<_>>>()?;
    for left_index in 0..normalized.len() {
        let (left_lineage, left) = &normalized[left_index];
        for (right_lineage, right) in &normalized[left_index + 1..] {
            if lineage_is_ancestor(left_lineage, right_lineage)
                || lineage_is_ancestor(right_lineage, left_lineage)
            {
                continue;
            }
            let mut conflicts = Vec::new();
            collect_task_scope_conflicts(left, right, &mut conflicts);
            if let Some(conflict) = conflicts.first() {
                anyhow::bail!(
                    "{operation} concurrent assignments '{}' and '{}' overlap: {:?} between '{}' and '{}'",
                    conflict.left_assignment_id,
                    conflict.right_assignment_id,
                    conflict.kind,
                    conflict.left_value,
                    conflict.right_value
                );
            }
        }
    }
    Ok(())
}

fn lineage_is_ancestor(candidate: &[usize], descendant: &[usize]) -> bool {
    candidate.len() < descendant.len() && descendant.starts_with(candidate)
}

fn validate_completed_scope_not_reclaimed(
    scoped_nodes: &[(Vec<usize>, TaskAssignmentProposal)],
    completed_assignments: &[TaskAssignmentProposal],
    operation: &str,
) -> Result<()> {
    let completed = completed_assignments
        .iter()
        .map(normalize_task_scope)
        .collect::<Result<Vec<_>>>()?;
    for (_, assignment) in scoped_nodes {
        let candidate = normalize_task_scope(assignment)?;
        for completed_assignment in &completed {
            let mut conflicts = Vec::new();
            collect_task_scope_conflicts(&candidate, completed_assignment, &mut conflicts);
            if let Some(conflict) = conflicts.first() {
                anyhow::bail!(
                    "{operation} assignment '{}' reclaims completed scope from '{}': {:?} between '{}' and '{}'",
                    candidate.id,
                    completed_assignment.id,
                    conflict.kind,
                    conflict.left_value,
                    conflict.right_value
                );
            }
        }
    }
    Ok(())
}

fn append_provider_diagnostics(
    diagnostics: &mut TaskPathProposalDiagnostics,
    response: &LlmResponse,
    phase: &str,
) {
    diagnostics.notes.push(format!(
        "provider '{}' model '{}' supplied {phase} using {} token(s)",
        response.provider_id, response.model, response.usage.total_tokens
    ));
    diagnostics.notes.extend(
        response
            .proposal
            .notes
            .iter()
            .map(|note| format!("provider note: {note}")),
    );
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct NormalizedTaskExecutionFeedback {
    completed_assignment_ids: BTreeSet<String>,
    failed_assignment_ids: BTreeSet<String>,
    coverage_gap_fragment_ids: BTreeSet<String>,
    notes: Vec<String>,
}

fn normalize_execution_feedback(
    feedback: &TaskExecutionFeedback,
    proposal: &TaskDecompositionProposal,
    completed_fragment_ids: &BTreeSet<String>,
) -> Result<NormalizedTaskExecutionFeedback> {
    let item_count = feedback
        .completed_assignment_ids
        .len()
        .checked_add(feedback.failed_assignment_ids.len())
        .and_then(|count| count.checked_add(feedback.coverage_gap_fragment_ids.len()))
        .and_then(|count| count.checked_add(feedback.notes.len()))
        .context("execution feedback item count overflowed")?;
    if item_count == 0 {
        anyhow::bail!("re-planning requires at least one execution feedback item");
    }
    if item_count > PROVIDER_PLANNING_MAX_FEEDBACK_ITEMS {
        anyhow::bail!(
            "execution feedback contains {item_count} items but at most {PROVIDER_PLANNING_MAX_FEEDBACK_ITEMS} are allowed"
        );
    }
    let mut total_bytes = 0usize;
    for item in feedback
        .completed_assignment_ids
        .iter()
        .chain(&feedback.failed_assignment_ids)
        .chain(&feedback.coverage_gap_fragment_ids)
        .chain(&feedback.notes)
    {
        if item.len() > PROVIDER_PLANNING_MAX_FEEDBACK_ITEM_BYTES {
            anyhow::bail!(
                "execution feedback item contains {} bytes but at most {} are allowed",
                item.len(),
                PROVIDER_PLANNING_MAX_FEEDBACK_ITEM_BYTES
            );
        }
        total_bytes = total_bytes
            .checked_add(item.len())
            .context("execution feedback byte count overflowed")?;
        if total_bytes > PROVIDER_PLANNING_MAX_TOTAL_FEEDBACK_BYTES {
            anyhow::bail!(
                "execution feedback exceeds its {PROVIDER_PLANNING_MAX_TOTAL_FEEDBACK_BYTES}-byte aggregate limit"
            );
        }
    }
    let known_assignment_ids = proposal
        .assignments
        .iter()
        .map(|assignment| assignment.id.clone())
        .collect::<BTreeSet<_>>();
    let declared_fragment_ids = proposal
        .fragments
        .iter()
        .map(|fragment| fragment.id.clone())
        .collect::<BTreeSet<_>>();
    let completed_assignment_ids = normalize_feedback_ids(
        &feedback.completed_assignment_ids,
        &known_assignment_ids,
        "completed assignment",
    )?;
    let failed_assignment_ids = normalize_feedback_ids(
        &feedback.failed_assignment_ids,
        &known_assignment_ids,
        "failed assignment",
    )?;
    if let Some(overlap) = completed_assignment_ids
        .intersection(&failed_assignment_ids)
        .next()
    {
        anyhow::bail!("execution feedback marks assignment '{overlap}' both completed and failed");
    }
    let coverage_gap_fragment_ids = normalize_feedback_ids(
        &feedback.coverage_gap_fragment_ids,
        &declared_fragment_ids,
        "coverage gap fragment",
    )?;
    if let Some(completed) = coverage_gap_fragment_ids
        .iter()
        .find(|fragment_id| completed_fragment_ids.contains(*fragment_id))
    {
        anyhow::bail!(
            "execution feedback reports completed fragment '{completed}' as a coverage gap"
        );
    }
    let notes = feedback
        .notes
        .iter()
        .map(|note| note.trim())
        .filter(|note| !note.is_empty())
        .map(str::to_string)
        .collect::<Vec<_>>();
    if completed_assignment_ids.is_empty()
        && failed_assignment_ids.is_empty()
        && coverage_gap_fragment_ids.is_empty()
        && notes.is_empty()
    {
        anyhow::bail!("re-planning requires non-empty normalized execution feedback");
    }
    Ok(NormalizedTaskExecutionFeedback {
        completed_assignment_ids,
        failed_assignment_ids,
        coverage_gap_fragment_ids,
        notes,
    })
}

fn normalize_feedback_ids(
    values: &[String],
    known_values: &BTreeSet<String>,
    label: &str,
) -> Result<BTreeSet<String>> {
    let mut normalized = BTreeSet::new();
    for value in values {
        let value = value.trim();
        if value.is_empty() {
            anyhow::bail!("execution feedback {label} id cannot be empty");
        }
        if !known_values.contains(value) {
            anyhow::bail!("execution feedback names unknown {label} '{value}'");
        }
        if !normalized.insert(value.to_string()) {
            anyhow::bail!("execution feedback repeats {label} '{value}'");
        }
    }
    Ok(normalized)
}

fn propose_fragment_scope(
    fragment: &TaskSpecFragment,
    repo: &Path,
    files: &[PathBuf],
    file_set: &BTreeSet<PathBuf>,
    semantic_map: Option<&repo_semantic::SemanticRepoMap>,
) -> ProposedFragmentScope {
    let lowered = fragment.text.to_ascii_lowercase();
    let normalized_text = normalize_text(&fragment.text);
    let mut explicit_paths = BTreeSet::new();
    let mut broad_semantic_paths = BTreeSet::new();
    let mut exact_symbol_paths = BTreeSet::new();
    let mut semantic_symbols = BTreeSet::new();
    let mut semantic_modules = BTreeSet::new();
    let mut notes = Vec::new();

    for file in files {
        let display = file.to_string_lossy().to_ascii_lowercase();
        if contains_path_mention(&lowered, &display) {
            explicit_paths.insert(file.clone());
        }
    }
    let named = match_named_paths_in_text(repo, &fragment.text, files, file_set);
    explicit_paths.extend(named.resolved);
    notes.extend(named.notes);
    if explicit_paths.is_empty() {
        propose_docs_paths(&normalized_text, file_set, &mut explicit_paths);
        propose_non_rust_identifier_paths(&normalized_text, files, &mut explicit_paths);
    }

    if let Some(map) = semantic_map {
        for file in &map.files {
            if !file_set.contains(&file.path) {
                continue;
            }
            if identifier_matches(&normalized_text, &file.path) {
                broad_semantic_paths.insert(file.path.clone());
            }
            if module_matches(&normalized_text, &file.module_path) {
                broad_semantic_paths.insert(file.path.clone());
                semantic_modules.insert(file.module_path.join("::"));
            }
        }
        for symbol in &map.symbols {
            if !file_set.contains(&symbol.file)
                || !(identifier_matches_text(&normalized_text, &symbol.name)
                    || qualified_path_matches(&normalized_text, &symbol.qualified_path))
            {
                continue;
            }
            let qualified = symbol.qualified_path.join("::");
            if symbol.kind == repo_semantic::SemanticSymbolKind::Module {
                broad_semantic_paths.insert(symbol.file.clone());
                semantic_modules.insert(qualified);
            } else {
                exact_symbol_paths.insert(symbol.file.clone());
                semantic_symbols.insert(qualified);
            }
        }
    } else {
        for file in file_set {
            if file
                .extension()
                .and_then(|extension| extension.to_str())
                .is_some_and(|extension| extension.eq_ignore_ascii_case("rs"))
                && identifier_matches(&normalized_text, file)
            {
                broad_semantic_paths.insert(file.clone());
            }
        }
    }

    let suppressed_broad_paths = if exact_symbol_paths.is_empty() {
        explicit_paths.extend(broad_semantic_paths);
        0
    } else {
        let suppressed = broad_semantic_paths
            .difference(&exact_symbol_paths)
            .filter(|path| !explicit_paths.contains(*path))
            .count();
        explicit_paths.extend(exact_symbol_paths);
        semantic_modules.clear();
        suppressed
    };

    ProposedFragmentScope {
        assignment: TaskAssignmentProposal {
            id: fragment.id.clone(),
            task: fragment.text.clone(),
            fragment_ids: vec![fragment.id.clone()],
            assigned_paths: collapse_covered_paths(explicit_paths),
            semantic_symbols: semantic_symbols.into_iter().collect(),
            semantic_modules: semantic_modules.into_iter().collect(),
        },
        suppressed_broad_paths,
        unresolved_named_paths: named.unresolved,
        notes,
    }
}

struct ProposedFragmentScope {
    assignment: TaskAssignmentProposal,
    suppressed_broad_paths: usize,
    unresolved_named_paths: Vec<String>,
    notes: Vec<String>,
}

fn module_matches(normalized_text: &str, module_path: &[String]) -> bool {
    module_path
        .last()
        .is_some_and(|module| identifier_matches_text(normalized_text, module))
        || qualified_path_matches(normalized_text, module_path)
}

fn coalesce_overlapping_assignments(
    candidates: Vec<TaskAssignmentProposal>,
) -> Result<Vec<TaskAssignmentProposal>> {
    let mut assignments: Vec<TaskAssignmentProposal> = Vec::new();
    for candidate in candidates {
        let mut merged = candidate;
        let mut index = 0;
        while index < assignments.len() {
            let overlap =
                !task_assignment_disjointness(&[assignments[index].clone(), merged.clone()])?
                    .disjoint;
            if overlap {
                let existing = assignments.remove(index);
                merged = merge_assignment_proposals(existing, merged);
                index = 0;
            } else {
                index += 1;
            }
        }
        assignments.push(merged);
    }
    assignments.sort_by(|left, right| left.fragment_ids.cmp(&right.fragment_ids));
    for (index, assignment) in assignments.iter_mut().enumerate() {
        assignment.id = format!("assignment-{:03}", index + 1);
    }
    Ok(assignments)
}

fn merge_assignment_proposals(
    left: TaskAssignmentProposal,
    right: TaskAssignmentProposal,
) -> TaskAssignmentProposal {
    let mut fragment_ids = left
        .fragment_ids
        .into_iter()
        .chain(right.fragment_ids)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    fragment_ids.sort();
    let assigned_paths = collapse_covered_paths(
        left.assigned_paths
            .into_iter()
            .chain(right.assigned_paths)
            .collect(),
    );
    let semantic_symbols = left
        .semantic_symbols
        .into_iter()
        .chain(right.semantic_symbols)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let semantic_modules = left
        .semantic_modules
        .into_iter()
        .chain(right.semantic_modules)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    TaskAssignmentProposal {
        id: fragment_ids
            .first()
            .cloned()
            .unwrap_or_else(|| "assignment".to_string()),
        task: format!("{}\n{}", left.task, right.task),
        fragment_ids,
        assigned_paths,
        semantic_symbols,
        semantic_modules,
    }
}

fn task_spec_fragments(title: &str, body: &str) -> Result<Vec<TaskSpecFragment>> {
    let total_bytes = title
        .len()
        .checked_add(body.len())
        .context("task spec byte length overflowed")?;
    if total_bytes > TASK_SPEC_MAX_TOTAL_BYTES {
        anyhow::bail!(
            "task spec contains {total_bytes} bytes but at most {TASK_SPEC_MAX_TOTAL_BYTES} are allowed"
        );
    }

    let mut texts = Vec::new();
    push_fragment_text(&mut texts, normalize_fragment_text(title))?;
    let mut paragraph = String::new();
    for line in body.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            push_fragment_text(&mut texts, std::mem::take(&mut paragraph))?;
            continue;
        }
        let (line_text, starts_fragment) = strip_markdown_fragment_marker(trimmed);
        if starts_fragment {
            push_fragment_text(&mut texts, std::mem::take(&mut paragraph))?;
        } else if !paragraph.is_empty() {
            paragraph.push(' ');
        }
        paragraph.push_str(line_text);
    }
    push_fragment_text(&mut texts, paragraph)?;
    if texts.is_empty() {
        anyhow::bail!("task spec must contain at least one non-empty fragment");
    }

    Ok(texts
        .into_iter()
        .enumerate()
        .map(|(index, text)| TaskSpecFragment {
            id: format!("fragment-{:03}", index + 1),
            text,
        })
        .collect())
}

fn push_fragment_text(fragments: &mut Vec<String>, text: String) -> Result<()> {
    if text.is_empty() {
        return Ok(());
    }
    if text.len() > TASK_SPEC_MAX_FRAGMENT_BYTES {
        anyhow::bail!(
            "task spec fragment contains {} bytes but at most {} are allowed",
            text.len(),
            TASK_SPEC_MAX_FRAGMENT_BYTES
        );
    }
    if fragments.len() >= TASK_SPEC_MAX_FRAGMENTS {
        anyhow::bail!(
            "task spec contains more than {} fragments",
            TASK_SPEC_MAX_FRAGMENTS
        );
    }
    fragments.push(text);
    Ok(())
}

fn normalize_fragment_text(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn strip_markdown_fragment_marker(line: &str) -> (&str, bool) {
    if let Some(stripped) = line.strip_prefix('#') {
        return (stripped.trim_start_matches('#').trim(), true);
    }
    for marker in ["- ", "* ", "+ "] {
        if let Some(stripped) = line.strip_prefix(marker) {
            return (stripped.trim(), true);
        }
    }
    if let Some((number, stripped)) = line.split_once(". ") {
        if !number.is_empty() && number.bytes().all(|byte| byte.is_ascii_digit()) {
            return (stripped.trim(), true);
        }
    }
    (line, false)
}

pub fn propose_task_paths(repo: &Path, title: &str, body: &str) -> Result<Vec<PathBuf>> {
    Ok(propose_task_path_proposal(repo, title, body)?.paths)
}

pub fn propose_task_path_proposal(
    repo: &Path,
    title: &str,
    body: &str,
) -> Result<TaskPathProposal> {
    let text = format!("{title}\n{body}");
    let lowered = text.to_ascii_lowercase();
    let normalized_text = normalize_text(&text);
    let mut diagnostics = TaskPathProposalDiagnostics::default();
    let files = collect_planning_files(repo, title, body, &mut diagnostics)?;
    let file_set = files.iter().cloned().collect::<BTreeSet<_>>();
    let mut proposed = BTreeSet::new();

    for file in &files {
        let display = file.to_string_lossy().to_ascii_lowercase();
        if contains_path_mention(&lowered, &display) {
            proposed.insert(file.clone());
        }
    }
    let named = match_named_paths_in_text(repo, &text, &files, &file_set);
    proposed.extend(named.resolved);
    diagnostics.notes.extend(named.notes);

    propose_docs_paths(&normalized_text, &file_set, &mut proposed);
    propose_non_rust_identifier_paths(&normalized_text, &files, &mut proposed);
    propose_rust_paths(
        repo,
        &normalized_text,
        &file_set,
        &mut proposed,
        &mut diagnostics,
    );

    if proposed.is_empty() && file_set.contains(Path::new("README.md")) {
        proposed.insert(PathBuf::from("README.md"));
    }

    Ok(TaskPathProposal {
        paths: collapse_covered_paths(proposed),
        diagnostics,
    })
}

pub fn paths_overlap(left: &Path, right: &Path) -> bool {
    left == right || left.starts_with(right) || right.starts_with(left)
}

pub fn any_path_overlaps<'a>(
    target_paths: &[PathBuf],
    candidate_paths: impl IntoIterator<Item = &'a PathBuf>,
) -> Vec<PathBuf> {
    candidate_paths
        .into_iter()
        .filter(|candidate| {
            target_paths
                .iter()
                .any(|target| paths_overlap(target, candidate))
        })
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn propose_docs_paths(
    normalized_text: &str,
    file_set: &BTreeSet<PathBuf>,
    proposed: &mut BTreeSet<PathBuf>,
) {
    if contains_phrase(normalized_text, "readme") && file_set.contains(Path::new("README.md")) {
        proposed.insert(PathBuf::from("README.md"));
    }
    if (contains_phrase(normalized_text, "release notes")
        || contains_phrase(normalized_text, "release_notes"))
        && file_set.contains(Path::new("RELEASE_NOTES.md"))
    {
        proposed.insert(PathBuf::from("RELEASE_NOTES.md"));
    }
    if contains_phrase(normalized_text, "documentation")
        || contains_phrase(normalized_text, "docs")
        || contains_phrase(normalized_text, "doc")
    {
        let docs_paths = file_set
            .iter()
            .filter(|path| is_conventional_documentation_path(path))
            .cloned()
            .collect::<Vec<_>>();
        if docs_paths.is_empty() && file_set.contains(Path::new("README.md")) {
            proposed.insert(PathBuf::from("README.md"));
        } else {
            proposed.extend(docs_paths);
        }
    }
}

fn propose_rust_paths(
    repo: &Path,
    normalized_text: &str,
    file_set: &BTreeSet<PathBuf>,
    proposed: &mut BTreeSet<PathBuf>,
    diagnostics: &mut TaskPathProposalDiagnostics,
) {
    match repo_semantic::scan_repository(repo) {
        Ok(map) => {
            for file in &map.files {
                if file_set.contains(&file.path) && identifier_matches(normalized_text, &file.path)
                {
                    proposed.insert(file.path.clone());
                }
                if let Some(module) = file.module_path.last() {
                    if identifier_matches_text(normalized_text, module) {
                        proposed.insert(file.path.clone());
                    }
                }
            }

            for symbol in &map.symbols {
                if identifier_matches_text(normalized_text, &symbol.name)
                    || qualified_path_matches(normalized_text, &symbol.qualified_path)
                {
                    proposed.insert(symbol.file.clone());
                }
            }
        }
        Err(_) => {
            diagnostics.degraded = true;
            diagnostics
                .notes
                .push("semantic scan failed; used filename-only Rust matching".to_string());
            for file in file_set {
                if file
                    .extension()
                    .and_then(|extension| extension.to_str())
                    .is_some_and(|extension| extension.eq_ignore_ascii_case("rs"))
                    && identifier_matches(normalized_text, file)
                {
                    proposed.insert(file.clone());
                }
            }
        }
    }
}

fn identifier_matches(normalized_text: &str, path: &Path) -> bool {
    path.file_stem()
        .and_then(|stem| stem.to_str())
        .is_some_and(|stem| identifier_matches_text(normalized_text, stem))
}

fn identifier_matches_text(normalized_text: &str, identifier: &str) -> bool {
    identifier_phrases(identifier).into_iter().any(|phrase| {
        let normalized_phrase = normalize_text(&phrase);
        identifier_phrase_matches(normalized_text, &normalized_phrase)
    })
}

fn identifier_phrase_matches(normalized_text: &str, phrase: &str) -> bool {
    let words = phrase.split_whitespace().collect::<Vec<_>>();
    match words.as_slice() {
        [] => false,
        [word] if is_common_weak_identifier(word) => false,
        [word] if word.len() < 4 => contains_standalone_token(normalized_text, word),
        _ => contains_phrase(normalized_text, phrase),
    }
}

fn qualified_path_matches(normalized_text: &str, qualified_path: &[String]) -> bool {
    let phrase = qualified_path.join(" ");
    !phrase.trim().is_empty() && contains_phrase(normalized_text, &phrase)
}

fn contains_standalone_token(text: &str, token: &str) -> bool {
    text.split_whitespace().any(|word| word == token)
}

fn is_common_weak_identifier(identifier: &str) -> bool {
    matches!(identifier, "new" | "run" | "status")
}

fn identifier_phrases(identifier: &str) -> Vec<String> {
    let mut phrases = BTreeSet::new();
    let lowered = identifier.trim().to_ascii_lowercase();
    if !lowered.is_empty() {
        phrases.insert(lowered.clone());
        phrases.insert(lowered.replace('_', " "));
        phrases.insert(lowered.replace('-', " "));
    }
    let camel = split_camel_words(identifier);
    if camel.len() > 1 {
        phrases.insert(camel.join(" ").to_ascii_lowercase());
    }
    phrases
        .into_iter()
        .filter(|phrase| !phrase.trim().is_empty())
        .collect()
}

fn split_camel_words(identifier: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut current = String::new();
    for ch in identifier.chars() {
        if ch == '_' || ch == '-' {
            if !current.is_empty() {
                words.push(current.clone());
                current.clear();
            }
            continue;
        }
        if ch.is_ascii_uppercase() && !current.is_empty() {
            words.push(current.clone());
            current.clear();
        }
        current.push(ch);
    }
    if !current.is_empty() {
        words.push(current);
    }
    words
}

fn contains_path_mention(text: &str, path: &str) -> bool {
    text.contains(path)
        || text.contains(&format!("`{path}`"))
        || text.contains(&format!("'{}'", path))
        || text.contains(&format!("\"{path}\""))
}

fn collect_planning_files(
    repo: &Path,
    title: &str,
    body: &str,
    diagnostics: &mut TaskPathProposalDiagnostics,
) -> Result<Vec<PathBuf>> {
    let named_on_disk = named_paths_present_on_disk(repo, &format!("{title}\n{body}"));
    match collect_repo_files(repo) {
        Ok(mut files) => {
            let mut file_set = files.iter().cloned().collect::<BTreeSet<_>>();
            for path in named_on_disk {
                if file_set.insert(path.clone()) {
                    diagnostics.notes.push(format!(
                        "included explicitly named path '{}' that was not in the Git-visible inventory",
                        path.display()
                    ));
                    files.push(path);
                }
            }
            files.sort();
            Ok(files)
        }
        Err(error) => {
            if let Some(path) = unresolved_explicit_named_file(repo, &format!("{title}\n{body}")) {
                anyhow::bail!(
                    "named repository path '{path}' is not a readable regular file in the repository"
                );
            }
            if named_on_disk.is_empty() {
                return Err(error).context(
                    "repository inventory failed and the spec named no resolvable repository paths",
                );
            }
            diagnostics.degraded = true;
            diagnostics.notes.push(format!(
                "repository inventory failed ({error:#}); using {} explicitly named repository path(s)",
                named_on_disk.len()
            ));
            Ok(named_on_disk)
        }
    }
}

fn named_paths_present_on_disk(repo: &Path, text: &str) -> Vec<PathBuf> {
    extract_path_like_tokens(text)
        .into_iter()
        .filter_map(|token| resolve_named_repo_file(repo, Path::new(&token)))
        .collect()
}

fn unresolved_explicit_named_file(repo: &Path, text: &str) -> Option<String> {
    extract_path_like_tokens(text).into_iter().find(|token| {
        let Ok(normalized) = normalize_repo_relative_path(token) else {
            return false;
        };
        normalized.components().count() > 1
            && normalized
                .extension()
                .is_some_and(|extension| !extension.is_empty())
            && !is_excluded_planning_path(&normalized)
            && resolve_named_repo_file(repo, &normalized).is_none()
    })
}

struct NamedPathMatch {
    resolved: BTreeSet<PathBuf>,
    unresolved: Vec<String>,
    notes: Vec<String>,
}

fn match_named_paths_in_text(
    repo: &Path,
    text: &str,
    files: &[PathBuf],
    file_set: &BTreeSet<PathBuf>,
) -> NamedPathMatch {
    let mut resolved = BTreeSet::new();
    let mut unresolved = Vec::new();
    let mut notes = Vec::new();
    for token in extract_path_like_tokens(text) {
        let matches = resolve_path_token(repo, &token, files, file_set, &mut notes);
        if matches.is_empty() {
            unresolved.push(token);
        } else {
            resolved.extend(matches);
        }
    }
    NamedPathMatch {
        resolved,
        unresolved,
        notes,
    }
}

fn resolve_path_token(
    repo: &Path,
    token: &str,
    files: &[PathBuf],
    file_set: &BTreeSet<PathBuf>,
    notes: &mut Vec<String>,
) -> BTreeSet<PathBuf> {
    let Ok(normalized) = normalize_repo_relative_path(token) else {
        return BTreeSet::new();
    };
    if normalized.as_os_str().is_empty() || is_excluded_planning_path(&normalized) {
        return BTreeSet::new();
    }

    let mut resolved = BTreeSet::new();
    if normalized.components().count() == 1 {
        let file_name = normalized.file_name();
        for file in files {
            if file.file_name() == file_name {
                resolved.insert(file.clone());
            }
        }
        if resolved.len() > MAX_NAMED_PATH_EXPANSION {
            notes.push(format!(
                "bare path '{token}' matches {} inventoried files; name a more specific repository-relative path",
                resolved.len()
            ));
            resolved.clear();
        }
        if resolved.is_empty() {
            if let Some(on_disk) = resolve_named_repo_file(repo, &normalized) {
                resolved.insert(on_disk);
            }
        }
        return resolved;
    }

    if file_set.contains(&normalized) {
        resolved.insert(normalized);
        return resolved;
    }
    if !is_overbroad_prefix(&normalized) {
        for file in files {
            if file.starts_with(&normalized) {
                resolved.insert(file.clone());
            }
        }
        if resolved.len() > MAX_NAMED_PATH_EXPANSION {
            notes.push(format!(
                "named path prefix '{token}' matches {} inventoried files; name a more specific repository-relative file",
                resolved.len()
            ));
            resolved.clear();
        }
    }
    if resolved.is_empty() {
        if let Some(on_disk) = resolve_named_repo_file(repo, &normalized) {
            resolved.insert(on_disk);
        }
    }
    resolved
}

fn resolve_named_repo_file(repo: &Path, relative: &Path) -> Option<PathBuf> {
    let normalized = normalize_repo_relative_path(relative).ok()?;
    if normalized.as_os_str().is_empty() || is_excluded_planning_path(&normalized) {
        return None;
    }
    let metadata = fs::symlink_metadata(repo.join(&normalized)).ok()?;
    metadata.is_file().then_some(normalized)
}

fn is_excluded_planning_path(path: &Path) -> bool {
    is_runtime_path(path)
        || path.starts_with(".git")
        || path
            .components()
            .any(|component| component.as_os_str() == ".git")
}

fn is_overbroad_prefix(path: &Path) -> bool {
    if path.components().count() != 1 {
        return false;
    }
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("");
    name.starts_with('.')
        || matches!(
            name,
            "src" | "docs" | "scripts" | "tests" | "test" | "target" | "bin" | "lib"
        )
}

fn extract_path_like_tokens(text: &str) -> Vec<String> {
    let mut tokens = BTreeSet::new();
    let mut current = String::new();
    let mut quote = None;
    for ch in text.chars() {
        match quote {
            Some(q) if ch == q => {
                consider_path_token(&mut tokens, &current);
                current.clear();
                quote = None;
            }
            Some(_) => current.push(ch),
            None if matches!(ch, '`' | '\'' | '"') => {
                consider_path_token(&mut tokens, &current);
                current.clear();
                quote = Some(ch);
            }
            None if ch.is_whitespace() => {
                consider_path_token(&mut tokens, &current);
                current.clear();
            }
            None => current.push(ch),
        }
    }
    consider_path_token(&mut tokens, &current);
    tokens.into_iter().collect()
}

fn consider_path_token(tokens: &mut BTreeSet<String>, raw: &str) {
    if let Some(token) = normalize_path_token(raw) {
        if looks_like_repo_relative_path(&token) {
            tokens.insert(token);
        }
    }
}

fn normalize_path_token(raw: &str) -> Option<String> {
    let trimmed = raw.trim().trim_matches(|c: char| {
        matches!(c, ',' | ';' | ':' | ')' | '(' | '[' | ']' | '{' | '}' | '!')
    });
    if trimmed.is_empty() {
        return None;
    }
    let trimmed = trimmed.strip_prefix("./").unwrap_or(trimmed);
    let trimmed = match trimmed.strip_suffix('.') {
        Some(stripped) if looks_like_repo_relative_path(stripped) => stripped,
        _ => trimmed,
    };
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn looks_like_repo_relative_path(token: &str) -> bool {
    if token.is_empty() || token == "." || token == ".." || token.contains("://") {
        return false;
    }
    let path = Path::new(token);
    if path.is_absolute() {
        return false;
    }
    token.contains('/')
        || token.starts_with('.')
        || path
            .extension()
            .is_some_and(|extension| !extension.is_empty())
}

fn propose_non_rust_identifier_paths(
    normalized_text: &str,
    files: &[PathBuf],
    proposed: &mut BTreeSet<PathBuf>,
) {
    for file in files {
        if is_rust_source_path(file) {
            continue;
        }
        if distinctive_non_rust_path_matches(normalized_text, file) {
            proposed.insert(file.clone());
        }
    }
}

fn distinctive_non_rust_path_matches(normalized_text: &str, path: &Path) -> bool {
    if let Some(stem) = path.file_stem().and_then(|stem| stem.to_str()) {
        if !is_generic_file_stem(stem) && identifier_matches_text(normalized_text, stem) {
            return true;
        }
    }
    path.parent()
        .and_then(|parent| parent.file_name())
        .and_then(|name| name.to_str())
        .is_some_and(|name| {
            !is_generic_dir_name(name) && identifier_matches_text(normalized_text, name)
        })
}

fn is_generic_file_stem(stem: &str) -> bool {
    matches!(
        stem.to_ascii_lowercase().as_str(),
        "skill"
            | "readme"
            | "license"
            | "changelog"
            | "contributing"
            | "makefile"
            | "dockerfile"
            | "index"
            | "config"
            | "script"
            | "test"
            | "spec"
            | "doc"
            | "docs"
            | "mod"
            | "lib"
            | "main"
            | "package"
            | "cargo"
    )
}

fn is_generic_dir_name(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "src"
            | "docs"
            | "scripts"
            | "script"
            | "skills"
            | "skill"
            | "agents"
            | ".agents"
            | ".agent"
            | "bin"
            | "lib"
            | "test"
            | "tests"
            | "spec"
            | "config"
    )
}

fn is_rust_source_path(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("rs"))
}

fn is_markdown_path(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("md"))
}

fn is_conventional_documentation_path(path: &Path) -> bool {
    path.starts_with("docs")
        || path.starts_with(".agents/docs")
        || (path.components().count() == 1 && is_markdown_path(path))
}

fn contains_phrase(text: &str, phrase: &str) -> bool {
    let phrase = normalize_text(phrase);
    text.split_whitespace()
        .collect::<Vec<_>>()
        .windows(phrase.split_whitespace().count())
        .any(|window| window.join(" ") == phrase)
}

fn normalize_text(text: &str) -> String {
    text.chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '_' {
                ch.to_ascii_lowercase()
            } else {
                ' '
            }
        })
        .collect::<String>()
}

fn collect_repo_files(repo: &Path) -> Result<Vec<PathBuf>> {
    let mut deadline = Instant::now()
        .checked_add(repository_inventory_max_duration())
        .context("repository inventory deadline overflowed")?;
    let binding = crate::worktree::RepositoryBindingGuard::bind(repo)?;
    let first = collect_git_inventory_snapshot(&binding, &mut deadline)?;
    let second = collect_git_inventory_snapshot(&binding, &mut deadline)?;
    let stable = if first == second {
        second
    } else {
        let retry = collect_git_inventory_snapshot(&binding, &mut deadline)?;
        if second != retry {
            anyhow::bail!("repository inventory changed across its bounded retry");
        }
        retry
    };
    binding.verify()?;
    remaining_inventory_time(deadline, "after repository inventory")?;
    let visible = stable.0;
    let mut files = stable
        .1
        .into_iter()
        .filter(|entry| {
            entry.kind == BoundedTreeEntryKind::RegularFile
                && visible.contains(&entry.relative_path)
        })
        .map(|entry| entry.relative_path)
        .collect::<Vec<_>>();
    files.sort();
    files.dedup();
    Ok(files)
}

#[cfg(not(test))]
fn repository_inventory_max_duration() -> Duration {
    REPOSITORY_INVENTORY_MAX_DURATION
}

#[cfg(test)]
fn repository_inventory_max_duration() -> Duration {
    REPOSITORY_INVENTORY_DURATION_OVERRIDE
        .with(|override_duration| override_duration.get())
        .unwrap_or(REPOSITORY_INVENTORY_MAX_DURATION)
}

#[cfg(test)]
thread_local! {
    static REPOSITORY_INVENTORY_DURATION_OVERRIDE: std::cell::Cell<Option<Duration>> =
        const { std::cell::Cell::new(None) };
}

fn collect_git_inventory_snapshot(
    binding: &crate::worktree::RepositoryBindingGuard,
    deadline: &mut Instant,
) -> Result<(BTreeSet<PathBuf>, Vec<BoundedTreeEntry>)> {
    let (visible, process_queue_wait) =
        crate::worktree::bounded_repository_visible_paths_bound_with_process_wait(
            binding,
            REPOSITORY_INVENTORY_MAX_ENTRIES,
            REPOSITORY_INVENTORY_MAX_TOTAL_PATH_BYTES,
            remaining_inventory_time(*deadline, "before bounded Git inventory")?,
        )?;
    // The bounded-status layer serializes callers in-process before it starts
    // its own execution deadline. Exclude only that queue wait from the
    // repository inventory deadline so concurrent tests or callers do not
    // consume one another's real inventory budget.
    extend_inventory_deadline(
        deadline,
        process_queue_wait,
        "bounded Git inventory queue wait",
    )?;
    let visible = visible.into_iter().collect::<BTreeSet<_>>();
    let inventory = collect_descriptor_inventory(binding.worktree_binding(), *deadline)?;
    binding.verify()?;
    Ok((visible, inventory))
}

fn extend_inventory_deadline(
    deadline: &mut Instant,
    duration: Duration,
    phase: &str,
) -> Result<()> {
    if duration.is_zero() {
        return Ok(());
    }
    *deadline = deadline.checked_add(duration).with_context(|| {
        format!("repository inventory deadline overflowed while excluding {phase}")
    })?;
    Ok(())
}

fn collect_descriptor_inventory(
    binding: &DirectoryBindingGuard,
    deadline: Instant,
) -> Result<Vec<BoundedTreeEntry>> {
    BoundedTreeWalker::walk_bound_with(
        binding,
        BoundedTreeWalkLimits {
            max_depth: REPOSITORY_INVENTORY_MAX_DEPTH,
            max_entries: REPOSITORY_INVENTORY_MAX_ENTRIES,
            max_path_bytes: REPOSITORY_INVENTORY_MAX_PATH_BYTES,
            max_total_path_bytes: REPOSITORY_INVENTORY_MAX_TOTAL_PATH_BYTES,
            max_duration: remaining_inventory_time(deadline, "before descriptor inventory")?,
            same_device: true,
        },
        |entry| {
            let path = &entry.relative_path;
            if is_runtime_path(path) {
                return Ok(BoundedTreeWalkAction::Skip);
            }
            Ok(match entry.kind {
                BoundedTreeEntryKind::Directory => {
                    let name = path
                        .file_name()
                        .and_then(|name| name.to_str())
                        .unwrap_or("");
                    if should_skip_dir(name) {
                        BoundedTreeWalkAction::Skip
                    } else {
                        BoundedTreeWalkAction::RecordAndDescend
                    }
                }
                BoundedTreeEntryKind::RegularFile if entry.is_safe_regular_file() => {
                    BoundedTreeWalkAction::Record
                }
                BoundedTreeEntryKind::RegularFile
                | BoundedTreeEntryKind::Symlink
                | BoundedTreeEntryKind::Special => BoundedTreeWalkAction::Skip,
            })
        },
    )
}

fn remaining_inventory_time(deadline: Instant, phase: &str) -> Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .with_context(|| format!("repository inventory exceeded its total time limit {phase}"))
}

fn should_skip_dir(name: &str) -> bool {
    matches!(name, ".git" | ".maco" | ".maco-cache" | "target")
}

fn is_runtime_path(path: &Path) -> bool {
    path.starts_with(".maco")
        || path.starts_with(".maco-cache")
        || path.starts_with("target")
        || path.starts_with(".agent/temp")
        || path.starts_with(".agent/storage")
        || path.starts_with(".agents/temp")
        || path.starts_with(".agents/storage")
        || path.starts_with(".agents/live")
}

fn collapse_covered_paths(paths: BTreeSet<PathBuf>) -> Vec<PathBuf> {
    let mut collapsed: Vec<PathBuf> = Vec::new();
    for path in paths {
        if collapsed.iter().any(|existing| path.starts_with(existing)) {
            continue;
        }
        collapsed.retain(|existing| !existing.starts_with(&path));
        collapsed.push(path);
    }
    collapsed
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::llm::FakeProvider;
    use std::fs;

    const CONTENTION_RESILIENT_INVENTORY_DURATION: Duration = Duration::from_secs(600);

    static CONTENTION_RESILIENT_INVENTORY_TEST_LOCK: std::sync::OnceLock<std::sync::Mutex<()>> =
        std::sync::OnceLock::new();

    struct RepositoryInventoryDurationOverride {
        previous: Option<Duration>,
    }

    impl RepositoryInventoryDurationOverride {
        fn set(duration: Duration) -> Self {
            let previous = REPOSITORY_INVENTORY_DURATION_OVERRIDE
                .with(|override_duration| override_duration.replace(Some(duration)));
            Self { previous }
        }
    }

    impl Drop for RepositoryInventoryDurationOverride {
        fn drop(&mut self) {
            REPOSITORY_INVENTORY_DURATION_OVERRIDE
                .with(|override_duration| override_duration.set(self.previous));
        }
    }

    fn run_contention_resilient_inventory_test<R>(test: impl FnOnce() -> R) -> R {
        let lock = CONTENTION_RESILIENT_INVENTORY_TEST_LOCK
            .get_or_init(|| std::sync::Mutex::new(()))
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let _duration_override =
            RepositoryInventoryDurationOverride::set(CONTENTION_RESILIENT_INVENTORY_DURATION);
        let result = test();
        drop(lock);
        result
    }

    #[test]
    fn propose_task_paths_does_not_match_common_symbol_words() {
        skip_without_containment!();
        let temp = tempfile::tempdir().expect("tempdir");
        let repo = temp.path();
        git2::Repository::init(repo).expect("init repo");
        write_file(repo, "src/run.rs", "pub fn run() {}\n");
        write_file(repo, "src/new.rs", "pub fn new() {}\n");
        write_file(repo, "src/status.rs", "pub struct Status;\n");

        let paths = propose_task_paths(
            repo,
            "Run the new status check",
            "The task text uses common workflow words, not specific symbols.",
        )
        .expect("propose paths");

        assert_eq!(paths, Vec::<PathBuf>::new());
    }

    #[test]
    fn propose_task_paths_requires_standalone_short_identifier_tokens() {
        skip_without_containment!();
        let temp = tempfile::tempdir().expect("tempdir");
        let repo = temp.path();
        git2::Repository::init(repo).expect("init repo");
        write_file(repo, "src/api.rs", "pub fn api() {}\n");

        let incidental =
            propose_task_paths(repo, "Repair rapid retry", "").expect("propose incidental paths");
        assert_eq!(incidental, Vec::<PathBuf>::new());

        let explicit =
            propose_task_paths(repo, "Repair api retry", "").expect("propose explicit paths");
        assert_eq!(explicit, vec![PathBuf::from("src/api.rs")]);
    }

    #[test]
    fn propose_task_paths_matches_real_symbol_mentions() {
        skip_without_containment!();
        let temp = tempfile::tempdir().expect("tempdir");
        let repo = temp.path();
        git2::Repository::init(repo).expect("init repo");
        write_file(repo, "src/worktree.rs", "pub struct WorktreeManager;\n");
        write_file(repo, "src/planning.rs", "pub fn propose_task_paths() {}\n");

        let paths = propose_task_paths(
            repo,
            "Update WorktreeManager",
            "Keep propose_task_paths conservative.",
        )
        .expect("propose paths");

        assert_eq!(
            paths,
            vec![
                PathBuf::from("src/planning.rs"),
                PathBuf::from("src/worktree.rs")
            ]
        );
    }

    #[test]
    fn propose_task_paths_routes_docs_and_rust_tasks_separately() {
        skip_without_containment!();
        run_contention_resilient_inventory_test(|| {
            let temp = tempfile::tempdir().expect("tempdir");
            let repo = temp.path();
            git2::Repository::init(repo).expect("init repo");
            write_file(repo, "README.md", "# Project\n");
            write_file(repo, "docs/guide.md", "# Guide\n");
            write_file(repo, "src/worktree.rs", "pub struct WorktreeManager;\n");

            let docs_paths = propose_task_paths(repo, "Update docs", "Refresh documentation.")
                .expect("propose docs paths");
            assert_eq!(
                docs_paths,
                vec![PathBuf::from("README.md"), PathBuf::from("docs/guide.md")]
            );

            let rust_paths =
                propose_task_paths(repo, "Repair WorktreeManager", "").expect("propose rust paths");
            assert_eq!(rust_paths, vec![PathBuf::from("src/worktree.rs")]);
        });
    }

    #[test]
    fn propose_task_path_proposal_keeps_empty_result_without_readme() {
        skip_without_containment!();
        let temp = tempfile::tempdir().expect("tempdir");
        let repo = temp.path();
        git2::Repository::init(repo).expect("init repo");
        write_file(repo, "src/lib.rs", "pub fn unrelated() {}\n");

        let proposal = propose_task_path_proposal(repo, "Unmatched task", "")
            .expect("propose task path proposal");

        assert_eq!(proposal.paths, Vec::<PathBuf>::new());
        assert!(!proposal.diagnostics.degraded);
        assert!(proposal.diagnostics.notes.is_empty());
    }

    #[test]
    fn propose_task_path_proposal_reports_filename_only_degradation() {
        skip_without_containment!();
        run_contention_resilient_inventory_test(|| {
            let temp = tempfile::tempdir().expect("tempdir");
            let repo = temp.path();
            git2::Repository::init(repo).expect("init repo");
            write_file(repo, "src/planning.rs", "pub fn propose_task_paths() {}\n");

            let proposal = propose_task_path_proposal(repo, "Repair planning", "")
                .expect("propose degraded paths");

            assert_eq!(proposal.paths, vec![PathBuf::from("src/planning.rs")]);
            assert!(!proposal.diagnostics.degraded);
            assert!(proposal.diagnostics.notes.is_empty());
        });
    }

    #[test]
    fn collapse_covered_paths_removes_children_of_selected_parent() {
        let paths = [
            PathBuf::from("README.md"),
            PathBuf::from("src"),
            PathBuf::from("src/lib.rs"),
            PathBuf::from("src/planning.rs"),
        ]
        .into_iter()
        .collect::<BTreeSet<_>>();

        assert_eq!(
            collapse_covered_paths(paths),
            vec![PathBuf::from("README.md"), PathBuf::from("src")]
        );
    }

    fn assignment_scope(
        id: &str,
        paths: &[&str],
        symbols: &[&str],
        modules: &[&str],
    ) -> TaskAssignmentProposal {
        TaskAssignmentProposal {
            id: id.to_string(),
            task: id.to_string(),
            fragment_ids: vec![format!("fragment-{id}")],
            assigned_paths: paths.iter().map(PathBuf::from).collect(),
            semantic_symbols: symbols.iter().map(|value| value.to_string()).collect(),
            semantic_modules: modules.iter().map(|value| value.to_string()).collect(),
        }
    }

    fn provider_assignment(
        id: &str,
        task: &str,
        fragment_id: &str,
        path: &str,
    ) -> TaskAssignmentProposal {
        TaskAssignmentProposal {
            id: id.to_string(),
            task: task.to_string(),
            fragment_ids: vec![fragment_id.to_string()],
            assigned_paths: vec![PathBuf::from(path)],
            semantic_symbols: Vec::new(),
            semantic_modules: Vec::new(),
        }
    }

    fn provider_tree_leaf(
        id: &str,
        task: &str,
        fragment_ids: &[&str],
        path: &str,
    ) -> ProviderTaskAssignmentTree {
        ProviderTaskAssignmentTree {
            id: id.to_string(),
            task: task.to_string(),
            fragment_ids: fragment_ids.iter().map(|id| (*id).to_string()).collect(),
            assigned_paths: vec![PathBuf::from(path)],
            semantic_symbols: Vec::new(),
            semantic_modules: Vec::new(),
            child_assignments: Vec::new(),
        }
    }

    #[test]
    fn task_assignment_disjointness_detects_equal_and_hierarchical_paths() {
        let assignments = vec![
            assignment_scope("left", &["src"], &[], &[]),
            assignment_scope("equal", &["src"], &[], &[]),
            assignment_scope("child", &["src/planning.rs"], &[], &[]),
        ];

        let report = task_assignment_disjointness(&assignments).expect("disjointness");

        assert!(!report.disjoint);
        assert_eq!(
            report
                .conflicts
                .iter()
                .filter(|conflict| conflict.kind == TaskScopeConflictKind::PathOverlap)
                .count(),
            3
        );
    }

    #[test]
    fn task_assignment_disjointness_detects_post_normalization_path_collisions() {
        let assignments = vec![
            assignment_scope("left", &["src/../README.md"], &[], &[]),
            assignment_scope("right", &["README.md"], &[], &[]),
        ];

        let report = task_assignment_disjointness(&assignments).expect("disjointness");

        assert!(!report.disjoint);
        assert_eq!(report.conflicts.len(), 1);
        assert_eq!(report.conflicts[0].kind, TaskScopeConflictKind::PathOverlap);
        assert_eq!(report.conflicts[0].left_value, "README.md");
        assert_eq!(report.conflicts[0].right_value, "README.md");
    }

    #[test]
    fn task_assignment_disjointness_detects_semantic_scope_collisions() {
        let assignments = vec![
            assignment_scope(
                "left",
                &[],
                &["crate :: planning :: propose_task_paths"],
                &["planning"],
            ),
            assignment_scope(
                "right",
                &[],
                &["crate::planning::propose_task_paths"],
                &["crate::planning::nested"],
            ),
            assignment_scope("equal-module", &[], &[], &["crate :: planning"]),
        ];

        let report = task_assignment_disjointness(&assignments).expect("disjointness");
        let kinds = report
            .conflicts
            .iter()
            .map(|conflict| conflict.kind)
            .collect::<BTreeSet<_>>();

        assert!(!report.disjoint);
        assert!(kinds.contains(&TaskScopeConflictKind::SymbolOverlap));
        assert!(kinds.contains(&TaskScopeConflictKind::ModuleOverlap));
        assert!(kinds.contains(&TaskScopeConflictKind::ModuleHierarchyOverlap));
        assert!(kinds.contains(&TaskScopeConflictKind::ModuleSymbolOverlap));
    }

    #[test]
    fn task_assignment_disjointness_detects_post_normalization_symbol_collisions() {
        let assignments = vec![
            assignment_scope("relative", &[], &["planning :: propose_task_paths"], &[]),
            assignment_scope(
                "canonical",
                &[],
                &["crate::planning::propose_task_paths"],
                &[],
            ),
        ];

        let report = task_assignment_disjointness(&assignments).expect("disjointness");

        assert!(!report.disjoint);
        assert_eq!(report.conflicts.len(), 1);
        assert_eq!(
            report.conflicts[0].kind,
            TaskScopeConflictKind::SymbolOverlap
        );
        assert_eq!(
            report.conflicts[0].left_value,
            "crate::planning::propose_task_paths"
        );
        assert_eq!(
            report.conflicts[0].right_value,
            "crate::planning::propose_task_paths"
        );
    }

    #[test]
    fn fan_out_width_warning_is_loud_only_for_a_serialized_independent_plan() {
        let warning = fan_out_width_warning(1, 3).expect("width warning");

        assert_eq!(warning.code, "planning_width_pinned_to_one");
        assert_eq!(warning.configured_max_child_assignments, 1);
        assert_eq!(warning.independent_scope_count, 3);
        assert_eq!(
            warning.to_string(),
            "max_child_assignments is pinned to 1 despite 3 independent scopes; this plan serializes work that can fan out"
        );
        assert!(fan_out_width_warning(4, 3).is_none());
        assert!(fan_out_width_warning(1, 1).is_none());
    }

    #[test]
    fn optional_provider_uses_heuristic_fallback_when_unconfigured() {
        skip_without_containment!();
        run_contention_resilient_inventory_test(|| {
            let temp = tempfile::tempdir().expect("tempdir");
            let repo = temp.path();
            git2::Repository::init(repo).expect("init repo");
            write_file(repo, "src/alpha.rs", "pub fn alpha_task() {}\n");
            write_file(repo, "src/beta.rs", "pub fn beta_task() {}\n");
            let config = ProviderPlanningConfig::new("fallback", "unused-model");

            let fallback = propose_task_decomposition_with_optional_provider(
                repo,
                "",
                "- Update alpha_task.\n- Update beta_task.",
                None,
                &config,
            )
            .expect("heuristic fallback");
            let heuristic =
                propose_task_decomposition(repo, "", "- Update alpha_task.\n- Update beta_task.")
                    .expect("heuristic proposal");

            assert_eq!(fallback.source(), TaskPlanningSource::Heuristic);
            assert_eq!(fallback.proposal(), &heuristic);
            assert_eq!(fallback.provider_usage(), Usage::default());
            assert_eq!(fallback.replans_used(), 0);
        });
    }

    #[test]
    fn fake_provider_proposes_a_validated_disjoint_plan() {
        skip_without_containment!();
        run_contention_resilient_inventory_test(|| {
            let temp = tempfile::tempdir().expect("tempdir");
            let repo = temp.path();
            git2::Repository::init(repo).expect("init repo");
            write_file(repo, "src/alpha.rs", "pub fn alpha_task() {}\n");
            write_file(repo, "src/beta.rs", "pub fn beta_task() {}\n");
            let config = ProviderPlanningConfig::new("fake-planning", "planner-model");
            let provider_plan = ProviderTaskPlan {
                assignments: vec![
                    provider_assignment(
                        "provider-alpha",
                        "Update alpha implementation",
                        "fragment-001",
                        "src/alpha.rs",
                    ),
                    provider_assignment(
                        "provider-beta",
                        "Update beta implementation",
                        "fragment-002",
                        "src/beta.rs",
                    ),
                ],
            };
            let mut provider = FakeProvider::new("fake-planner", "planner-model");
            provider
                .push_json_response("fake-planning-proposal", &provider_plan)
                .expect("script provider plan");

            let session = propose_task_decomposition_with_optional_provider(
                repo,
                "",
                "- Update alpha behavior.\n- Update beta behavior.",
                Some(&mut provider),
                &config,
            )
            .expect("provider proposal");

            assert_eq!(session.source(), TaskPlanningSource::Provider);
            assert_eq!(session.provider_id(), Some("fake-planner"));
            assert_eq!(session.model(), Some("planner-model"));
            assert_eq!(session.proposal().assignments, provider_plan.assignments);
            assert!(session.proposal().disjointness.disjoint);
            validate_task_assignment_disjointness(&session.proposal().assignments)
                .expect("same deterministic disjointness authority");
            assert_eq!(provider.calls().len(), 1);
            assert_eq!(
                provider.calls()[0].metadata["planning_operation"],
                "provider task decomposition"
            );
            let rendered_prompt = provider.calls()[0].prompt.render();
            assert!(rendered_prompt.contains("src/alpha.rs"));
            assert!(rendered_prompt.contains("fragment-002"));
            println!(
                "provider_plan_demo assignments={} disjoint={} calls={} tokens={}",
                session.proposal().assignments.len(),
                session.proposal().disjointness.disjoint,
                provider.calls().len(),
                session.provider_usage().total_tokens
            );
        });
    }

    #[test]
    fn provider_plan_rejects_overlapping_assignments() {
        skip_without_containment!();
        run_contention_resilient_inventory_test(|| {
            let temp = tempfile::tempdir().expect("tempdir");
            let repo = temp.path();
            git2::Repository::init(repo).expect("init repo");
            write_file(repo, "src/shared.rs", "pub fn shared() {}\n");
            let config = ProviderPlanningConfig::new("overlap", "planner-model");
            let provider_plan = ProviderTaskPlan {
                assignments: vec![
                    provider_assignment(
                        "left",
                        "Update left behavior",
                        "fragment-001",
                        "src/shared.rs",
                    ),
                    provider_assignment(
                        "right",
                        "Update right behavior",
                        "fragment-002",
                        "src/shared.rs",
                    ),
                ],
            };
            let mut provider = FakeProvider::new("fake-planner", "planner-model");
            provider
                .push_json_response("overlap-proposal", &provider_plan)
                .expect("script provider plan");

            let error = propose_task_decomposition_with_provider(
                repo,
                "",
                "- Update left behavior.\n- Update right behavior.",
                &mut provider,
                &config,
            )
            .expect_err("overlapping provider assignments must fail");

            let message = error.to_string();
            assert!(
                message.contains("failed disjointness validation") || message.contains("overlap"),
                "unexpected overlap error: {message}"
            );
        });
    }

    #[test]
    fn fake_provider_replans_from_feedback_with_a_hard_attempt_limit() {
        skip_without_containment!();
        run_contention_resilient_inventory_test(|| {
            let temp = tempfile::tempdir().expect("tempdir");
            let repo = temp.path();
            git2::Repository::init(repo).expect("init repo");
            write_file(repo, "src/alpha.rs", "pub fn alpha_task() {}\n");
            write_file(repo, "src/beta.rs", "pub fn beta_task() {}\n");
            write_file(repo, "src/gamma.rs", "pub fn gamma_task() {}\n");
            let config = ProviderPlanningConfig::new("feedback", "planner-model");
            let initial = ProviderTaskPlan {
                assignments: vec![
                    provider_assignment("alpha", "Update alpha", "fragment-001", "src/alpha.rs"),
                    provider_assignment("beta", "Update beta", "fragment-002", "src/beta.rs"),
                ],
            };
            let first_replan = ProviderTaskPlan {
                assignments: vec![provider_assignment(
                    "beta-revised",
                    "Move the failing beta work to the discovered implementation",
                    "fragment-002",
                    "src/gamma.rs",
                )],
            };
            let second_replan = ProviderTaskPlan {
                assignments: vec![provider_assignment(
                    "beta-final",
                    "Retry beta with the corrected scope",
                    "fragment-002",
                    "src/beta.rs",
                )],
            };
            let mut provider = FakeProvider::new("fake-planner", "planner-model");
            provider
                .push_json_response("feedback-proposal", &initial)
                .expect("script initial plan")
                .push_json_response("feedback-replan-01", &first_replan)
                .expect("script first re-plan")
                .push_json_response("feedback-replan-02", &second_replan)
                .expect("script second re-plan");
            let mut session = propose_task_decomposition_with_provider(
                repo,
                "",
                "- Update alpha behavior.\n- Update beta behavior.",
                &mut provider,
                &config,
            )
            .expect("initial provider plan");
            let first_feedback = TaskExecutionFeedback {
                completed_assignment_ids: vec!["alpha".to_string()],
                failed_assignment_ids: vec!["beta".to_string()],
                coverage_gap_fragment_ids: vec!["fragment-002".to_string()],
                notes: vec!["execution found the implementation in gamma".to_string()],
            };

            replan_task_decomposition_with_provider(
                repo,
                &mut session,
                &first_feedback,
                &mut provider,
                &config,
            )
            .expect("first feedback re-plan");

            assert_eq!(session.replans_used(), 1);
            assert_eq!(session.proposal().assignments, first_replan.assignments);
            assert!(session.proposal().disjointness.disjoint);
            let first_replan_prompt = provider.calls()[1].prompt.render();
            assert!(first_replan_prompt.contains("execution found the implementation in gamma"));
            assert!(first_replan_prompt.contains("fragment-001"));
            assert!(first_replan_prompt.contains("completed_assignment_ids"));

            let second_feedback = TaskExecutionFeedback {
                failed_assignment_ids: vec!["beta-revised".to_string()],
                notes: vec!["validation still fails".to_string()],
                ..TaskExecutionFeedback::default()
            };
            replan_task_decomposition_with_provider(
                repo,
                &mut session,
                &second_feedback,
                &mut provider,
                &config,
            )
            .expect("second feedback re-plan");
            assert_eq!(session.replans_used(), MAX_PROVIDER_REPLANS);
            assert_eq!(session.proposal().assignments, second_replan.assignments);

            let limit_error = replan_task_decomposition_with_provider(
                repo,
                &mut session,
                &second_feedback,
                &mut provider,
                &config,
            )
            .expect_err("third re-plan must be rejected");
            assert!(limit_error.to_string().contains("limit of 2 attempt"));
            assert_eq!(provider.calls().len(), 3);
            println!(
                "provider_replan_demo replans={} final_paths={:?} calls={} limit={}",
                session.replans_used(),
                session.proposal().assignments[0].assigned_paths,
                provider.calls().len(),
                MAX_PROVIDER_REPLANS
            );
        });
    }

    #[test]
    fn fake_provider_proposes_a_recursive_tree_and_flattens_executable_leaves() {
        skip_without_containment!();
        run_contention_resilient_inventory_test(|| {
            let temp = tempfile::tempdir().expect("tempdir");
            let repo = temp.path();
            git2::Repository::init(repo).expect("init repo");
            write_file(repo, "src/alpha.rs", "pub fn alpha_task() {}\n");
            write_file(repo, "src/beta.rs", "pub fn beta_task() {}\n");
            let config =
                ProviderPlanningConfig::new("recursive", "planner-model").with_max_depth(3);
            let provider_plan = ProviderRecursiveTaskPlan {
                assignments: vec![ProviderTaskAssignmentTree {
                    id: "parent".to_string(),
                    task: "Coordinate alpha and beta".to_string(),
                    fragment_ids: vec!["fragment-001".to_string(), "fragment-002".to_string()],
                    assigned_paths: vec![
                        PathBuf::from("src/alpha.rs"),
                        PathBuf::from("src/beta.rs"),
                    ],
                    semantic_symbols: Vec::new(),
                    semantic_modules: Vec::new(),
                    child_assignments: vec![
                        provider_tree_leaf(
                            "alpha",
                            "Update alpha",
                            &["fragment-001"],
                            "src/alpha.rs",
                        ),
                        provider_tree_leaf("beta", "Update beta", &["fragment-002"], "src/beta.rs"),
                    ],
                }],
            };
            let mut provider = FakeProvider::new("fake-planner", "planner-model");
            provider
                .push_json_response("recursive-proposal", &provider_plan)
                .expect("script recursive plan");

            let session = propose_task_decomposition_with_provider(
                repo,
                "",
                "- Update alpha behavior.\n- Update beta behavior.",
                &mut provider,
                &config,
            )
            .expect("recursive provider proposal");

            assert_eq!(session.source(), TaskPlanningSource::Provider);
            assert_eq!(session.proposal().assignments.len(), 2);
            assert_eq!(session.proposal().assignments[0].id, "alpha");
            assert_eq!(session.proposal().assignments[1].id, "beta");
            assert!(session.proposal().disjointness.disjoint);
            assert_eq!(session.provider_assignment_tree().len(), 1);
            assert_eq!(session.provider_assignment_tree()[0].id, "parent");
            assert_eq!(
                session.provider_assignment_tree()[0]
                    .child_assignments
                    .len(),
                2
            );
        });
    }

    #[test]
    fn recursive_provider_plan_rejects_internal_fragment_union_mismatch() {
        skip_without_containment!();
        run_contention_resilient_inventory_test(|| {
            let temp = tempfile::tempdir().expect("tempdir");
            let repo = temp.path();
            git2::Repository::init(repo).expect("init repo");
            write_file(repo, "src/alpha.rs", "pub fn alpha_task() {}\n");
            write_file(repo, "src/beta.rs", "pub fn beta_task() {}\n");
            let config = ProviderPlanningConfig::new("union-mismatch", "planner-model");
            let provider_plan = ProviderRecursiveTaskPlan {
                assignments: vec![ProviderTaskAssignmentTree {
                    id: "parent".to_string(),
                    task: "Coordinate work".to_string(),
                    fragment_ids: vec!["fragment-001".to_string()],
                    assigned_paths: vec![
                        PathBuf::from("src/alpha.rs"),
                        PathBuf::from("src/beta.rs"),
                    ],
                    semantic_symbols: Vec::new(),
                    semantic_modules: Vec::new(),
                    child_assignments: vec![
                        provider_tree_leaf(
                            "alpha",
                            "Update alpha",
                            &["fragment-001"],
                            "src/alpha.rs",
                        ),
                        provider_tree_leaf("beta", "Update beta", &["fragment-002"], "src/beta.rs"),
                    ],
                }],
            };
            let mut provider = FakeProvider::new("fake-planner", "planner-model");
            provider
                .push_json_response("union-mismatch-proposal", &provider_plan)
                .expect("script mismatched tree");

            let error = propose_task_decomposition_with_provider(
                repo,
                "",
                "- Update alpha behavior.\n- Update beta behavior.",
                &mut provider,
                &config,
            )
            .expect_err("mismatched internal fragments must fail");
            assert!(error
                .to_string()
                .contains("fragment_ids must exactly match its descendant executable leaves"));
        });
    }

    #[test]
    fn recursive_provider_plan_rejects_depth_and_reclaimed_completed_scope() {
        skip_without_containment!();
        run_contention_resilient_inventory_test(|| {
            let temp = tempfile::tempdir().expect("tempdir");
            let repo = temp.path();
            git2::Repository::init(repo).expect("init repo");
            write_file(repo, "src/alpha.rs", "pub fn alpha_task() {}\n");
            write_file(repo, "src/beta.rs", "pub fn beta_task() {}\n");
            let deep_config =
                ProviderPlanningConfig::new("too-deep", "planner-model").with_max_depth(1);
            let deep_plan = ProviderRecursiveTaskPlan {
                assignments: vec![ProviderTaskAssignmentTree {
                    id: "parent".to_string(),
                    task: "Coordinate work".to_string(),
                    fragment_ids: vec!["fragment-001".to_string(), "fragment-002".to_string()],
                    assigned_paths: vec![
                        PathBuf::from("src/alpha.rs"),
                        PathBuf::from("src/beta.rs"),
                    ],
                    semantic_symbols: Vec::new(),
                    semantic_modules: Vec::new(),
                    child_assignments: vec![
                        provider_tree_leaf(
                            "alpha",
                            "Update alpha",
                            &["fragment-001"],
                            "src/alpha.rs",
                        ),
                        provider_tree_leaf("beta", "Update beta", &["fragment-002"], "src/beta.rs"),
                    ],
                }],
            };
            let mut provider = FakeProvider::new("fake-planner", "planner-model");
            provider
                .push_json_response("too-deep-proposal", &deep_plan)
                .expect("script deep tree");
            let deep_error = propose_task_decomposition_with_provider(
                repo,
                "",
                "- Update alpha behavior.\n- Update beta behavior.",
                &mut provider,
                &deep_config,
            )
            .expect_err("depth overflow must fail");
            assert!(deep_error.to_string().contains("max_depth is 1"));

            let config = ProviderPlanningConfig::new("reclaim", "planner-model");
            let initial = ProviderTaskPlan {
                assignments: vec![
                    provider_assignment("alpha", "Update alpha", "fragment-001", "src/alpha.rs"),
                    provider_assignment("beta", "Update beta", "fragment-002", "src/beta.rs"),
                ],
            };
            let reclaim = ProviderTaskPlan {
                assignments: vec![provider_assignment(
                    "beta-revised",
                    "Reuse completed alpha path",
                    "fragment-002",
                    "src/alpha.rs",
                )],
            };
            provider
                .push_json_response("reclaim-proposal", &initial)
                .expect("script initial")
                .push_json_response("reclaim-replan-01", &reclaim)
                .expect("script reclaim");
            let mut session = propose_task_decomposition_with_provider(
                repo,
                "",
                "- Update alpha behavior.\n- Update beta behavior.",
                &mut provider,
                &config,
            )
            .expect("initial provider plan");
            let feedback = TaskExecutionFeedback {
                completed_assignment_ids: vec!["alpha".to_string()],
                failed_assignment_ids: vec!["beta".to_string()],
                coverage_gap_fragment_ids: vec!["fragment-002".to_string()],
                notes: vec!["do not reclaim alpha".to_string()],
            };
            let reclaim_error = replan_task_decomposition_with_provider(
                repo,
                &mut session,
                &feedback,
                &mut provider,
                &config,
            )
            .expect_err("reclaiming completed scope must fail");
            assert!(reclaim_error
                .to_string()
                .contains("reclaims completed scope"));
        });
    }

    #[test]
    fn authoritative_single_file_goal_stays_single_and_has_no_semantic_leakage() {
        skip_without_containment!();
        run_contention_resilient_inventory_test(|| {
            let temp = tempfile::tempdir().expect("tempdir");
            let repo = temp.path();
            git2::Repository::init(repo).expect("init repo");
            write_file(repo, "RELEASE_NOTES.md", "# Releases\n");
            write_file(
                repo,
                "src/lib.rs",
                "pub fn write() {}\npub fn commit() {}\n",
            );

            let title = "Smoke goal — prove a managed-worktree child write";
            let body = r#"## Goal

Add a single new line at the end of `RELEASE_NOTES.md`. Do not change any other file.

## Spec

- Edit only `RELEASE_NOTES.md`.
- Commit the change with message `docs: child write`.

## Acceptance

- `RELEASE_NOTES.md` ends with the new line and is committed."#;
            let first = propose_task_decomposition(repo, title, body)
                .expect("authoritative single-file proposal");
            let second = propose_task_decomposition(repo, title, body)
                .expect("deterministic authoritative single-file proposal");

            assert_eq!(first, second);
            assert_eq!(first.assignments.len(), 1);
            assert_eq!(first.assignments[0].id, "assignment-001");
            assert_eq!(
                first.assignments[0].assigned_paths,
                vec![PathBuf::from("RELEASE_NOTES.md")]
            );
            assert_eq!(
                first.assignments[0].fragment_ids,
                first
                    .fragments
                    .iter()
                    .map(|fragment| fragment.id.clone())
                    .collect::<Vec<_>>()
            );
            assert!(first.assignments[0].semantic_symbols.is_empty());
            assert!(first.assignments[0].semantic_modules.is_empty());
            assert!(first.coverage_gaps.is_empty());
            assert!(first.disjointness.disjoint);
            assert!(first
                .diagnostics
                .notes
                .iter()
                .any(|note| { note.contains("explicit single-file-only directive") }));
        });
    }

    #[test]
    fn one_named_file_without_a_tied_only_directive_uses_normal_decomposition() {
        skip_without_containment!();
        run_contention_resilient_inventory_test(|| {
            let temp = tempfile::tempdir().expect("tempdir");
            let repo = temp.path();
            git2::Repository::init(repo).expect("init repo");
            write_file(repo, "RELEASE_NOTES.md", "# Releases\n");
            write_file(repo, "src/lib.rs", "pub fn write() {}\n");

            let proposal = propose_task_decomposition(
                repo,
                "Update release notes",
                "Add an entry to RELEASE_NOTES.md.\n\nExplain the write behavior.",
            )
            .expect("ordinary heuristic proposal");

            assert!(!proposal
                .diagnostics
                .notes
                .iter()
                .any(|note| { note.contains("explicit single-file-only directive") }));
            assert!(proposal
                .assignments
                .iter()
                .any(|assignment| !assignment.semantic_symbols.is_empty()));
        });
    }

    #[test]
    fn propose_task_decomposition_is_deterministic_and_exposes_coverage_and_intents() {
        skip_without_containment!();
        run_contention_resilient_inventory_test(|| {
            let temp = tempfile::tempdir().expect("tempdir");
            let repo = temp.path();
            git2::Repository::init(repo).expect("init repo");
            write_file(repo, "src/lib.rs", "pub mod planning;\npub mod worktree;\n");
            write_file(repo, "src/planning.rs", "pub fn propose_task_paths() {}\n");
            write_file(repo, "src/worktree.rs", "pub struct WorktreeManager;\n");

            let proposal = propose_task_decomposition(
                repo,
                "Planner goal",
                "- Update propose_task_paths in planning.\n- Repair WorktreeManager.\n- Explain the unmatched frobnicator behavior.",
            )
            .expect("propose decomposition");

            assert_eq!(
                proposal.fragments,
                vec![
                    TaskSpecFragment {
                        id: "fragment-001".to_string(),
                        text: "Planner goal".to_string(),
                    },
                    TaskSpecFragment {
                        id: "fragment-002".to_string(),
                        text: "Update propose_task_paths in planning.".to_string(),
                    },
                    TaskSpecFragment {
                        id: "fragment-003".to_string(),
                        text: "Repair WorktreeManager.".to_string(),
                    },
                    TaskSpecFragment {
                        id: "fragment-004".to_string(),
                        text: "Explain the unmatched frobnicator behavior.".to_string(),
                    },
                ]
            );
            assert_eq!(proposal.assignments.len(), 2);
            assert_eq!(proposal.assignments[0].id, "assignment-001");
            assert_eq!(proposal.assignments[0].fragment_ids, vec!["fragment-002"]);
            assert_eq!(
                proposal.assignments[0].assigned_paths,
                vec![PathBuf::from("src/planning.rs")]
            );
            assert!(proposal.assignments[0]
                .semantic_symbols
                .contains(&"crate::planning::propose_task_paths".to_string()));
            assert!(proposal.assignments[0].semantic_modules.is_empty());
            assert_eq!(proposal.assignments[1].id, "assignment-002");
            assert_eq!(
                proposal.assignments[1].assigned_paths,
                vec![PathBuf::from("src/worktree.rs")]
            );
            assert!(proposal.assignments[1]
                .semantic_symbols
                .contains(&"crate::worktree::WorktreeManager".to_string()));
            assert_eq!(
                proposal
                    .coverage_gaps
                    .iter()
                    .map(|gap| gap.fragment_id.as_str())
                    .collect::<Vec<_>>(),
                vec!["fragment-001", "fragment-004"]
            );
            assert!(proposal.disjointness.disjoint);
            assert!(proposal.disjointness.conflicts.is_empty());
            assert!(proposal.diagnostics.notes.iter().any(|note| {
                note.contains("fragment-002 preferred exact symbol implementation scope")
            }));
        });
    }

    #[test]
    fn exact_symbol_scope_avoids_a_shared_megafile_module_attractor() {
        skip_without_containment!();
        run_contention_resilient_inventory_test(|| {
            let temp = tempfile::tempdir().expect("tempdir");
            let repo = temp.path();
            git2::Repository::init(repo).expect("init repo");
            write_file(repo, "src/lib.rs", "pub mod giant;\n");
            write_file(
                repo,
                "src/giant.rs",
                "pub mod alpha;\npub mod beta;\n// large shared module root\n",
            );
            write_file(repo, "src/giant/alpha.rs", "pub fn alpha_task() {}\n");
            write_file(repo, "src/giant/beta.rs", "pub fn beta_task() {}\n");

            let proposal = propose_task_decomposition(
                repo,
                "",
                "- Update alpha_task in giant alpha.\n- Repair beta_task in giant beta.",
            )
            .expect("propose decomposition");

            assert_eq!(proposal.assignments.len(), 2);
            assert_eq!(
                proposal.assignments[0].assigned_paths,
                vec![PathBuf::from("src/giant/alpha.rs")]
            );
            assert_eq!(
                proposal.assignments[1].assigned_paths,
                vec![PathBuf::from("src/giant/beta.rs")]
            );
            assert!(proposal.assignments.iter().all(|assignment| !assignment
                .assigned_paths
                .contains(&PathBuf::from("src/giant.rs"))));
            assert!(proposal.disjointness.disjoint);
            assert_eq!(
                proposal
                    .diagnostics
                    .notes
                    .iter()
                    .filter(|note| note.contains("preferred exact symbol implementation scope"))
                    .count(),
                2
            );
            println!(
                "megafile_attractor_demo assignments={} paths={:?} disjoint={}",
                proposal.assignments.len(),
                proposal
                    .assignments
                    .iter()
                    .map(|assignment| assignment.assigned_paths.clone())
                    .collect::<Vec<_>>(),
                proposal.disjointness.disjoint
            );
        });
    }

    #[test]
    fn propose_task_decomposition_coalesces_transitive_scope_overlap() {
        skip_without_containment!();
        run_contention_resilient_inventory_test(|| {
            let temp = tempfile::tempdir().expect("tempdir");
            let repo = temp.path();
            git2::Repository::init(repo).expect("init repo");
            write_file(repo, "src/lib.rs", "pub mod planning;\n");
            write_file(
                repo,
                "src/planning.rs",
                "pub fn first_task() {}\npub fn second_task() {}\n",
            );

            let proposal =
                propose_task_decomposition(repo, "", "- Update first_task.\n- Repair second_task.")
                    .expect("propose decomposition");

            assert_eq!(proposal.assignments.len(), 1);
            assert_eq!(
                proposal.assignments[0].fragment_ids,
                vec!["fragment-001", "fragment-002"]
            );
            assert_eq!(
                proposal.assignments[0].assigned_paths,
                vec![PathBuf::from("src/planning.rs")]
            );
            assert_eq!(
                proposal.assignments[0].semantic_symbols,
                vec![
                    "crate::planning::first_task".to_string(),
                    "crate::planning::second_task".to_string(),
                ]
            );
            assert!(proposal.coverage_gaps.is_empty());
            assert!(proposal.disjointness.disjoint);
        });
    }

    #[test]
    fn propose_task_decomposition_matches_policy_and_script_paths() {
        run_contention_resilient_inventory_test(|| {
            let temp = tempfile::tempdir().expect("tempdir");
            let repo = temp.path();
            git2::Repository::init(repo).expect("init repo");
            write_file(
                repo,
                ".agents/skills/agent-orchestration/SKILL.md",
                "# Orchestration\n",
            );
            write_file(repo, ".agents/scripts/o2-autopilot", "#!/bin/sh\n");
            write_file(repo, "docs/guide.md", "# Guide\n");

            let proposal = propose_task_decomposition(
                repo,
                "Coordinate policy and script work.",
                "- Update `.agents/skills/agent-orchestration/SKILL.md`.\n\
                 - Update `.agents/scripts/o2-autopilot`.\n",
            )
            .expect("propose policy/script decomposition");

            let mut scopes = proposal
                .assignments
                .iter()
                .map(|assignment| assignment.assigned_paths.clone())
                .collect::<Vec<_>>();
            scopes.sort();
            assert_eq!(
                scopes,
                vec![
                    vec![PathBuf::from(".agents/scripts/o2-autopilot")],
                    vec![PathBuf::from(".agents/skills/agent-orchestration/SKILL.md")],
                ]
            );
            assert!(proposal.assignments.iter().all(|assignment| {
                assignment.semantic_symbols.is_empty() && assignment.semantic_modules.is_empty()
            }));
        });
    }

    #[test]
    fn propose_task_paths_does_not_sweep_nested_policy_markdown() {
        skip_without_containment!();
        run_contention_resilient_inventory_test(|| {
            let temp = tempfile::tempdir().expect("tempdir");
            let repo = temp.path();
            git2::Repository::init(repo).expect("init repo");
            write_file(repo, "README.md", "# Project\n");
            write_file(repo, "docs/guide.md", "# Guide\n");
            write_file(repo, ".agents/skills/demo/SKILL.md", "# Skill\n");

            let docs_paths = propose_task_paths(repo, "Update docs", "Refresh documentation.")
                .expect("propose docs paths");
            assert_eq!(
                docs_paths,
                vec![PathBuf::from("README.md"), PathBuf::from("docs/guide.md")]
            );
            assert!(!docs_paths
                .iter()
                .any(|path| path.starts_with(".agents/skills")));
        });
    }

    #[test]
    fn propose_task_decomposition_includes_explicit_gitignored_policy_path() {
        run_contention_resilient_inventory_test(|| {
            let temp = tempfile::tempdir().expect("tempdir");
            let repo = temp.path();
            git2::Repository::init(repo).expect("init repo");
            write_file(repo, ".gitignore", ".agents/\n");
            write_file(repo, ".agents/skills/demo/SKILL.md", "# Skill\n");
            write_file(repo, "README.md", "# Project\n");

            let proposal =
                propose_task_decomposition(repo, "", "- Update `.agents/skills/demo/SKILL.md`.")
                    .expect("named gitignored policy path");

            assert_eq!(proposal.assignments.len(), 1);
            assert_eq!(
                proposal.assignments[0].assigned_paths,
                vec![PathBuf::from(".agents/skills/demo/SKILL.md")]
            );
        });
    }

    #[test]
    fn propose_task_decomposition_matches_script_basename() {
        skip_without_containment!();
        run_contention_resilient_inventory_test(|| {
            let temp = tempfile::tempdir().expect("tempdir");
            let repo = temp.path();
            git2::Repository::init(repo).expect("init repo");
            write_file(repo, ".agents/scripts/o2-autopilot", "#!/bin/sh\n");

            let proposal = propose_task_decomposition(repo, "", "- Update o2-autopilot.")
                .expect("script basename");

            assert_eq!(proposal.assignments.len(), 1);
            assert_eq!(
                proposal.assignments[0].assigned_paths,
                vec![PathBuf::from(".agents/scripts/o2-autopilot")]
            );
        });
    }

    #[test]
    fn sentence_period_is_not_a_named_repository_path() {
        assert!(!looks_like_repo_relative_path("frobnicator."));
        assert!(!looks_like_repo_relative_path("frobnicator"));
        assert!(looks_like_repo_relative_path("README.md"));
        assert!(looks_like_repo_relative_path(
            ".agents/scripts/o2-autopilot"
        ));
    }

    #[test]
    fn propose_task_decomposition_names_missing_explicit_path() {
        let temp = tempfile::tempdir().expect("tempdir");
        let repo = temp.path();
        git2::Repository::init(repo).expect("init repo");
        write_file(repo, "README.md", "# Project\n");

        let error =
            propose_task_decomposition(repo, "", "- Update `.agents/skills/missing/SKILL.md`.")
                .expect_err("missing named path");
        let message = format!("{error:#}");
        assert!(
            message.contains(".agents/skills/missing/SKILL.md"),
            "{message}"
        );
        assert!(message.contains("not a readable regular file"), "{message}");
    }

    #[test]
    fn propose_task_decomposition_uses_named_paths_when_inventory_fails() {
        let temp = tempfile::tempdir().expect("tempdir");
        let repo = temp.path();
        git2::Repository::init(repo).expect("init repo");
        write_file(repo, ".agents/skills/demo/SKILL.md", "# Skill\n");
        let _override = RepositoryInventoryDurationOverride::set(Duration::from_nanos(1));

        let proposal =
            propose_task_decomposition(repo, "", "- Update `.agents/skills/demo/SKILL.md`.")
                .expect("named path survives inventory failure");

        assert_eq!(proposal.assignments.len(), 1);
        assert_eq!(
            proposal.assignments[0].assigned_paths,
            vec![PathBuf::from(".agents/skills/demo/SKILL.md")]
        );
    }

    #[test]
    fn collect_repo_files_excludes_local_agent_runtime_state() {
        skip_without_containment!();
        let temp = tempfile::tempdir().expect("tempdir");
        let repo = temp.path();
        git2::Repository::init(repo).expect("init repo");
        fs::create_dir_all(repo.join(".agents/temp")).expect("create agents temp");
        fs::create_dir_all(repo.join(".agents/storage")).expect("create agents storage");
        fs::create_dir_all(repo.join(".agents/live/claims")).expect("create agents live");
        fs::create_dir_all(repo.join(".agents/docs")).expect("create agents docs");
        fs::create_dir_all(repo.join("src")).expect("create src");
        fs::write(repo.join(".agents/temp/scratch.md"), "scratch\n").expect("write temp");
        fs::write(repo.join(".agents/storage/cache.md"), "cache\n").expect("write storage");
        fs::write(repo.join(".agents/live/claims/worker.md"), "# Claim\n").expect("write live");
        fs::write(repo.join(".agents/docs/PROJECT_RULES.md"), "# Rules\n").expect("write docs");
        fs::write(repo.join("src/lib.rs"), "pub fn ok() {}\n").expect("write src");

        let files = collect_repo_files(repo).expect("collect repo files");

        assert!(files.contains(&PathBuf::from(".agents/docs/PROJECT_RULES.md")));
        assert!(files.contains(&PathBuf::from("src/lib.rs")));
        assert!(!files.iter().any(|path| path.starts_with(".agents/temp")));
        assert!(!files.iter().any(|path| path.starts_with(".agents/storage")));
        assert!(!files.iter().any(|path| path.starts_with(".agents/live")));
    }

    #[test]
    fn collect_repo_files_excludes_git_ignored_directory() {
        skip_without_containment!();
        run_contention_resilient_inventory_test(|| {
            let temp = tempfile::tempdir().expect("tempdir");
            let repo = temp.path();
            git2::Repository::init(repo).expect("init repo");
            write_file(repo, ".gitignore", "ignored/\n");
            write_file(repo, "ignored/generated.rs", "pub fn ignored() {}\n");
            write_file(repo, "src/lib.rs", "pub fn kept() {}\n");

            let files = collect_repo_files(repo).expect("collect repo files");

            assert!(files.contains(&PathBuf::from(".gitignore")));
            assert!(files.contains(&PathBuf::from("src/lib.rs")));
            assert!(!files.iter().any(|path| path.starts_with("ignored")));
        });
    }

    #[cfg(unix)]
    #[test]
    fn collect_repo_files_never_follows_links_or_accepts_unsafe_files() {
        skip_without_containment!();
        use std::os::unix::fs::{symlink, FileTypeExt};

        let temp = tempfile::tempdir().expect("tempdir");
        let repo = temp.path().join("repo");
        let outside = temp.path().join("outside");
        fs::create_dir_all(repo.join("src")).expect("repo tree");
        fs::create_dir_all(&outside).expect("outside tree");
        git2::Repository::init(&repo).expect("init repo");
        fs::write(repo.join("README.md"), "# Safe\n").expect("readme");
        fs::write(repo.join("src/lib.rs"), "pub fn ok() {}\n").expect("source");
        fs::write(outside.join("secret.rs"), "pub fn secret() {}\n").expect("secret");
        symlink(&outside, repo.join("outside-link")).expect("outside link");
        fs::hard_link(repo.join("src/lib.rs"), repo.join("hardlink.rs")).expect("hardlink");
        let socket_path = repo.join("socket");
        let _socket = crate::test_support::bind_test_unix_socket(&socket_path).expect("socket");
        assert!(
            fs::symlink_metadata(&socket_path)
                .expect("socket metadata")
                .file_type()
                .is_socket(),
            "fixture socket must remain a socket entry"
        );

        let files = collect_repo_files(&repo).expect("collect files");
        assert_eq!(files, vec![PathBuf::from("README.md")]);
        assert!(!files.contains(&PathBuf::from("socket")));
    }

    #[test]
    fn heuristic_replans_from_feedback_without_a_planner_model() {
        run_contention_resilient_inventory_test(|| {
            let temp = tempfile::tempdir().expect("tempdir");
            let repo = temp.path();
            git2::Repository::init(repo).expect("init repo");
            write_file(repo, "src/alpha.rs", "pub fn alpha_task() {}\n");
            write_file(repo, "src/beta.rs", "pub fn beta_task() {}\n");
            write_file(repo, "src/gamma.rs", "pub fn gamma_task() {}\n");
            let config = ProviderPlanningConfig::new("feedback", "planner-model");
            let mut session = propose_task_decomposition_with_optional_provider(
                repo,
                "",
                "- Update alpha_task in src/alpha.rs.\n- Update beta_task in src/beta.rs.",
                None,
                &config,
            )
            .expect("heuristic session");
            assert_eq!(session.source(), TaskPlanningSource::Heuristic);
            assert_eq!(session.proposal().assignments.len(), 2);
            assert_eq!(
                session.proposal().assignments[0].assigned_paths,
                vec![PathBuf::from("src/alpha.rs")]
            );
            assert_eq!(
                session.proposal().assignments[1].assigned_paths,
                vec![PathBuf::from("src/beta.rs")]
            );

            let first_feedback = TaskExecutionFeedback {
                completed_assignment_ids: vec!["assignment-001".to_string()],
                failed_assignment_ids: vec!["assignment-002".to_string()],
                coverage_gap_fragment_ids: vec!["fragment-002".to_string()],
                notes: vec!["execution found the implementation in src/gamma.rs".to_string()],
            };
            replan_task_decomposition_from_feedback(repo, &mut session, &first_feedback)
                .expect("first feedback re-plan");
            assert_eq!(session.replans_used(), 1);
            assert_eq!(session.source(), TaskPlanningSource::Heuristic);
            assert_eq!(session.completed_fragment_ids().len(), 1);
            assert_eq!(session.completed_assignments().len(), 1);
            assert_eq!(
                session.completed_assignments()[0].assigned_paths,
                vec![PathBuf::from("src/alpha.rs")]
            );
            assert_eq!(session.proposal().assignments.len(), 1);
            assert_eq!(
                session.proposal().assignments[0].id,
                "assignment-replan-01-001"
            );
            assert!(
                session.proposal().assignments[0]
                    .assigned_paths
                    .contains(&PathBuf::from("src/gamma.rs")),
                "remaining work should pick up the feedback path: {:?}",
                session.proposal().assignments[0].assigned_paths
            );
            assert!(
                !session.proposal().assignments[0]
                    .assigned_paths
                    .contains(&PathBuf::from("src/alpha.rs")),
                "remaining work must not reclaim completed alpha"
            );
            assert!(session
                .proposal()
                .diagnostics
                .notes
                .iter()
                .any(|note| note.contains("without a planner model")));

            let second_feedback = TaskExecutionFeedback {
                failed_assignment_ids: vec!["assignment-replan-01-001".to_string()],
                notes: vec!["retry remaining work in src/gamma.rs".to_string()],
                ..TaskExecutionFeedback::default()
            };
            replan_task_decomposition_from_feedback(repo, &mut session, &second_feedback)
                .expect("second feedback re-plan");
            assert_eq!(session.replans_used(), MAX_PROVIDER_REPLANS);
            assert_eq!(
                session.proposal().assignments[0].id,
                "assignment-replan-02-001"
            );

            let limit_error =
                replan_task_decomposition_from_feedback(repo, &mut session, &second_feedback)
                    .expect_err("third re-plan must be rejected");
            assert!(limit_error.to_string().contains("limit of 2 attempt"));
        });
    }

    #[test]
    fn heuristic_replan_rejects_completed_scope_reclaim_and_provider_sessions() {
        // Heuristic rematch already refuses completed-scope reclaim. Inventory
        // and provider-session setup still use isolated git.
        skip_without_containment!();
        run_contention_resilient_inventory_test(|| {
            let temp = tempfile::tempdir().expect("tempdir");
            let repo = temp.path();
            git2::Repository::init(repo).expect("init repo");
            write_file(repo, "src/alpha.rs", "pub fn alpha_task() {}\n");
            write_file(repo, "src/beta.rs", "pub fn beta_task() {}\n");
            let config = ProviderPlanningConfig::new("reclaim", "planner-model");
            let mut session = propose_task_decomposition_with_optional_provider(
                repo,
                "",
                "- Update alpha_task in src/alpha.rs.\n- Update beta_task in src/beta.rs.",
                None,
                &config,
            )
            .expect("heuristic session");
            let reclaim_error = replan_task_decomposition_from_feedback(
                repo,
                &mut session,
                &TaskExecutionFeedback {
                    completed_assignment_ids: vec!["assignment-001".to_string()],
                    failed_assignment_ids: vec!["assignment-002".to_string()],
                    coverage_gap_fragment_ids: vec!["fragment-002".to_string()],
                    notes: vec!["keep using src/alpha.rs".to_string()],
                },
            )
            .expect_err("reclaiming completed scope must fail");
            assert!(reclaim_error
                .to_string()
                .contains("reclaims completed scope"));

            let empty_error = replan_task_decomposition_from_feedback(
                repo,
                &mut session,
                &TaskExecutionFeedback::default(),
            )
            .expect_err("empty feedback must fail");
            assert!(empty_error
                .to_string()
                .contains("re-planning requires at least one execution feedback item"));

            let provider_plan = ProviderTaskPlan {
                assignments: vec![
                    provider_assignment("alpha", "Update alpha", "fragment-001", "src/alpha.rs"),
                    provider_assignment("beta", "Update beta", "fragment-002", "src/beta.rs"),
                ],
            };
            let mut provider = FakeProvider::new("fake-planner", "planner-model");
            provider
                .push_json_response("reclaim-proposal", &provider_plan)
                .expect("script provider plan");
            let mut provider_session = propose_task_decomposition_with_provider(
                repo,
                "",
                "- Update alpha behavior.\n- Update beta behavior.",
                &mut provider,
                &config,
            )
            .expect("provider session");
            let provider_error = replan_task_decomposition_from_feedback(
                repo,
                &mut provider_session,
                &TaskExecutionFeedback {
                    failed_assignment_ids: vec!["beta".to_string()],
                    notes: vec!["use heuristic rematch".to_string()],
                    ..TaskExecutionFeedback::default()
                },
            )
            .expect_err("provider sessions must use the provider re-plan path");
            assert!(provider_error
                .to_string()
                .contains("requires a heuristic planning session"));
        });
    }

    fn write_file(repo: &Path, relative: &str, contents: &str) {
        let path = repo.join(relative);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("create parent directory");
        }
        fs::write(path, contents).expect("write file");
    }
}
