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
    fmt,
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
const TASK_PROPOSAL_MAX_SCOPE_ITEM_BYTES: usize = 4096;
const TASK_PROPOSAL_MAX_TOTAL_SCOPE_BYTES: usize = 16 * 1024 * 1024;
const TASK_PROPOSAL_MAX_REPORTED_CONFLICTS: usize = 4096;
const PROVIDER_PLANNING_MAX_FEEDBACK_ITEMS: usize = 128;
const PROVIDER_PLANNING_MAX_FEEDBACK_ITEM_BYTES: usize = 16 * 1024;
const PROVIDER_PLANNING_MAX_TOTAL_FEEDBACK_BYTES: usize = 256 * 1024;
const DEFAULT_PROVIDER_MAX_CHILD_ASSIGNMENTS: usize = 8;
const DEFAULT_PROVIDER_MAX_DEPTH: usize = 4;
const PROVIDER_PLANNING_MAX_AGENT_ID_BYTES: usize = 256;
// Provider roots lower at supervisor depth 2, so provider depth 31 is the
// greatest value representable by the supervisor's depth-32 plan schema.
const PROVIDER_PLANNING_MAX_DEPTH: usize = 31;
const PROVIDER_WORKER_ID_SUFFIX: &str = "-worker";
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
#[serde(deny_unknown_fields)]
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
    session_id: String,
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
    /// Opaque provider-session authority retained across bounded re-plans and
    /// clones. Provider sessions receive a unique value; heuristic sessions
    /// leave it empty because they cannot be bound to provider execution.
    pub(crate) fn session_id(&self) -> &str {
        &self.session_id
    }

    #[cfg(test)]
    pub(crate) fn reissue_provider_authority_for_test(
        &self,
        provider_id: &str,
        model: &str,
    ) -> Result<Self> {
        let mut reissued = self.clone();
        reissued.session_id = crate::artifacts::state_auth::random_identifier()
            .context("failed to reissue test planning-session authority")?;
        reissued.provider_id = Some(provider_id.to_string());
        reissued.model = Some(model.to_string());
        Ok(reissued)
    }

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

    /// Stable execution authority for the last deterministically validated
    /// provider plan. Attempt counters and cumulative usage are deliberately
    /// excluded: a failed transactional proposal consumes an attempt without
    /// changing the plan that an already-authenticated run executed.
    pub(crate) fn execution_binding_authority_state(&self) -> serde_json::Value {
        serde_json::json!({
            "session_id": self.session_id,
            "proposal": self.proposal,
            "source": self.source,
            "provider_id": self.provider_id,
            "model": self.model,
            "completed_fragment_ids": self.completed_fragment_ids,
            "completed_assignments": self.completed_assignments,
            "provider_assignment_tree": self.provider_assignment_tree,
        })
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
    let files = collect_repo_files(repo)?;
    let file_set = files.iter().cloned().collect::<BTreeSet<_>>();
    let mut diagnostics = TaskPathProposalDiagnostics::default();
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
    for fragment in &fragments {
        let proposed = propose_fragment_scope(fragment, &files, &file_set, semantic_map.as_ref());
        let candidate = proposed.assignment;
        if proposed.suppressed_broad_paths > 0 {
            diagnostics.notes.push(format!(
                "{} preferred exact symbol implementation scope and suppressed {} broader module/declaration path match(es)",
                fragment.id, proposed.suppressed_broad_paths
            ));
        }
        if candidate.assigned_paths.is_empty()
            && candidate.semantic_symbols.is_empty()
            && candidate.semantic_modules.is_empty()
        {
            coverage_gaps.push(TaskCoverageGap {
                fragment_id: fragment.id.clone(),
                kind: TaskCoverageGapKind::UnmatchedScope,
                message: "no bounded repository path or Rust semantic intent matched this fragment"
                    .to_string(),
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

    Ok(TaskDecompositionProposal {
        fragments,
        assignments,
        coverage_gaps,
        diagnostics,
        disjointness,
    })
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
            session_id: String::new(),
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
    let semantic_inventory = collect_provider_semantic_inventory(repo);
    let allowed_fragment_ids = fragments
        .iter()
        .map(|fragment| fragment.id.clone())
        .collect::<BTreeSet<_>>();
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
            "Every internal node's fragment ids, paths, semantic modules, and semantic symbols must exactly equal the unions of all descendant executable leaves.",
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
    let (mut proposal, provider_assignment_tree) =
        validated_provider_proposal(ProviderProposalValidationInput {
            fragments,
            provider_plan,
            allowed_fragment_ids: &allowed_fragment_ids,
            files: &files,
            semantic_inventory: &semantic_inventory,
            completed_assignments: &[],
            config,
            operation: "provider task decomposition",
        })?;
    append_provider_diagnostics(&mut proposal.diagnostics, &response, "initial proposal");

    Ok(TaskPlanningSession {
        session_id: crate::artifacts::state_auth::random_identifier()
            .context("failed to create provider task-planning session authority")?,
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

#[cfg(test)]
pub(crate) struct ValidatedProviderSessionTestInput<'a> {
    pub(crate) fragments: Vec<TaskSpecFragment>,
    pub(crate) provider_plan: ProviderRecursiveTaskPlan,
    pub(crate) repository_paths: Vec<PathBuf>,
    pub(crate) semantic_modules: BTreeSet<String>,
    pub(crate) semantic_symbols: BTreeSet<String>,
    pub(crate) provider_id: &'a str,
    pub(crate) model: &'a str,
    pub(crate) config: &'a ProviderPlanningConfig,
}

#[cfg(test)]
pub(crate) fn validated_provider_session_for_test(
    input: ValidatedProviderSessionTestInput<'_>,
) -> Result<TaskPlanningSession> {
    let ValidatedProviderSessionTestInput {
        fragments,
        provider_plan,
        repository_paths,
        semantic_modules,
        semantic_symbols,
        provider_id,
        model,
        config,
    } = input;
    validate_provider_planning_config(config)?;
    if provider_id.is_empty() || model.is_empty() || model != config.model.trim() {
        anyhow::bail!("test provider planning authority is invalid");
    }
    let allowed_fragment_ids = fragments
        .iter()
        .map(|fragment| fragment.id.clone())
        .collect::<BTreeSet<_>>();
    let (proposal, provider_assignment_tree) =
        validated_provider_proposal(ProviderProposalValidationInput {
            fragments,
            provider_plan,
            allowed_fragment_ids: &allowed_fragment_ids,
            files: &repository_paths,
            semantic_inventory: &ProviderSemanticInventory {
                modules: semantic_modules,
                symbols: semantic_symbols,
            },
            completed_assignments: &[],
            config,
            operation: "validated test provider task decomposition",
        })?;
    Ok(TaskPlanningSession {
        session_id: crate::artifacts::state_auth::random_identifier()
            .context("failed to create test provider planning-session authority")?,
        proposal,
        source: TaskPlanningSource::Provider,
        provider_id: Some(provider_id.to_string()),
        model: Some(model.to_string()),
        provider_usage: Usage::default(),
        replans_used: 0,
        completed_fragment_ids: BTreeSet::new(),
        completed_assignments: Vec::new(),
        provider_assignment_tree,
    })
}

pub(crate) fn replan_task_decomposition_with_provider<P: LlmProvider + ?Sized>(
    repo: &Path,
    session: &mut TaskPlanningSession,
    feedback: &TaskExecutionFeedback,
    provider: &mut P,
    config: &ProviderPlanningConfig,
) -> Result<()> {
    validate_provider_planning_config(config)?;
    if session.source != TaskPlanningSource::Provider || session.provider_assignment_tree.is_empty()
    {
        anyhow::bail!("provider re-planning requires a validated provider planning session");
    }
    if session.provider_id.as_deref() != Some(provider.provider_id()) {
        anyhow::bail!(
            "provider re-planning provider '{}' does not match the planning session provider",
            provider.provider_id()
        );
    }
    if session.model.as_deref() != Some(config.model.trim()) {
        anyhow::bail!(
            "provider re-planning model '{}' does not match the planning session model",
            config.model.trim()
        );
    }
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
            "Every internal node's fragment ids, paths, semantic modules, and semantic symbols must exactly equal the unions of all descendant executable leaves.",
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
    let (mut proposal, provider_assignment_tree) =
        validated_provider_proposal(ProviderProposalValidationInput {
            fragments: session.proposal.fragments.clone(),
            provider_plan,
            allowed_fragment_ids: &allowed_fragment_ids,
            files: &files,
            semantic_inventory: &semantic_inventory,
            completed_assignments: &next_completed_assignments,
            config,
            operation: "provider task re-planning",
        })?;
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
    if config.max_depth == 0 || config.max_depth > PROVIDER_PLANNING_MAX_DEPTH {
        anyhow::bail!(
            "provider planning max_depth must be between 1 and {PROVIDER_PLANNING_MAX_DEPTH}"
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
    let input_chars = prompt.render().len();
    if input_chars > budget.max_input_chars {
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
    if response.provider_id != provider.provider_id() {
        anyhow::bail!(
            "{operation} response provider id '{}' does not match bound provider '{}'",
            response.provider_id,
            provider.provider_id()
        );
    }
    if response.model != config.model.trim() {
        anyhow::bail!(
            "{operation} response model '{}' does not match bound model '{}'",
            response.model,
            config.model.trim()
        );
    }
    let output_chars = response.proposal.rendered_len();
    if output_chars > budget.max_output_chars {
        anyhow::bail!(
            "{operation} response exceeds its {} character provider boundary",
            budget.max_output_chars
        );
    }
    let centrally_estimated_usage = Usage::from_char_counts(input_chars, output_chars);
    if centrally_estimated_usage.total_tokens > budget.max_total_tokens {
        anyhow::bail!(
            "{operation} response exceeds its {} token provider boundary",
            budget.max_total_tokens
        );
    }
    let reported_total_tokens = response
        .usage
        .input_tokens
        .checked_add(response.usage.output_tokens)
        .context("provider planning reported usage overflowed")?;
    if response.usage.total_tokens != reported_total_tokens {
        anyhow::bail!("{operation} response reported internally inconsistent token usage");
    }
    if response.usage.total_tokens > budget.max_total_tokens {
        anyhow::bail!(
            "{operation} response reported {} tokens above its {} token provider boundary",
            response.usage.total_tokens,
            budget.max_total_tokens
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
    serde_json::from_str(&response.proposal.summary).with_context(|| {
        format!("{operation} response summary is not a recursive provider task-plan JSON object")
    })
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
    runtime_ids: BTreeSet<String>,
    leaf_fragment_ids: BTreeSet<String>,
    leaf_assignments: Vec<TaskAssignmentProposal>,
    scoped_nodes: Vec<(Vec<usize>, TaskAssignmentProposal)>,
    total_nodes: usize,
    total_scope_items: usize,
    total_scope_bytes: usize,
    total_task_bytes: usize,
}

impl ProviderTreeValidationState {
    fn new() -> Self {
        Self {
            ids: BTreeSet::new(),
            runtime_ids: BTreeSet::new(),
            leaf_fragment_ids: BTreeSet::new(),
            leaf_assignments: Vec::new(),
            scoped_nodes: Vec::new(),
            total_nodes: 0,
            total_scope_items: 0,
            total_scope_bytes: 0,
            total_task_bytes: 0,
        }
    }
}

#[derive(Default)]
struct ProviderDescendantScope {
    fragment_ids: BTreeSet<String>,
    assigned_paths: BTreeSet<PathBuf>,
    semantic_symbols: BTreeSet<String>,
    semantic_modules: BTreeSet<String>,
}

impl ProviderDescendantScope {
    fn extend(&mut self, other: Self) {
        self.fragment_ids.extend(other.fragment_ids);
        self.assigned_paths.extend(other.assigned_paths);
        self.semantic_symbols.extend(other.semantic_symbols);
        self.semantic_modules.extend(other.semantic_modules);
    }
}

struct ProviderProposalValidationInput<'a> {
    fragments: Vec<TaskSpecFragment>,
    provider_plan: ProviderRecursiveTaskPlan,
    allowed_fragment_ids: &'a BTreeSet<String>,
    files: &'a [PathBuf],
    semantic_inventory: &'a ProviderSemanticInventory,
    completed_assignments: &'a [TaskAssignmentProposal],
    config: &'a ProviderPlanningConfig,
    operation: &'a str,
}

fn validated_provider_proposal(
    input: ProviderProposalValidationInput<'_>,
) -> Result<(TaskDecompositionProposal, Vec<ProviderTaskAssignmentTree>)> {
    let ProviderProposalValidationInput {
        fragments,
        provider_plan,
        allowed_fragment_ids,
        files,
        semantic_inventory,
        completed_assignments,
        config,
        operation,
    } = input;
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
    for completed in completed_assignments {
        let completed_id = normalize_provider_agent_id(&completed.id, operation)?;
        state.ids.insert(completed_id.clone());
        state.runtime_ids.insert(completed_id.clone());
        state
            .runtime_ids
            .insert(format!("{completed_id}{PROVIDER_WORKER_ID_SUFFIX}"));
    }
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
) -> Result<(ProviderTaskAssignmentTree, ProviderDescendantScope)> {
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

    let id = normalize_provider_agent_id(&node.id, operation)?;
    if !state.ids.insert(id.clone()) {
        anyhow::bail!("{operation} repeats assignment id '{id}'");
    }
    if !state.runtime_ids.insert(id.clone()) {
        anyhow::bail!("{operation} assignment id '{id}' collides with a generated runtime id");
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
    let raw_scope_items = node
        .assigned_paths
        .len()
        .checked_add(node.semantic_symbols.len())
        .and_then(|count| count.checked_add(node.semantic_modules.len()))
        .context("provider planning scope item count overflowed")?;
    if raw_scope_items > TASK_PROPOSAL_MAX_SCOPE_ITEMS_PER_ASSIGNMENT {
        anyhow::bail!(
            "{operation} assignment '{id}' contains {raw_scope_items} scope items but at most {TASK_PROPOSAL_MAX_SCOPE_ITEMS_PER_ASSIGNMENT} are allowed"
        );
    }
    state.total_scope_items = state
        .total_scope_items
        .checked_add(raw_scope_items)
        .context("provider planning total scope item count overflowed")?;
    if state.total_scope_items > TASK_PROPOSAL_MAX_TOTAL_SCOPE_ITEMS {
        anyhow::bail!(
            "{operation} contains more than {TASK_PROPOSAL_MAX_TOTAL_SCOPE_ITEMS} total scope items"
        );
    }
    let raw_scope_bytes = node
        .assigned_paths
        .iter()
        .map(|path| path.as_os_str().as_encoded_bytes().len())
        .chain(node.semantic_symbols.iter().map(String::len))
        .chain(node.semantic_modules.iter().map(String::len))
        .try_fold(0usize, |total, bytes| {
            if bytes > TASK_PROPOSAL_MAX_SCOPE_ITEM_BYTES {
                anyhow::bail!(
                    "{operation} assignment '{id}' contains a scope item larger than {TASK_PROPOSAL_MAX_SCOPE_ITEM_BYTES} bytes"
                );
            }
            total
                .checked_add(bytes)
                .context("provider planning scope byte count overflowed")
        })?;
    state.total_scope_bytes = state
        .total_scope_bytes
        .checked_add(raw_scope_bytes)
        .context("provider planning total scope byte count overflowed")?;
    if state.total_scope_bytes > TASK_PROPOSAL_MAX_TOTAL_SCOPE_BYTES {
        anyhow::bail!(
            "{operation} contains more than {TASK_PROPOSAL_MAX_TOTAL_SCOPE_BYTES} total scope bytes"
        );
    }

    let mut assigned_paths = BTreeSet::new();
    for path in &node.assigned_paths {
        let normalized = normalize_repo_relative_path(path)
            .with_context(|| format!("{operation} assignment '{id}' has an invalid path"))?;
        if &normalized != path {
            anyhow::bail!(
                "{operation} assignment '{id}' path '{}' is not a canonical inventoried path",
                path.display()
            );
        }
        if !assigned_paths.insert(normalized) {
            anyhow::bail!("{operation} assignment '{id}' repeats an assigned path");
        }
    }
    if assigned_paths.is_empty() {
        anyhow::bail!("{operation} assignment '{id}' must own at least one repository file");
    }
    if let Some(unknown) = assigned_paths.iter().find(|path| !file_set.contains(*path)) {
        anyhow::bail!(
            "{operation} assignment '{id}' references repository path '{}' that is not an inventoried file",
            unknown.display()
        );
    }
    let semantic_symbols =
        normalize_provider_semantic_values(&node.semantic_symbols, "symbol", &id, operation)?;
    if let Some(unknown) = semantic_symbols
        .iter()
        .find(|symbol| !semantic_inventory.symbols.contains(*symbol))
    {
        anyhow::bail!(
            "{operation} assignment '{id}' references unknown semantic symbol '{unknown}'"
        );
    }
    let semantic_modules =
        normalize_provider_semantic_values(&node.semantic_modules, "module", &id, operation)?;
    if let Some(unknown) = semantic_modules
        .iter()
        .find(|module| !semantic_inventory.modules.contains(*module))
    {
        anyhow::bail!(
            "{operation} assignment '{id}' references unknown semantic module '{unknown}'"
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
    let descendant_scope = if is_leaf {
        let worker_id = format!("{id}{PROVIDER_WORKER_ID_SUFFIX}");
        if worker_id.len() > PROVIDER_PLANNING_MAX_AGENT_ID_BYTES {
            anyhow::bail!(
                "{operation} assignment '{id}' generates a worker id longer than {PROVIDER_PLANNING_MAX_AGENT_ID_BYTES} bytes"
            );
        }
        if !state.runtime_ids.insert(worker_id.clone()) {
            anyhow::bail!(
                "{operation} assignment '{id}' generates colliding worker id '{worker_id}'"
            );
        }
        for fragment_id in &fragment_ids {
            if !state.leaf_fragment_ids.insert(fragment_id.clone()) {
                anyhow::bail!(
                    "{operation} maps fragment '{fragment_id}' to more than one executable leaf"
                );
            }
        }
        state.leaf_assignments.push(assignment.clone());
        ProviderDescendantScope {
            fragment_ids: fragment_ids.clone(),
            assigned_paths: assignment.assigned_paths.iter().cloned().collect(),
            semantic_symbols: assignment.semantic_symbols.iter().cloned().collect(),
            semantic_modules: assignment.semantic_modules.iter().cloned().collect(),
        }
    } else {
        let mut descendants = ProviderDescendantScope::default();
        for (child_index, child) in node.child_assignments.into_iter().enumerate() {
            let mut child_lineage = lineage.clone();
            child_lineage.push(child_index);
            let (normalized_child, child_scope) = normalize_provider_assignment_tree(
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
            descendants.extend(child_scope);
            normalized_children.push(normalized_child);
        }
        if fragment_ids != descendants.fragment_ids {
            anyhow::bail!(
                "{operation} internal assignment '{id}' fragment_ids must exactly match its descendant executable leaves"
            );
        }
        let node_paths = assignment
            .assigned_paths
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        let node_symbols = assignment
            .semantic_symbols
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        let node_modules = assignment
            .semantic_modules
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        if node_paths != descendants.assigned_paths
            || node_symbols != descendants.semantic_symbols
            || node_modules != descendants.semantic_modules
        {
            anyhow::bail!(
                "{operation} internal assignment '{id}' path, symbol, and module scopes must exactly match the unions of all descendant executable leaves"
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
        descendant_scope,
    ))
}

fn normalize_provider_agent_id(value: &str, operation: &str) -> Result<String> {
    let value = value.trim();
    if value.is_empty() {
        anyhow::bail!("{operation} assignment id cannot be empty");
    }
    if value.len() > PROVIDER_PLANNING_MAX_AGENT_ID_BYTES {
        anyhow::bail!(
            "{operation} assignment id exceeds {PROVIDER_PLANNING_MAX_AGENT_ID_BYTES} bytes"
        );
    }
    if matches!(value, "." | "..")
        || !value.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.')
        })
    {
        anyhow::bail!("{operation} assignment id '{value}' is not a supervisor-safe agent id");
    }
    Ok(value.to_string())
}

fn normalize_provider_semantic_values(
    values: &[String],
    kind: &str,
    assignment_id: &str,
    operation: &str,
) -> Result<Vec<String>> {
    let mut normalized_values = BTreeSet::new();
    for value in values {
        let normalized = normalize_semantic_value(value)?;
        if value.trim() != normalized {
            anyhow::bail!(
                "{operation} assignment '{assignment_id}' semantic {kind} '{value}' is not canonical"
            );
        }
        if !normalized_values.insert(normalized) {
            anyhow::bail!("{operation} assignment '{assignment_id}' repeats a semantic {kind}");
        }
    }
    Ok(normalized_values.into_iter().collect())
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
        anyhow::bail!("provider re-planning requires at least one execution feedback item");
    }
    if item_count > PROVIDER_PLANNING_MAX_FEEDBACK_ITEMS {
        anyhow::bail!(
            "execution feedback contains {item_count} items but at most {PROVIDER_PLANNING_MAX_FEEDBACK_ITEMS} are allowed"
        );
    }
    let raw_items = feedback
        .completed_assignment_ids
        .iter()
        .chain(&feedback.failed_assignment_ids)
        .chain(&feedback.coverage_gap_fragment_ids)
        .chain(&feedback.notes);
    let mut total_bytes = 0usize;
    for item in raw_items {
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
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    if completed_assignment_ids.is_empty()
        && failed_assignment_ids.is_empty()
        && coverage_gap_fragment_ids.is_empty()
        && notes.is_empty()
    {
        anyhow::bail!("provider re-planning requires non-empty normalized execution feedback");
    }
    Ok(NormalizedTaskExecutionFeedback {
        completed_assignment_ids,
        failed_assignment_ids,
        coverage_gap_fragment_ids,
        notes,
    })
}

pub(crate) fn validate_and_normalize_execution_feedback_for_session(
    session: &TaskPlanningSession,
    feedback: &TaskExecutionFeedback,
) -> Result<TaskExecutionFeedback> {
    let normalized =
        normalize_execution_feedback(feedback, &session.proposal, &session.completed_fragment_ids)?;
    Ok(TaskExecutionFeedback {
        completed_assignment_ids: normalized.completed_assignment_ids.into_iter().collect(),
        failed_assignment_ids: normalized.failed_assignment_ids.into_iter().collect(),
        coverage_gap_fragment_ids: normalized.coverage_gap_fragment_ids.into_iter().collect(),
        notes: normalized.notes,
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
        normalized.insert(value.to_string());
    }
    Ok(normalized)
}

fn propose_fragment_scope(
    fragment: &TaskSpecFragment,
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

    for file in files {
        let display = file.to_string_lossy().to_ascii_lowercase();
        if contains_path_mention(&lowered, &display) {
            explicit_paths.insert(file.clone());
        }
    }
    propose_docs_paths(&normalized_text, file_set, &mut explicit_paths);

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
    }
}

struct ProposedFragmentScope {
    assignment: TaskAssignmentProposal,
    suppressed_broad_paths: usize,
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
    let files = collect_repo_files(repo)?;
    let file_set = files.iter().cloned().collect::<BTreeSet<_>>();
    let mut proposed = BTreeSet::new();
    let mut diagnostics = TaskPathProposalDiagnostics::default();

    for file in &files {
        let display = file.to_string_lossy().to_ascii_lowercase();
        if contains_path_mention(&lowered, &display) {
            proposed.insert(file.clone());
        }
    }

    propose_docs_paths(&normalized_text, &file_set, &mut proposed);
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
            .filter(|path| {
                path.starts_with("docs")
                    || path
                        .extension()
                        .and_then(|extension| extension.to_str())
                        .is_some_and(|extension| extension.eq_ignore_ascii_case("md"))
            })
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
    use crate::llm::{
        provider::CommandPurpose, FakeBudgetBehavior, FakeProvider, ProposedCommand, ProposedPatch,
        ProviderCapabilities, ProviderError, WorkProposal,
    };
    use std::fs;

    const CONTENTION_RESILIENT_INVENTORY_DURATION: Duration = Duration::from_secs(600);

    struct UntrustedUsageProvider {
        usage: Usage,
    }

    impl LlmProvider for UntrustedUsageProvider {
        fn provider_id(&self) -> &str {
            "untrusted-usage"
        }

        fn capabilities(&self) -> ProviderCapabilities {
            ProviderCapabilities::local_fake()
        }

        fn complete(
            &mut self,
            request: LlmRequest,
        ) -> std::result::Result<LlmResponse, ProviderError> {
            Ok(LlmResponse {
                request_id: request.request_id,
                provider_id: self.provider_id().to_string(),
                model: request.model,
                proposal: WorkProposal::summary("{}"),
                usage: self.usage,
                transcript: Default::default(),
                redactions: Default::default(),
            })
        }
    }

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

    fn provider_tree_assignment(
        id: &str,
        task: &str,
        fragment_ids: &[&str],
        path: &str,
        child_assignments: Vec<ProviderTaskAssignmentTree>,
    ) -> ProviderTaskAssignmentTree {
        let is_leaf = child_assignments.is_empty();
        let assigned_paths = if is_leaf {
            vec![PathBuf::from(path)]
        } else {
            child_assignments
                .iter()
                .flat_map(|child| child.assigned_paths.iter().cloned())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect()
        };
        let semantic_symbols = if is_leaf {
            Vec::new()
        } else {
            child_assignments
                .iter()
                .flat_map(|child| child.semantic_symbols.iter().cloned())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect()
        };
        let semantic_modules = if is_leaf {
            Vec::new()
        } else {
            child_assignments
                .iter()
                .flat_map(|child| child.semantic_modules.iter().cloned())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect()
        };
        ProviderTaskAssignmentTree {
            id: id.to_string(),
            task: task.to_string(),
            fragment_ids: fragment_ids
                .iter()
                .map(|fragment_id| fragment_id.to_string())
                .collect(),
            assigned_paths,
            semantic_symbols,
            semantic_modules,
            child_assignments,
        }
    }

    #[test]
    fn provider_config_and_agent_ids_fit_supervisor_lowering_bounds() {
        validate_provider_planning_config(
            &ProviderPlanningConfig::new("bounded", "planner-model")
                .with_max_depth(PROVIDER_PLANNING_MAX_DEPTH),
        )
        .expect("maximum lowerable provider depth is valid");
        assert!(validate_provider_planning_config(
            &ProviderPlanningConfig::new("too-deep", "planner-model")
                .with_max_depth(PROVIDER_PLANNING_MAX_DEPTH + 1),
        )
        .expect_err("unlowerable provider depth must fail before provider invocation")
        .to_string()
        .contains("must be between 1 and 31"));

        for invalid in [".", "..", "bad/id", "bad id", "bad\nline"] {
            assert!(normalize_provider_agent_id(invalid, "test").is_err());
        }
        let too_long = "x".repeat(PROVIDER_PLANNING_MAX_AGENT_ID_BYTES + 1);
        assert!(normalize_provider_agent_id(&too_long, "test").is_err());
        assert_eq!(
            normalize_provider_agent_id(" safe-id_1 ", "test").expect("safe id"),
            "safe-id_1"
        );
    }

    #[test]
    fn provider_response_budget_is_enforced_after_an_ignoring_transport_returns() {
        let budget = RequestBudget::default();
        let mut provider = FakeProvider::new("fake-planner", "planner-model")
            .with_budget_behavior(FakeBudgetBehavior::Ignore);
        provider.push_response(
            "oversized",
            WorkProposal::summary("x".repeat(budget.max_output_chars + 1)),
        );

        let error = complete_provider_planning_request(
            &mut provider,
            &ProviderPlanningConfig::new("ignored", "planner-model"),
            "oversized".to_string(),
            "provider budget test",
            serde_json::json!({"bounded": true}),
        )
        .expect_err("central planning boundary must reject oversized transport output");

        assert!(error.to_string().contains("character provider boundary"));
        assert_eq!(provider.calls().len(), 1);
    }

    #[test]
    fn provider_reported_usage_is_consistent_and_within_the_request_budget() {
        let config = ProviderPlanningConfig::new("usage", "planner-model");
        for (usage, expected) in [
            (
                Usage {
                    input_tokens: 1,
                    output_tokens: 1,
                    total_tokens: 3,
                },
                "internally inconsistent",
            ),
            (
                Usage {
                    input_tokens: RequestBudget::default().max_total_tokens + 1,
                    output_tokens: 0,
                    total_tokens: RequestBudget::default().max_total_tokens + 1,
                },
                "token provider boundary",
            ),
        ] {
            let mut provider = UntrustedUsageProvider { usage };
            let error = complete_provider_planning_request(
                &mut provider,
                &config,
                "usage".to_string(),
                "provider usage test",
                serde_json::json!({"bounded": true}),
            )
            .expect_err("untrusted provider usage must fail closed");
            assert!(error.to_string().contains(expected), "{error:#}");
        }
    }

    #[test]
    fn provider_response_model_is_bound_to_the_request() {
        let mut provider = FakeProvider::new("fake-planner", "unexpected-model");
        provider.push_response("identity", WorkProposal::summary("{}"));
        let error = complete_provider_planning_request(
            &mut provider,
            &ProviderPlanningConfig::new("identity", "planner-model"),
            "identity".to_string(),
            "provider identity test",
            serde_json::json!({"bounded": true}),
        )
        .expect_err("provider response model mismatch must fail closed");
        assert!(error.to_string().contains("does not match bound model"));
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
        run_contention_resilient_inventory_test(|| {
            let temp = tempfile::tempdir().expect("tempdir");
            let repo = temp.path();
            git2::Repository::init(repo).expect("init repo");
            write_file(repo, "src/alpha.rs", "pub fn alpha_task() {}\n");
            write_file(repo, "src/beta.rs", "pub fn beta_task() {}\n");
            let config = ProviderPlanningConfig::new("fallback", "unused-model");
            let unused_provider = FakeProvider::new("must-not-run", "unused-model");

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
            assert!(fallback.provider_assignment_tree().is_empty());
            assert!(unused_provider.calls().is_empty());
        });
    }

    #[test]
    fn fake_provider_proposes_a_validated_disjoint_plan() {
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
    fn fake_provider_proposes_and_retains_a_recursive_depth_two_plan() {
        run_contention_resilient_inventory_test(|| {
            let temp = tempfile::tempdir().expect("tempdir");
            let repo = temp.path();
            git2::Repository::init(repo).expect("init repo");
            write_file(repo, "src/lib.rs", "pub mod alpha;\npub mod beta;\n");
            write_file(repo, "src/alpha.rs", "pub fn alpha_task() {}\n");
            write_file(repo, "src/beta.rs", "pub fn beta_task() {}\n");
            let alpha = provider_tree_assignment(
                "alpha-leaf",
                "Implement alpha",
                &["fragment-001"],
                "src/alpha.rs",
                Vec::new(),
            );
            let beta = provider_tree_assignment(
                "beta-leaf",
                "Implement beta",
                &["fragment-002"],
                "src/beta.rs",
                Vec::new(),
            );
            let plan = ProviderRecursiveTaskPlan {
                assignments: vec![provider_tree_assignment(
                    "root",
                    "Coordinate alpha and beta",
                    &["fragment-002", "fragment-001"],
                    "src/alpha.rs",
                    vec![alpha.clone(), beta.clone()],
                )],
            };
            let config = ProviderPlanningConfig::new("recursive", "planner-model")
                .with_max_child_assignments(3)
                .with_max_depth(2);
            let mut provider = FakeProvider::new("fake-planner", "planner-model");
            provider
                .push_json_response("recursive-proposal", &plan)
                .expect("script recursive plan");

            let session = propose_task_decomposition_with_provider(
                repo,
                "",
                "- Update alpha behavior.\n- Update beta behavior.",
                &mut provider,
                &config,
            )
            .expect("recursive plan");

            assert_eq!(session.provider_assignment_tree().len(), 1);
            assert_eq!(
                session.provider_assignment_tree()[0].fragment_ids,
                vec!["fragment-001", "fragment-002"]
            );
            assert_eq!(
                session.provider_assignment_tree()[0].child_assignments,
                vec![alpha, beta]
            );
            assert_eq!(
                session
                    .proposal()
                    .assignments
                    .iter()
                    .map(|assignment| assignment.id.as_str())
                    .collect::<Vec<_>>(),
                vec!["alpha-leaf", "beta-leaf"]
            );
            assert!(session.proposal().coverage_gaps.is_empty());
            let prompt = provider.calls()[0].prompt.render();
            assert!(prompt.contains("root assignments are depth 1"));
            assert!(prompt.contains("child_assignments"));
            assert!(prompt.contains("\"max_depth\":2"));
        });
    }

    #[test]
    fn recursive_provider_plan_enforces_depth_width_and_total_bounds() {
        run_contention_resilient_inventory_test(|| {
            let temp = tempfile::tempdir().expect("tempdir");
            let repo = temp.path();
            git2::Repository::init(repo).expect("init repo");
            write_file(repo, "src/root.rs", "pub fn root() {}\n");
            write_file(repo, "src/alpha.rs", "pub fn alpha() {}\n");
            write_file(repo, "src/beta.rs", "pub fn beta() {}\n");

            let leaf = provider_tree_assignment(
                "leaf",
                "Implement leaf",
                &["fragment-001"],
                "src/alpha.rs",
                Vec::new(),
            );
            let depth_plan = ProviderRecursiveTaskPlan {
                assignments: vec![provider_tree_assignment(
                    "root",
                    "Coordinate leaf",
                    &["fragment-001"],
                    "src/root.rs",
                    vec![leaf.clone()],
                )],
            };
            let mut depth_provider = FakeProvider::new("fake-planner", "planner-model");
            depth_provider
                .push_json_response("depth-proposal", &depth_plan)
                .expect("script depth plan");
            let depth_error = propose_task_decomposition_with_provider(
                repo,
                "Only fragment",
                "",
                &mut depth_provider,
                &ProviderPlanningConfig::new("depth", "planner-model")
                    .with_max_child_assignments(2)
                    .with_max_depth(1),
            )
            .expect_err("depth must be bounded");
            assert!(depth_error.to_string().contains("reaches depth 2"));

            let width_plan = ProviderRecursiveTaskPlan {
                assignments: vec![provider_tree_assignment(
                    "root",
                    "Coordinate leaves",
                    &["fragment-001"],
                    "src/root.rs",
                    vec![
                        leaf.clone(),
                        provider_tree_assignment(
                            "other-leaf",
                            "Implement other leaf",
                            &["fragment-001"],
                            "src/beta.rs",
                            Vec::new(),
                        ),
                    ],
                )],
            };
            let mut width_provider = FakeProvider::new("fake-planner", "planner-model");
            width_provider
                .push_json_response("width-proposal", &width_plan)
                .expect("script width plan");
            let width_error = propose_task_decomposition_with_provider(
                repo,
                "Only fragment",
                "",
                &mut width_provider,
                &ProviderPlanningConfig::new("width", "planner-model")
                    .with_max_child_assignments(1)
                    .with_max_depth(2),
            )
            .expect_err("sibling width must be bounded");
            assert!(width_error.to_string().contains("has 2 children"));

            let chain = provider_tree_assignment(
                "root",
                "Coordinate middle",
                &["fragment-001"],
                "src/root.rs",
                vec![provider_tree_assignment(
                    "middle",
                    "Coordinate leaf",
                    &["fragment-001"],
                    "src/root.rs",
                    vec![leaf],
                )],
            );
            let mut total_provider = FakeProvider::new("fake-planner", "planner-model");
            total_provider
                .push_json_response(
                    "total-proposal",
                    &ProviderRecursiveTaskPlan {
                        assignments: vec![chain],
                    },
                )
                .expect("script total plan");
            let total_error = propose_task_decomposition_with_provider(
                repo,
                "Only fragment",
                "",
                &mut total_provider,
                &ProviderPlanningConfig::new("total", "planner-model")
                    .with_max_child_assignments(2)
                    .with_max_depth(3),
            )
            .expect_err("flattened assignment count must be bounded");
            assert!(total_error
                .to_string()
                .contains("more than 2 total flattened assignments"));
        });
    }

    #[test]
    fn recursive_provider_plan_rejects_overlap_across_sibling_branches() {
        run_contention_resilient_inventory_test(|| {
            let temp = tempfile::tempdir().expect("tempdir");
            let repo = temp.path();
            git2::Repository::init(repo).expect("init repo");
            write_file(repo, "src/root.rs", "pub fn root() {}\n");
            write_file(repo, "src/shared.rs", "pub fn shared() {}\n");
            let plan = ProviderRecursiveTaskPlan {
                assignments: vec![provider_tree_assignment(
                    "root",
                    "Coordinate work",
                    &["fragment-001", "fragment-002"],
                    "src/root.rs",
                    vec![
                        provider_tree_assignment(
                            "left",
                            "Implement left",
                            &["fragment-001"],
                            "src/shared.rs",
                            Vec::new(),
                        ),
                        provider_tree_assignment(
                            "right",
                            "Implement right",
                            &["fragment-002"],
                            "src/shared.rs",
                            Vec::new(),
                        ),
                    ],
                )],
            };
            let mut provider = FakeProvider::new("fake-planner", "planner-model");
            provider
                .push_json_response("branch-overlap-proposal", &plan)
                .expect("script overlap plan");
            let error = propose_task_decomposition_with_provider(
                repo,
                "",
                "- Left fragment.\n- Right fragment.",
                &mut provider,
                &ProviderPlanningConfig::new("branch-overlap", "planner-model")
                    .with_max_child_assignments(3)
                    .with_max_depth(2),
            )
            .expect_err("sibling overlap must fail");

            assert!(error.to_string().contains("concurrent assignments"));
            assert!(error.to_string().contains("PathOverlap"));
        });
    }

    #[test]
    fn recursive_provider_plan_rejects_cross_branch_ids_and_ambiguous_fragment_coverage() {
        run_contention_resilient_inventory_test(|| {
            let temp = tempfile::tempdir().expect("tempdir");
            let repo = temp.path();
            git2::Repository::init(repo).expect("init repo");
            write_file(repo, "src/root.rs", "pub fn root() {}\n");
            write_file(repo, "src/alpha.rs", "pub fn alpha() {}\n");
            write_file(repo, "src/beta.rs", "pub fn beta() {}\n");
            let duplicate_ids = ProviderRecursiveTaskPlan {
                assignments: vec![provider_tree_assignment(
                    "root",
                    "Coordinate work",
                    &["fragment-001", "fragment-002"],
                    "src/root.rs",
                    vec![
                        provider_tree_assignment(
                            "duplicate",
                            "Implement alpha",
                            &["fragment-001"],
                            "src/alpha.rs",
                            Vec::new(),
                        ),
                        provider_tree_assignment(
                            "duplicate",
                            "Implement beta",
                            &["fragment-002"],
                            "src/beta.rs",
                            Vec::new(),
                        ),
                    ],
                )],
            };
            let union_mismatch = ProviderRecursiveTaskPlan {
                assignments: vec![provider_tree_assignment(
                    "root",
                    "Coordinate work",
                    &["fragment-001"],
                    "src/root.rs",
                    vec![
                        provider_tree_assignment(
                            "alpha",
                            "Implement alpha",
                            &["fragment-001"],
                            "src/alpha.rs",
                            Vec::new(),
                        ),
                        provider_tree_assignment(
                            "beta",
                            "Implement beta",
                            &["fragment-002"],
                            "src/beta.rs",
                            Vec::new(),
                        ),
                    ],
                )],
            };
            let duplicate_leaf_fragment = ProviderRecursiveTaskPlan {
                assignments: vec![provider_tree_assignment(
                    "root",
                    "Coordinate work",
                    &["fragment-001"],
                    "src/root.rs",
                    vec![
                        provider_tree_assignment(
                            "alpha",
                            "Implement alpha",
                            &["fragment-001"],
                            "src/alpha.rs",
                            Vec::new(),
                        ),
                        provider_tree_assignment(
                            "beta",
                            "Implement beta",
                            &["fragment-001"],
                            "src/beta.rs",
                            Vec::new(),
                        ),
                    ],
                )],
            };
            let mut scope_union_mismatch = ProviderRecursiveTaskPlan {
                assignments: vec![provider_tree_assignment(
                    "root",
                    "Coordinate work",
                    &["fragment-001", "fragment-002"],
                    "src/root.rs",
                    vec![
                        provider_tree_assignment(
                            "alpha",
                            "Implement alpha",
                            &["fragment-001"],
                            "src/alpha.rs",
                            Vec::new(),
                        ),
                        provider_tree_assignment(
                            "beta",
                            "Implement beta",
                            &["fragment-002"],
                            "src/beta.rs",
                            Vec::new(),
                        ),
                    ],
                )],
            };
            scope_union_mismatch.assignments[0].assigned_paths = vec![PathBuf::from("src/root.rs")];
            let generated_worker_collision = ProviderRecursiveTaskPlan {
                assignments: vec![provider_tree_assignment(
                    "root",
                    "Coordinate work",
                    &["fragment-001", "fragment-002"],
                    "src/root.rs",
                    vec![
                        provider_tree_assignment(
                            "alpha",
                            "Implement alpha",
                            &["fragment-001"],
                            "src/alpha.rs",
                            Vec::new(),
                        ),
                        provider_tree_assignment(
                            "alpha-worker",
                            "Implement beta",
                            &["fragment-002"],
                            "src/beta.rs",
                            Vec::new(),
                        ),
                    ],
                )],
            };
            for (suffix, plan, expected) in [
                ("ids", duplicate_ids, "repeats assignment id 'duplicate'"),
                (
                    "union",
                    union_mismatch,
                    "fragment_ids must exactly match its descendant executable leaves",
                ),
                (
                    "leaf-fragment",
                    duplicate_leaf_fragment,
                    "maps fragment 'fragment-001' to more than one executable leaf",
                ),
                (
                    "scope-union",
                    scope_union_mismatch,
                    "path, symbol, and module scopes must exactly match the unions",
                ),
                (
                    "worker-id-collision",
                    generated_worker_collision,
                    "collides with a generated runtime id",
                ),
            ] {
                let prefix = format!("recursive-invariant-{suffix}");
                let mut provider = FakeProvider::new("fake-planner", "planner-model");
                provider
                    .push_json_response(format!("{prefix}-proposal"), &plan)
                    .expect("script invalid recursive plan");
                let error = propose_task_decomposition_with_provider(
                    repo,
                    "",
                    "- Alpha fragment.\n- Beta fragment.",
                    &mut provider,
                    &ProviderPlanningConfig::new(prefix, "planner-model")
                        .with_max_child_assignments(3)
                        .with_max_depth(2),
                )
                .expect_err("recursive invariant violation must fail closed");
                assert!(error.to_string().contains(expected), "{error:#}");
            }
        });
    }

    #[test]
    fn recursive_provider_plan_rejects_valid_inventory_semantic_conflicts_across_branches() {
        run_contention_resilient_inventory_test(|| {
            let temp = tempfile::tempdir().expect("tempdir");
            let repo = temp.path();
            git2::Repository::init(repo).expect("init repo");
            write_file(
                repo,
                "src/lib.rs",
                "pub mod shared;\npub mod left;\npub mod right;\npub mod root;\npub mod branch_left;\npub mod branch_right;\n",
            );
            write_file(repo, "src/shared.rs", "pub fn shared_symbol() {}\n");
            write_file(repo, "src/left.rs", "pub fn left() {}\n");
            write_file(repo, "src/right.rs", "pub fn right() {}\n");
            write_file(repo, "src/root.rs", "pub fn root() {}\n");
            write_file(repo, "src/branch_left.rs", "pub fn branch_left() {}\n");
            write_file(repo, "src/branch_right.rs", "pub fn branch_right() {}\n");

            let mut symbol_left = provider_tree_assignment(
                "symbol-left",
                "Implement left",
                &["fragment-001"],
                "src/left.rs",
                Vec::new(),
            );
            symbol_left.semantic_symbols = vec!["crate::shared::shared_symbol".to_string()];
            let mut symbol_right = provider_tree_assignment(
                "symbol-right",
                "Implement right",
                &["fragment-002"],
                "src/right.rs",
                Vec::new(),
            );
            symbol_right.semantic_symbols = vec!["crate::shared::shared_symbol".to_string()];
            let mut symbol_provider = FakeProvider::new("fake-planner", "planner-model");
            symbol_provider
                .push_json_response(
                    "semantic-symbol-proposal",
                    &ProviderRecursiveTaskPlan {
                        assignments: vec![symbol_left, symbol_right],
                    },
                )
                .expect("script symbol-conflict plan");
            let symbol_error = propose_task_decomposition_with_provider(
                repo,
                "",
                "- Alpha fragment.\n- Beta fragment.",
                &mut symbol_provider,
                &ProviderPlanningConfig::new("semantic-symbol", "planner-model")
                    .with_max_child_assignments(2),
            )
            .expect_err("known symbol collision must fail");
            assert!(symbol_error.to_string().contains("SymbolOverlap"));

            let mut module_left_leaf = provider_tree_assignment(
                "module-left-leaf",
                "Implement left",
                &["fragment-001"],
                "src/left.rs",
                Vec::new(),
            );
            module_left_leaf.semantic_modules = vec!["crate::shared".to_string()];
            let mut module_right_leaf = provider_tree_assignment(
                "module-right-leaf",
                "Implement right",
                &["fragment-002"],
                "src/right.rs",
                Vec::new(),
            );
            module_right_leaf.semantic_modules = vec!["crate::shared".to_string()];
            let cousin_plan = ProviderRecursiveTaskPlan {
                assignments: vec![provider_tree_assignment(
                    "module-root",
                    "Coordinate branches",
                    &["fragment-001", "fragment-002"],
                    "src/root.rs",
                    vec![
                        provider_tree_assignment(
                            "module-left-branch",
                            "Coordinate left",
                            &["fragment-001"],
                            "src/branch_left.rs",
                            vec![module_left_leaf],
                        ),
                        provider_tree_assignment(
                            "module-right-branch",
                            "Coordinate right",
                            &["fragment-002"],
                            "src/branch_right.rs",
                            vec![module_right_leaf],
                        ),
                    ],
                )],
            };
            let mut module_provider = FakeProvider::new("fake-planner", "planner-model");
            module_provider
                .push_json_response("semantic-module-proposal", &cousin_plan)
                .expect("script module-conflict plan");
            let module_error = propose_task_decomposition_with_provider(
                repo,
                "",
                "- Alpha fragment.\n- Beta fragment.",
                &mut module_provider,
                &ProviderPlanningConfig::new("semantic-module", "planner-model")
                    .with_max_child_assignments(5)
                    .with_max_depth(3),
            )
            .expect_err("known module cousin collision must fail");
            assert!(module_error.to_string().contains("ModuleOverlap"));
        });
    }

    #[test]
    fn provider_plan_rejects_invented_path_symbol_and_module_inventory() {
        run_contention_resilient_inventory_test(|| {
            let temp = tempfile::tempdir().expect("tempdir");
            let repo = temp.path();
            git2::Repository::init(repo).expect("init repo");
            write_file(repo, "src/lib.rs", "pub mod known;\n");
            write_file(repo, "src/known.rs", "pub fn known_symbol() {}\n");

            for (suffix, mut assignment, expected) in [
                (
                    "path",
                    provider_assignment(
                        "invented",
                        "Invent a path",
                        "fragment-001",
                        "src/missing.rs",
                    ),
                    "not an inventoried file",
                ),
                (
                    "symbol",
                    provider_assignment(
                        "invented",
                        "Invent a symbol",
                        "fragment-001",
                        "src/known.rs",
                    ),
                    "unknown semantic symbol",
                ),
                (
                    "module",
                    provider_assignment(
                        "invented",
                        "Invent a module",
                        "fragment-001",
                        "src/known.rs",
                    ),
                    "unknown semantic module",
                ),
            ] {
                if suffix == "symbol" {
                    assignment.semantic_symbols = vec!["crate::known::missing".to_string()];
                } else if suffix == "module" {
                    assignment.semantic_modules = vec!["crate::missing".to_string()];
                }
                let prefix = format!("invented-{suffix}");
                let mut provider = FakeProvider::new("fake-planner", "planner-model");
                provider
                    .push_json_response(
                        format!("{prefix}-proposal"),
                        &ProviderTaskPlan {
                            assignments: vec![assignment],
                        },
                    )
                    .expect("script invented scope plan");
                let error = propose_task_decomposition_with_provider(
                    repo,
                    "Only fragment",
                    "",
                    &mut provider,
                    &ProviderPlanningConfig::new(prefix, "planner-model"),
                )
                .expect_err("invented scope must fail closed");
                assert!(error.to_string().contains(expected), "{error:#}");
            }
        });
    }

    #[test]
    fn provider_plan_rejects_malformed_unknown_command_and_patch_output() {
        run_contention_resilient_inventory_test(|| {
            let temp = tempfile::tempdir().expect("tempdir");
            let repo = temp.path();
            git2::Repository::init(repo).expect("init repo");
            write_file(repo, "src/known.rs", "pub fn known() {}\n");
            let valid_summary = serde_json::to_string(&ProviderTaskPlan {
                assignments: vec![provider_assignment(
                    "known",
                    "Implement known",
                    "fragment-001",
                    "src/known.rs",
                )],
            })
            .expect("serialize valid summary");
            let unknown_summary = serde_json::json!({
                "assignments": [{
                    "id": "known",
                    "task": "Implement known",
                    "fragment_ids": ["fragment-001"],
                    "assigned_paths": ["src/known.rs"],
                    "semantic_symbols": [],
                    "semantic_modules": [],
                    "shell_command": "rm -rf ."
                }]
            })
            .to_string();
            let cases = vec![
                (
                    "malformed",
                    WorkProposal::summary("not-json"),
                    "not a recursive",
                ),
                (
                    "unknown",
                    WorkProposal::summary(unknown_summary),
                    "not a recursive",
                ),
                (
                    "command",
                    WorkProposal::summary(valid_summary.clone())
                        .with_command(ProposedCommand::new("cargo test", CommandPurpose::Validate)),
                    "must not contain commands or patches",
                ),
                (
                    "patch",
                    WorkProposal {
                        summary: valid_summary,
                        commands: Vec::new(),
                        patches: vec![ProposedPatch {
                            path: PathBuf::from("src/known.rs"),
                            unified_diff: "@@ forbidden @@".to_string(),
                        }],
                        notes: Vec::new(),
                    },
                    "must not contain commands or patches",
                ),
            ];
            for (suffix, proposal, expected) in cases {
                let prefix = format!("invalid-{suffix}");
                let mut provider = FakeProvider::new("fake-planner", "planner-model");
                provider.push_response(format!("{prefix}-proposal"), proposal);
                let error = propose_task_decomposition_with_provider(
                    repo,
                    "Only fragment",
                    "",
                    &mut provider,
                    &ProviderPlanningConfig::new(prefix, "planner-model"),
                )
                .expect_err("invalid structured output must fail closed");
                assert!(error.to_string().contains(expected), "{error:#}");
            }
        });
    }

    #[test]
    fn provider_plan_requires_exact_executable_leaf_coverage() {
        run_contention_resilient_inventory_test(|| {
            let temp = tempfile::tempdir().expect("tempdir");
            let repo = temp.path();
            git2::Repository::init(repo).expect("init repo");
            write_file(repo, "src/alpha.rs", "pub fn alpha() {}\n");
            let plan = ProviderTaskPlan {
                assignments: vec![provider_assignment(
                    "alpha",
                    "Implement alpha",
                    "fragment-001",
                    "src/alpha.rs",
                )],
            };
            let mut provider = FakeProvider::new("fake-planner", "planner-model");
            provider
                .push_json_response("coverage-proposal", &plan)
                .expect("script incomplete plan");
            let error = propose_task_decomposition_with_provider(
                repo,
                "",
                "- Alpha fragment.\n- Beta fragment.",
                &mut provider,
                &ProviderPlanningConfig::new("coverage", "planner-model"),
            )
            .expect_err("missing coverage must fail closed");
            assert!(error.to_string().contains("missing [\"fragment-002\"]"));
        });
    }

    #[test]
    fn provider_plan_rejects_overlapping_assignments() {
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

            assert!(error.to_string().contains("concurrent assignments"));
        });
    }

    #[test]
    fn fake_provider_replans_from_feedback_with_a_hard_attempt_limit() {
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
    fn recursive_feedback_replan_revises_only_the_remaining_subtree() {
        run_contention_resilient_inventory_test(|| {
            let temp = tempfile::tempdir().expect("tempdir");
            let repo = temp.path();
            git2::Repository::init(repo).expect("init repo");
            write_file(repo, "src/root.rs", "pub fn root() {}\n");
            write_file(repo, "src/alpha.rs", "pub fn alpha() {}\n");
            write_file(repo, "src/beta.rs", "pub fn beta() {}\n");
            write_file(repo, "src/gamma.rs", "pub fn gamma() {}\n");
            let initial = ProviderRecursiveTaskPlan {
                assignments: vec![provider_tree_assignment(
                    "initial-root",
                    "Coordinate alpha and beta",
                    &["fragment-001", "fragment-002"],
                    "src/root.rs",
                    vec![
                        provider_tree_assignment(
                            "alpha-leaf",
                            "Implement alpha",
                            &["fragment-001"],
                            "src/alpha.rs",
                            Vec::new(),
                        ),
                        provider_tree_assignment(
                            "beta-leaf",
                            "Implement beta",
                            &["fragment-002"],
                            "src/beta.rs",
                            Vec::new(),
                        ),
                    ],
                )],
            };
            let revised_leaf = provider_tree_assignment(
                "beta-revised-leaf",
                "Implement beta at the discovered location",
                &["fragment-002"],
                "src/gamma.rs",
                Vec::new(),
            );
            let revised = ProviderRecursiveTaskPlan {
                assignments: vec![provider_tree_assignment(
                    "remaining-root",
                    "Coordinate remaining beta work",
                    &["fragment-002"],
                    "src/root.rs",
                    vec![revised_leaf.clone()],
                )],
            };
            let config = ProviderPlanningConfig::new("recursive-feedback", "planner-model")
                .with_max_child_assignments(3)
                .with_max_depth(2);
            let mut provider = FakeProvider::new("fake-planner", "planner-model");
            provider
                .push_json_response("recursive-feedback-proposal", &initial)
                .expect("script initial recursive plan")
                .push_json_response("recursive-feedback-replan-01", &revised)
                .expect("script recursive replan");
            let mut session = propose_task_decomposition_with_provider(
                repo,
                "",
                "- Alpha fragment.\n- Beta fragment.",
                &mut provider,
                &config,
            )
            .expect("initial recursive plan");

            replan_task_decomposition_with_provider(
                repo,
                &mut session,
                &TaskExecutionFeedback {
                    completed_assignment_ids: vec!["alpha-leaf".to_string()],
                    failed_assignment_ids: vec!["beta-leaf".to_string()],
                    notes: vec!["beta moved to gamma".to_string()],
                    ..TaskExecutionFeedback::default()
                },
                &mut provider,
                &config,
            )
            .expect("recursive feedback replan");

            assert_eq!(session.replans_used(), 1);
            assert_eq!(session.proposal().assignments.len(), 1);
            assert_eq!(session.proposal().assignments[0].id, "beta-revised-leaf");
            assert_eq!(
                session.proposal().assignments[0].fragment_ids,
                vec!["fragment-002"]
            );
            assert_eq!(session.provider_assignment_tree().len(), 1);
            assert_eq!(session.provider_assignment_tree()[0].id, "remaining-root");
            assert_eq!(
                session.provider_assignment_tree()[0].child_assignments,
                vec![revised_leaf]
            );
            assert_eq!(
                session.completed_fragment_ids,
                ["fragment-001".to_string()].into_iter().collect()
            );
            assert_eq!(session.completed_assignments.len(), 1);
            assert_eq!(session.completed_assignments[0].id, "alpha-leaf");
            assert!(session
                .provider_assignment_tree()
                .iter()
                .flat_map(|root| root.fragment_ids.iter())
                .all(|fragment_id| fragment_id != "fragment-001"));
            assert_eq!(session.source(), TaskPlanningSource::Provider);
            assert_eq!(session.provider_id(), Some("fake-planner"));
            assert_eq!(session.model(), Some("planner-model"));
            let prompt = provider.calls()[1].prompt.render();
            assert!(prompt.contains("\"completed_fragment_ids\":[\"fragment-001\"]"));
            assert!(prompt.contains("beta moved to gamma"));
        });
    }

    #[test]
    fn failed_replan_cannot_reclaim_completed_scope_or_mutate_valid_state() {
        run_contention_resilient_inventory_test(|| {
            let temp = tempfile::tempdir().expect("tempdir");
            let repo = temp.path();
            git2::Repository::init(repo).expect("init repo");
            write_file(repo, "src/alpha.rs", "pub fn alpha() {}\n");
            write_file(repo, "src/beta.rs", "pub fn beta() {}\n");
            let initial = ProviderTaskPlan {
                assignments: vec![
                    provider_assignment("alpha", "Implement alpha", "fragment-001", "src/alpha.rs"),
                    provider_assignment("beta", "Implement beta", "fragment-002", "src/beta.rs"),
                ],
            };
            let reclaim = ProviderTaskPlan {
                assignments: vec![provider_assignment(
                    "beta-revised",
                    "Move beta onto completed alpha scope",
                    "fragment-002",
                    "src/alpha.rs",
                )],
            };
            let config = ProviderPlanningConfig::new("reclaim", "planner-model");
            let mut provider = FakeProvider::new("fake-planner", "planner-model");
            provider
                .push_json_response("reclaim-proposal", &initial)
                .expect("script initial plan")
                .push_json_response("reclaim-replan-01", &reclaim)
                .expect("script reclaim plan");
            let mut session = propose_task_decomposition_with_provider(
                repo,
                "",
                "- Alpha fragment.\n- Beta fragment.",
                &mut provider,
                &config,
            )
            .expect("initial provider plan");
            let original_proposal = session.proposal().clone();
            let original_tree = session.provider_assignment_tree().to_vec();
            let original_source = session.source();
            let original_provider_id = session.provider_id().map(str::to_string);
            let original_model = session.model().map(str::to_string);
            let original_usage = session.provider_usage();

            let error = replan_task_decomposition_with_provider(
                repo,
                &mut session,
                &TaskExecutionFeedback {
                    completed_assignment_ids: vec!["alpha".to_string()],
                    failed_assignment_ids: vec!["beta".to_string()],
                    ..TaskExecutionFeedback::default()
                },
                &mut provider,
                &config,
            )
            .expect_err("completed scope reclaim must fail");

            assert!(error.to_string().contains("reclaims completed scope"));
            assert_eq!(session.replans_used(), 1);
            assert_eq!(session.proposal(), &original_proposal);
            assert_eq!(session.provider_assignment_tree(), original_tree);
            assert_eq!(session.source(), original_source);
            assert_eq!(session.provider_id(), original_provider_id.as_deref());
            assert_eq!(session.model(), original_model.as_deref());
            assert_eq!(session.provider_usage(), original_usage);
            assert!(session.completed_fragment_ids.is_empty());
            assert!(session.completed_assignments.is_empty());
        });
    }

    #[test]
    fn replan_normalizes_and_deduplicates_feedback_notes() {
        run_contention_resilient_inventory_test(|| {
            let temp = tempfile::tempdir().expect("tempdir");
            let repo = temp.path();
            git2::Repository::init(repo).expect("init repo");
            write_file(repo, "src/alpha.rs", "pub fn alpha() {}\n");
            write_file(repo, "src/revised.rs", "pub fn revised() {}\n");
            let initial = ProviderTaskPlan {
                assignments: vec![provider_assignment(
                    "alpha",
                    "Implement alpha",
                    "fragment-001",
                    "src/alpha.rs",
                )],
            };
            let revised = ProviderTaskPlan {
                assignments: vec![provider_assignment(
                    "alpha-revised",
                    "Implement revised alpha",
                    "fragment-001",
                    "src/revised.rs",
                )],
            };
            let config = ProviderPlanningConfig::new("notes", "planner-model");
            let mut provider = FakeProvider::new("fake-planner", "planner-model");
            provider
                .push_json_response("notes-proposal", &initial)
                .expect("script initial plan")
                .push_json_response("notes-replan-01", &revised)
                .expect("script revised plan");
            let mut session = propose_task_decomposition_with_provider(
                repo,
                "Only fragment",
                "",
                &mut provider,
                &config,
            )
            .expect("initial provider plan");

            replan_task_decomposition_with_provider(
                repo,
                &mut session,
                &TaskExecutionFeedback {
                    notes: vec![
                        " zeta ".to_string(),
                        "alpha".to_string(),
                        "zeta".to_string(),
                        "   ".to_string(),
                    ],
                    ..TaskExecutionFeedback::default()
                },
                &mut provider,
                &config,
            )
            .expect("note-driven replan");

            let prompt = provider.calls()[1].prompt.render();
            assert!(prompt.contains("\"notes\":[\"alpha\",\"zeta\"]"));
            assert!(!prompt.contains(" zeta "));
        });
    }

    #[test]
    fn invalid_provider_replan_responses_consume_attempts_until_exhaustion() {
        run_contention_resilient_inventory_test(|| {
            let temp = tempfile::tempdir().expect("tempdir");
            let repo = temp.path();
            git2::Repository::init(repo).expect("init repo");
            write_file(repo, "src/alpha.rs", "pub fn alpha() {}\n");
            let initial = ProviderTaskPlan {
                assignments: vec![provider_assignment(
                    "alpha",
                    "Implement alpha",
                    "fragment-001",
                    "src/alpha.rs",
                )],
            };
            let unknown_field = serde_json::json!({
                "assignments": [{
                    "id": "alpha-revised",
                    "task": "Implement revised alpha",
                    "fragment_ids": ["fragment-001"],
                    "assigned_paths": ["src/alpha.rs"],
                    "semantic_symbols": [],
                    "semantic_modules": [],
                    "patch": "forbidden"
                }]
            });
            let config = ProviderPlanningConfig::new("exhaust", "planner-model");
            let mut provider = FakeProvider::new("fake-planner", "planner-model");
            provider
                .push_json_response("exhaust-proposal", &initial)
                .expect("script initial plan")
                .push_response("exhaust-replan-01", WorkProposal::summary("malformed-json"))
                .push_json_response("exhaust-replan-02", &unknown_field)
                .expect("script unknown-field plan");
            let mut session = propose_task_decomposition_with_provider(
                repo,
                "Only fragment",
                "",
                &mut provider,
                &config,
            )
            .expect("initial provider plan");
            let original_proposal = session.proposal().clone();
            let original_tree = session.provider_assignment_tree().to_vec();
            let original_source = session.source();
            let original_provider_id = session.provider_id().map(str::to_string);
            let original_model = session.model().map(str::to_string);
            let original_usage = session.provider_usage();
            let feedback = TaskExecutionFeedback {
                failed_assignment_ids: vec!["alpha".to_string()],
                ..TaskExecutionFeedback::default()
            };

            for expected_attempt in 1..=MAX_PROVIDER_REPLANS {
                replan_task_decomposition_with_provider(
                    repo,
                    &mut session,
                    &feedback,
                    &mut provider,
                    &config,
                )
                .expect_err("invalid response must fail closed");
                assert_eq!(session.replans_used(), expected_attempt);
                assert_eq!(session.proposal(), &original_proposal);
                assert_eq!(session.provider_assignment_tree(), original_tree);
                assert_eq!(session.source(), original_source);
                assert_eq!(session.provider_id(), original_provider_id.as_deref());
                assert_eq!(session.model(), original_model.as_deref());
                assert_eq!(session.provider_usage(), original_usage);
                assert!(session.completed_fragment_ids.is_empty());
                assert!(session.completed_assignments.is_empty());
            }
            let exhausted = replan_task_decomposition_with_provider(
                repo,
                &mut session,
                &feedback,
                &mut provider,
                &config,
            )
            .expect_err("third attempt must be rejected before provider call");
            assert!(exhausted.to_string().contains("limit of 2 attempt"));
            assert_eq!(provider.calls().len(), 3);
        });
    }

    #[test]
    fn provider_failures_consume_replan_attempts_without_mutating_valid_state() {
        run_contention_resilient_inventory_test(|| {
            let temp = tempfile::tempdir().expect("tempdir");
            let repo = temp.path();
            git2::Repository::init(repo).expect("init repo");
            write_file(repo, "src/alpha.rs", "pub fn alpha() {}\n");
            let initial = ProviderTaskPlan {
                assignments: vec![provider_assignment(
                    "alpha",
                    "Implement alpha",
                    "fragment-001",
                    "src/alpha.rs",
                )],
            };
            let config = ProviderPlanningConfig::new("provider-failure", "planner-model");
            let mut provider = FakeProvider::new("fake-planner", "planner-model");
            provider
                .push_json_response("provider-failure-proposal", &initial)
                .expect("script initial plan")
                .push_failure("provider-failure-replan-01", "temporary failure")
                .push_failure("provider-failure-replan-02", "persistent failure");
            let mut session = propose_task_decomposition_with_provider(
                repo,
                "Only fragment",
                "",
                &mut provider,
                &config,
            )
            .expect("initial provider plan");
            let original_proposal = session.proposal().clone();
            let original_tree = session.provider_assignment_tree().to_vec();
            let original_source = session.source();
            let original_provider_id = session.provider_id().map(str::to_string);
            let original_model = session.model().map(str::to_string);
            let original_usage = session.provider_usage();
            let feedback = TaskExecutionFeedback {
                failed_assignment_ids: vec!["alpha".to_string()],
                ..TaskExecutionFeedback::default()
            };

            for expected_attempt in 1..=MAX_PROVIDER_REPLANS {
                let error = replan_task_decomposition_with_provider(
                    repo,
                    &mut session,
                    &feedback,
                    &mut provider,
                    &config,
                )
                .expect_err("provider failure must fail closed");
                assert!(error.to_string().contains("provider 'fake-planner' failed"));
                assert_eq!(session.replans_used(), expected_attempt);
                assert_eq!(session.proposal(), &original_proposal);
                assert_eq!(session.provider_assignment_tree(), original_tree);
                assert_eq!(session.source(), original_source);
                assert_eq!(session.provider_id(), original_provider_id.as_deref());
                assert_eq!(session.model(), original_model.as_deref());
                assert_eq!(session.provider_usage(), original_usage);
                assert!(session.completed_fragment_ids.is_empty());
                assert!(session.completed_assignments.is_empty());
            }
            let exhausted = replan_task_decomposition_with_provider(
                repo,
                &mut session,
                &feedback,
                &mut provider,
                &config,
            )
            .expect_err("third attempt must fail before provider invocation");
            assert!(exhausted.to_string().contains("limit of 2 attempt"));
            assert_eq!(provider.calls().len(), 3);
        });
    }

    #[test]
    fn execution_feedback_deduplicates_ids_and_rejects_unknown_contradictory_history() {
        let proposal = TaskDecompositionProposal {
            fragments: vec![
                TaskSpecFragment {
                    id: "fragment-001".to_string(),
                    text: "Alpha".to_string(),
                },
                TaskSpecFragment {
                    id: "fragment-002".to_string(),
                    text: "Beta".to_string(),
                },
            ],
            assignments: vec![
                provider_assignment("alpha", "Alpha", "fragment-001", "src/alpha.rs"),
                provider_assignment("beta", "Beta", "fragment-002", "src/beta.rs"),
            ],
            coverage_gaps: Vec::new(),
            diagnostics: TaskPathProposalDiagnostics::default(),
            disjointness: TaskDisjointnessReport {
                disjoint: true,
                ..TaskDisjointnessReport::default()
            },
        };
        let empty_history = BTreeSet::new();
        let cases = [
            (
                TaskExecutionFeedback {
                    completed_assignment_ids: vec!["missing".to_string()],
                    ..TaskExecutionFeedback::default()
                },
                "unknown completed assignment",
            ),
            (
                TaskExecutionFeedback {
                    completed_assignment_ids: vec!["alpha".to_string()],
                    failed_assignment_ids: vec!["alpha".to_string()],
                    ..TaskExecutionFeedback::default()
                },
                "both completed and failed",
            ),
            (
                TaskExecutionFeedback {
                    coverage_gap_fragment_ids: vec!["fragment-missing".to_string()],
                    ..TaskExecutionFeedback::default()
                },
                "unknown coverage gap fragment",
            ),
        ];
        for (feedback, expected) in cases {
            let error = normalize_execution_feedback(&feedback, &proposal, &empty_history)
                .expect_err("invalid feedback ids must fail closed");
            assert!(error.to_string().contains(expected), "{error:#}");
        }

        let deduplicated = normalize_execution_feedback(
            &TaskExecutionFeedback {
                completed_assignment_ids: vec![" alpha ".to_string(), "alpha".to_string()],
                notes: vec![" note ".to_string(), "note".to_string()],
                ..TaskExecutionFeedback::default()
            },
            &proposal,
            &empty_history,
        )
        .expect("identical normalized feedback items are idempotent");
        assert_eq!(
            deduplicated.completed_assignment_ids,
            ["alpha".to_string()].into_iter().collect()
        );
        assert_eq!(deduplicated.notes, vec!["note"]);

        let completed_history = ["fragment-001".to_string()].into_iter().collect();
        let historical_gap = normalize_execution_feedback(
            &TaskExecutionFeedback {
                coverage_gap_fragment_ids: vec!["fragment-001".to_string()],
                ..TaskExecutionFeedback::default()
            },
            &proposal,
            &completed_history,
        )
        .expect_err("historically completed fragment cannot become a gap");
        assert!(historical_gap
            .to_string()
            .contains("reports completed fragment 'fragment-001' as a coverage gap"));
    }

    #[test]
    fn execution_feedback_enforces_item_and_byte_bounds() {
        let proposal = TaskDecompositionProposal {
            fragments: vec![TaskSpecFragment {
                id: "fragment-001".to_string(),
                text: "Alpha".to_string(),
            }],
            assignments: vec![provider_assignment(
                "alpha",
                "Alpha",
                "fragment-001",
                "src/alpha.rs",
            )],
            coverage_gaps: Vec::new(),
            diagnostics: TaskPathProposalDiagnostics::default(),
            disjointness: TaskDisjointnessReport {
                disjoint: true,
                ..TaskDisjointnessReport::default()
            },
        };
        let history = BTreeSet::new();
        let too_many = normalize_execution_feedback(
            &TaskExecutionFeedback {
                notes: vec!["x".to_string(); PROVIDER_PLANNING_MAX_FEEDBACK_ITEMS + 1],
                ..TaskExecutionFeedback::default()
            },
            &proposal,
            &history,
        )
        .expect_err("feedback item count must be bounded");
        assert!(too_many.to_string().contains("items but at most"));

        let oversized_item = normalize_execution_feedback(
            &TaskExecutionFeedback {
                notes: vec!["x".repeat(PROVIDER_PLANNING_MAX_FEEDBACK_ITEM_BYTES + 1)],
                ..TaskExecutionFeedback::default()
            },
            &proposal,
            &history,
        )
        .expect_err("feedback item bytes must be bounded");
        assert!(oversized_item
            .to_string()
            .contains("item contains 16385 bytes"));

        let oversized_padding = " ".repeat(PROVIDER_PLANNING_MAX_FEEDBACK_ITEM_BYTES + 1);
        for (label, feedback) in [
            (
                "completed assignment",
                TaskExecutionFeedback {
                    completed_assignment_ids: vec![format!("{oversized_padding}alpha")],
                    ..TaskExecutionFeedback::default()
                },
            ),
            (
                "failed assignment",
                TaskExecutionFeedback {
                    failed_assignment_ids: vec![format!("{oversized_padding}alpha")],
                    ..TaskExecutionFeedback::default()
                },
            ),
            (
                "coverage gap",
                TaskExecutionFeedback {
                    coverage_gap_fragment_ids: vec![format!("{oversized_padding}fragment-001")],
                    ..TaskExecutionFeedback::default()
                },
            ),
            (
                "note",
                TaskExecutionFeedback {
                    notes: vec![oversized_padding.clone()],
                    ..TaskExecutionFeedback::default()
                },
            ),
        ] {
            let error = normalize_execution_feedback(&feedback, &proposal, &history)
                .expect_err("raw whitespace padding must count toward the item byte limit");
            assert!(
                error.to_string().contains("item contains"),
                "{label} raw bytes were not rejected: {error:#}"
            );
        }

        let aggregate_items = PROVIDER_PLANNING_MAX_TOTAL_FEEDBACK_BYTES
            / PROVIDER_PLANNING_MAX_FEEDBACK_ITEM_BYTES
            + 1;
        let oversized_aggregate = normalize_execution_feedback(
            &TaskExecutionFeedback {
                notes: vec!["x".repeat(PROVIDER_PLANNING_MAX_FEEDBACK_ITEM_BYTES); aggregate_items],
                ..TaskExecutionFeedback::default()
            },
            &proposal,
            &history,
        )
        .expect_err("feedback aggregate bytes must be bounded");
        assert!(oversized_aggregate.to_string().contains("aggregate limit"));
    }

    #[test]
    fn execution_feedback_rejects_newly_completed_fragment_as_a_gap_before_provider_call() {
        run_contention_resilient_inventory_test(|| {
            let temp = tempfile::tempdir().expect("tempdir");
            let repo = temp.path();
            git2::Repository::init(repo).expect("init repo");
            write_file(repo, "src/alpha.rs", "pub fn alpha() {}\n");
            let initial = ProviderTaskPlan {
                assignments: vec![provider_assignment(
                    "alpha",
                    "Implement alpha",
                    "fragment-001",
                    "src/alpha.rs",
                )],
            };
            let config = ProviderPlanningConfig::new("new-gap", "planner-model");
            let mut provider = FakeProvider::new("fake-planner", "planner-model");
            provider
                .push_json_response("new-gap-proposal", &initial)
                .expect("script initial plan");
            let mut session = propose_task_decomposition_with_provider(
                repo,
                "Only fragment",
                "",
                &mut provider,
                &config,
            )
            .expect("initial provider plan");
            let original = session.clone();

            let error = replan_task_decomposition_with_provider(
                repo,
                &mut session,
                &TaskExecutionFeedback {
                    completed_assignment_ids: vec!["alpha".to_string()],
                    coverage_gap_fragment_ids: vec!["fragment-001".to_string()],
                    ..TaskExecutionFeedback::default()
                },
                &mut provider,
                &config,
            )
            .expect_err("newly completed fragment cannot also be a gap");
            assert!(error
                .to_string()
                .contains("marks newly completed fragment 'fragment-001' as a coverage gap"));
            assert_eq!(session, original);
            assert_eq!(provider.calls().len(), 1);
        });
    }

    #[test]
    fn propose_task_decomposition_is_deterministic_and_exposes_coverage_and_intents() {
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
    fn collect_repo_files_excludes_local_agent_runtime_state() {
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
        use std::os::unix::{fs::symlink, net::UnixListener};

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
        let _socket = UnixListener::bind(repo.join("socket")).expect("socket");

        let files = collect_repo_files(&repo).expect("collect files");
        assert_eq!(files, vec![PathBuf::from("README.md")]);
    }

    fn write_file(repo: &Path, relative: &str, contents: &str) {
        let path = repo.join(relative);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("create parent directory");
        }
        fs::write(path, contents).expect("write file");
    }
}
