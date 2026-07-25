use crate::{
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
        let candidate = propose_fragment_scope(fragment, &files, &file_set, semantic_map.as_ref());
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

fn propose_fragment_scope(
    fragment: &TaskSpecFragment,
    files: &[PathBuf],
    file_set: &BTreeSet<PathBuf>,
    semantic_map: Option<&repo_semantic::SemanticRepoMap>,
) -> TaskAssignmentProposal {
    let lowered = fragment.text.to_ascii_lowercase();
    let normalized_text = normalize_text(&fragment.text);
    let mut assigned_paths = BTreeSet::new();
    let mut semantic_symbols = BTreeSet::new();
    let mut semantic_modules = BTreeSet::new();

    for file in files {
        let display = file.to_string_lossy().to_ascii_lowercase();
        if contains_path_mention(&lowered, &display) {
            assigned_paths.insert(file.clone());
        }
    }
    propose_docs_paths(&normalized_text, file_set, &mut assigned_paths);

    if let Some(map) = semantic_map {
        for file in &map.files {
            if !file_set.contains(&file.path) {
                continue;
            }
            if identifier_matches(&normalized_text, &file.path) {
                assigned_paths.insert(file.path.clone());
            }
            if module_matches(&normalized_text, &file.module_path) {
                assigned_paths.insert(file.path.clone());
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
            assigned_paths.insert(symbol.file.clone());
            let qualified = symbol.qualified_path.join("::");
            if symbol.kind == repo_semantic::SemanticSymbolKind::Module {
                semantic_modules.insert(qualified);
            } else {
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
                assigned_paths.insert(file.clone());
            }
        }
    }

    TaskAssignmentProposal {
        id: fragment.id.clone(),
        task: fragment.text.clone(),
        fragment_ids: vec![fragment.id.clone()],
        assigned_paths: collapse_covered_paths(assigned_paths),
        semantic_symbols: semantic_symbols.into_iter().collect(),
        semantic_modules: semantic_modules.into_iter().collect(),
    }
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
                vec![
                    PathBuf::from("src/lib.rs"),
                    PathBuf::from("src/planning.rs")
                ]
            );
            assert!(proposal.assignments[0]
                .semantic_symbols
                .contains(&"crate::planning::propose_task_paths".to_string()));
            assert!(proposal.assignments[0]
                .semantic_modules
                .contains(&"crate::planning".to_string()));
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
