use crate::{
    merge::{serialize_path, serialize_paths, MergeCandidate, SafetyCheck, SafetyCheckStatus},
    repo_semantic::{
        self, SemanticDependencyImpact, SemanticRiskReport, SemanticSymbol, SemanticSymbolKind,
    },
};
use anyhow::{Context, Result};
use git2::{Diff, DiffFormat, DiffOptions, Oid, Repository};
use serde::Serialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};

const SEMANTIC_CONFLICT_MAX_PATHS: usize = 256;
const SEMANTIC_CONFLICT_MAX_ITEMS: usize = 1024;
const SEMANTIC_CONFLICT_MAX_NOTES: usize = 64;
const SEMANTIC_CONFLICT_MAX_CHANGED_LINES: usize = 32 * 1024;
const SEMANTIC_CONFLICT_MAX_RETAINED_TEXT_BYTES: usize = 4 * 1024 * 1024;
const SEMANTIC_CONFLICT_MAX_PRIMARY_BLOB_BYTES: i64 = 8 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SemanticConflictClassification {
    pub advisory: bool,
    pub status: SemanticConflictClassificationStatus,
    pub risk: SemanticConflictRisk,
    pub confidence: SemanticConflictConfidence,
    pub degraded: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
    #[serde(serialize_with = "serialize_paths")]
    pub conflict_paths: Vec<PathBuf>,
    pub overlaps: Vec<SemanticConflictOverlap>,
}

impl SemanticConflictClassification {
    pub(crate) fn no_conflict() -> Self {
        Self {
            advisory: true,
            status: SemanticConflictClassificationStatus::NoConflict,
            risk: SemanticConflictRisk::None,
            confidence: SemanticConflictConfidence::High,
            degraded: false,
            notes: Vec::new(),
            conflict_paths: Vec::new(),
            overlaps: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticConflictClassificationStatus {
    NoConflict,
    Classified,
    Degraded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticConflictRisk {
    None,
    Low,
    Medium,
    High,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticConflictConfidence {
    None,
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SemanticConflictOverlap {
    #[serde(serialize_with = "serialize_path")]
    pub path: PathBuf,
    pub kind: SemanticConflictOverlapKind,
    pub risk: SemanticConflictRisk,
    pub confidence: SemanticConflictConfidence,
    pub primary: SemanticConflictSide,
    pub candidate: SemanticConflictSide,
    pub common_symbols: Vec<SemanticConflictSymbol>,
    pub common_impls: Vec<SemanticConflictSymbol>,
    pub common_modules: Vec<String>,
    #[serde(serialize_with = "serialize_paths")]
    pub impacted_files: Vec<PathBuf>,
    pub dependency_impacts: Vec<SemanticConflictDependencyImpact>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticConflictOverlapKind {
    ImportOnly,
    FormattingOnly,
    SignatureLevel,
    SymbolLevel,
    ImplLevel,
    ModuleLevel,
    FileLevel,
    Unresolved,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SemanticConflictSide {
    pub touched_symbols: Vec<SemanticConflictSymbol>,
    pub touched_impls: Vec<SemanticConflictSymbol>,
    pub touched_modules: Vec<String>,
    pub touched_imports: Vec<SemanticConflictImport>,
    pub formatting_only: bool,
    pub import_only: bool,
    pub signature_level: bool,
    pub current_line_ranges: Vec<SemanticConflictLineRange>,
    pub base_line_ranges: Vec<SemanticConflictLineRange>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct SemanticConflictSymbol {
    pub name: String,
    pub qualified_path: Vec<String>,
    pub kind: SemanticSymbolKind,
    pub visibility: String,
    pub impl_target: Option<String>,
    pub impl_trait: Option<String>,
    #[serde(serialize_with = "serialize_path")]
    pub file: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct SemanticConflictImport {
    pub path: String,
    pub alias: Option<String>,
    pub glob: bool,
    pub visibility: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct SemanticConflictLineRange {
    pub start_line: usize,
    pub end_line: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SemanticConflictDependencyImpact {
    pub side: SemanticConflictDependencySide,
    pub impact: SemanticDependencyImpact,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticConflictDependencySide {
    Primary,
    Candidate,
}

#[derive(Debug, Clone, Default)]
struct PatchChangeSet {
    paths: BTreeMap<PathBuf, FilePatchChanges>,
    degraded: bool,
    notes: Vec<String>,
}

#[derive(Debug, Clone, Default)]
struct FilePatchChanges {
    current_lines: BTreeSet<usize>,
    base_lines: BTreeSet<usize>,
    added_text: Vec<(usize, String)>,
    removed_text: Vec<(usize, String)>,
    binary: bool,
    truncated: bool,
    invalid_utf8: bool,
}

impl FilePatchChanges {
    fn has_changes(&self) -> bool {
        !self.added_text.is_empty() || !self.removed_text.is_empty()
    }

    fn formatting_only(&self) -> bool {
        if !self.has_changes() || self.added_text.len() != self.removed_text.len() {
            return false;
        }
        let mut differs = false;
        let same_after_edge_whitespace =
            self.added_text
                .iter()
                .zip(&self.removed_text)
                .all(|((_, added), (_, removed))| {
                    differs |= added != removed;
                    added.trim() == removed.trim()
                });
        differs && same_after_edge_whitespace
    }

    fn changed_text(&self) -> impl Iterator<Item = &str> {
        self.added_text
            .iter()
            .chain(&self.removed_text)
            .map(|(_, text)| text.as_str())
    }
}

#[derive(Debug, Default)]
struct DiffRetentionBudget {
    retained_lines: usize,
    retained_text_bytes: usize,
    exhausted: bool,
}

impl DiffRetentionBudget {
    fn retain(&mut self, bytes: usize) -> bool {
        let Some(lines) = self.retained_lines.checked_add(1) else {
            self.exhausted = true;
            return false;
        };
        let Some(text_bytes) = self.retained_text_bytes.checked_add(bytes) else {
            self.exhausted = true;
            return false;
        };
        if lines > SEMANTIC_CONFLICT_MAX_CHANGED_LINES
            || text_bytes > SEMANTIC_CONFLICT_MAX_RETAINED_TEXT_BYTES
        {
            self.exhausted = true;
            return false;
        }
        self.retained_lines = lines;
        self.retained_text_bytes = text_bytes;
        true
    }
}

pub(crate) fn classify_semantic_conflicts(
    candidate: &MergeCandidate,
    apply_check: &SafetyCheck,
) -> SemanticConflictClassification {
    let mut notes = Vec::new();
    let mut conflict_paths = apply_check
        .paths
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    if conflict_paths.len() > SEMANTIC_CONFLICT_MAX_PATHS {
        notes.push(format!(
            "semantic conflict classification truncated conflict paths to {SEMANTIC_CONFLICT_MAX_PATHS}"
        ));
        conflict_paths.truncate(SEMANTIC_CONFLICT_MAX_PATHS);
    }

    if conflict_paths.is_empty() {
        if apply_check.status == SafetyCheckStatus::Failed {
            return degraded_without_paths(
                "apply check failed without a reported path; semantic overlap could not be located",
            );
        }
        return SemanticConflictClassification::no_conflict();
    }

    let primary_map =
        scan_semantic_map(&candidate.metadata.primary_repo_root, "primary", &mut notes);
    let candidate_map =
        scan_semantic_map(&candidate.metadata.worktree_path, "candidate", &mut notes);
    let primary_changes = match collect_primary_changes(candidate, &conflict_paths) {
        Ok(changes) => changes,
        Err(error) => {
            notes.push(format!(
                "primary conflict diff could not be collected; classification is degraded: {error:#}"
            ));
            PatchChangeSet::default()
        }
    };
    let candidate_changes = match collect_candidate_changes(candidate, &conflict_paths) {
        Ok(changes) => changes,
        Err(error) => {
            notes.push(format!(
                "candidate conflict diff could not be parsed; classification is degraded: {error:#}"
            ));
            PatchChangeSet::default()
        }
    };
    notes.extend(primary_changes.notes.iter().cloned());
    notes.extend(candidate_changes.notes.iter().cloned());

    let primary_risk = primary_map
        .as_ref()
        .map(|map| repo_semantic::risk_report_for_paths(map, &conflict_paths));
    let candidate_risk = candidate_map
        .as_ref()
        .map(|map| repo_semantic::risk_report_for_paths(map, &conflict_paths));
    classify_semantic_pair(
        conflict_paths,
        primary_map.as_ref(),
        candidate_map.as_ref(),
        &primary_changes,
        &candidate_changes,
        primary_risk.as_ref(),
        candidate_risk.as_ref(),
        notes,
        "primary",
        "candidate",
    )
}

pub(crate) fn classify_semantic_candidate_pair(
    first: &MergeCandidate,
    second: &MergeCandidate,
    conflict_paths: &[PathBuf],
) -> SemanticConflictClassification {
    let mut notes = Vec::new();
    let mut conflict_paths = conflict_paths
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    if conflict_paths.len() > SEMANTIC_CONFLICT_MAX_PATHS {
        notes.push(format!(
            "semantic conflict classification truncated conflict paths to {SEMANTIC_CONFLICT_MAX_PATHS}"
        ));
        conflict_paths.truncate(SEMANTIC_CONFLICT_MAX_PATHS);
    }
    if conflict_paths.is_empty() {
        return degraded_without_paths(
            "candidate-pair arbitration had no reported collision path; semantic overlap could not be located",
        );
    }

    let first_map = scan_semantic_map(&first.metadata.worktree_path, "first candidate", &mut notes);
    let second_map = scan_semantic_map(
        &second.metadata.worktree_path,
        "second candidate",
        &mut notes,
    );
    let first_changes = match collect_candidate_changes(first, &conflict_paths) {
        Ok(changes) => changes,
        Err(error) => {
            notes.push(format!(
                "first candidate conflict diff could not be parsed; classification is degraded: {error:#}"
            ));
            PatchChangeSet::default()
        }
    };
    let second_changes = match collect_candidate_changes(second, &conflict_paths) {
        Ok(changes) => changes,
        Err(error) => {
            notes.push(format!(
                "second candidate conflict diff could not be parsed; classification is degraded: {error:#}"
            ));
            PatchChangeSet::default()
        }
    };
    notes.extend(first_changes.notes.iter().cloned());
    notes.extend(second_changes.notes.iter().cloned());
    let first_risk = first_map
        .as_ref()
        .map(|map| repo_semantic::risk_report_for_paths(map, &conflict_paths));
    let second_risk = second_map
        .as_ref()
        .map(|map| repo_semantic::risk_report_for_paths(map, &conflict_paths));
    classify_semantic_pair(
        conflict_paths,
        first_map.as_ref(),
        second_map.as_ref(),
        &first_changes,
        &second_changes,
        first_risk.as_ref(),
        second_risk.as_ref(),
        notes,
        "first candidate",
        "second candidate",
    )
}

#[allow(clippy::too_many_arguments)]
fn classify_semantic_pair(
    conflict_paths: Vec<PathBuf>,
    primary_map: Option<&repo_semantic::SemanticRepoMap>,
    candidate_map: Option<&repo_semantic::SemanticRepoMap>,
    primary_changes: &PatchChangeSet,
    candidate_changes: &PatchChangeSet,
    primary_risk: Option<&SemanticRiskReport>,
    candidate_risk: Option<&SemanticRiskReport>,
    notes: Vec<String>,
    primary_label: &str,
    candidate_label: &str,
) -> SemanticConflictClassification {
    let mut overlaps = Vec::new();

    for path in &conflict_paths {
        let primary_file = primary_changes.paths.get(path).cloned().unwrap_or_default();
        let candidate_file = candidate_changes
            .paths
            .get(path)
            .cloned()
            .unwrap_or_default();
        let (primary, mut overlap_notes) =
            classify_side(primary_map, path, &primary_file, primary_label);
        let (candidate_side, candidate_notes) =
            classify_side(candidate_map, path, &candidate_file, candidate_label);
        overlap_notes.extend(candidate_notes);

        let common_symbols =
            common_touched_symbols(&primary.touched_symbols, &candidate_side.touched_symbols);
        let common_impls =
            common_touched_symbols(&primary.touched_impls, &candidate_side.touched_impls);
        let common_modules = primary
            .touched_modules
            .iter()
            .filter(|module| candidate_side.touched_modules.contains(module))
            .cloned()
            .collect::<Vec<_>>();
        let kind = overlap_kind(
            &primary,
            &candidate_side,
            &common_symbols,
            &common_impls,
            &common_modules,
        );
        let risk = overlap_risk(kind);
        let (impacted_files, dependency_impacts) =
            dependency_impacts_for_path(primary_risk, candidate_risk, path);
        let impacted_files = truncate_items(impacted_files, "impacted files", &mut overlap_notes);
        let dependency_impacts =
            truncate_items(dependency_impacts, "dependency impacts", &mut overlap_notes);
        let confidence = overlap_confidence(kind, &overlap_notes);
        overlaps.push(SemanticConflictOverlap {
            path: path.clone(),
            kind,
            risk,
            confidence,
            primary,
            candidate: candidate_side,
            common_symbols,
            common_impls,
            common_modules,
            impacted_files,
            dependency_impacts,
            notes: bounded_notes(overlap_notes),
        });
    }

    let degraded = !notes.is_empty()
        || primary_changes.degraded
        || candidate_changes.degraded
        || overlaps.iter().any(|overlap| {
            !overlap.notes.is_empty() || overlap.kind == SemanticConflictOverlapKind::Unresolved
        });
    let status = if degraded {
        SemanticConflictClassificationStatus::Degraded
    } else {
        SemanticConflictClassificationStatus::Classified
    };
    let risk = aggregate_risk(&overlaps);
    let confidence = overlaps
        .iter()
        .map(|overlap| overlap.confidence)
        .min()
        .unwrap_or(SemanticConflictConfidence::None);

    SemanticConflictClassification {
        advisory: true,
        status,
        risk,
        confidence,
        degraded,
        notes: bounded_notes(notes),
        conflict_paths,
        overlaps,
    }
}

fn degraded_without_paths(note: &str) -> SemanticConflictClassification {
    SemanticConflictClassification {
        advisory: true,
        status: SemanticConflictClassificationStatus::Degraded,
        risk: SemanticConflictRisk::Unknown,
        confidence: SemanticConflictConfidence::None,
        degraded: true,
        notes: vec![note.to_string()],
        conflict_paths: Vec::new(),
        overlaps: Vec::new(),
    }
}

fn scan_semantic_map(
    path: &Path,
    side: &str,
    notes: &mut Vec<String>,
) -> Option<repo_semantic::SemanticRepoMap> {
    match repo_semantic::scan_repository(path) {
        Ok(map) => Some(map),
        Err(error) => {
            notes.push(format!(
                "{side} semantic scan failed; classification is degraded: {error:#}"
            ));
            None
        }
    }
}

fn collect_primary_changes(
    candidate: &MergeCandidate,
    conflict_paths: &[PathBuf],
) -> Result<PatchChangeSet> {
    let base = candidate
        .metadata
        .merge_base
        .as_deref()
        .or(candidate.metadata.primary_head.as_deref())
        .context("merge base and primary HEAD are unavailable")?;
    let base = Oid::from_str(base).context("merge base object id is invalid")?;
    let repo =
        crate::git_repository::open(&candidate.metadata.primary_repo_root).with_context(|| {
            format!(
                "failed to open primary repository {}",
                candidate.metadata.primary_repo_root.display()
            )
        })?;
    let base_tree = repo
        .find_commit(base)
        .with_context(|| format!("failed to find merge base commit {base}"))?
        .tree()
        .context("failed to read merge base tree")?;
    let mut options = DiffOptions::new();
    options
        .context_lines(0)
        .include_typechange(true)
        .include_untracked(true)
        .recurse_untracked_dirs(true)
        .disable_pathspec_match(true)
        .max_size(SEMANTIC_CONFLICT_MAX_PRIMARY_BLOB_BYTES);
    for path in conflict_paths {
        options.pathspec(path);
    }
    let diff = repo
        .diff_tree_to_workdir_with_index(Some(&base_tree), Some(&mut options))
        .context("failed to diff primary worktree against merge base")?;
    collect_diff_changes(&diff, conflict_paths, "primary")
}

fn collect_candidate_changes(
    candidate: &MergeCandidate,
    conflict_paths: &[PathBuf],
) -> Result<PatchChangeSet> {
    let diff = Diff::from_buffer(&candidate.raw_diff)
        .context("candidate patch was not a valid Git diff")?;
    collect_diff_changes(&diff, conflict_paths, "candidate")
}

fn collect_diff_changes(
    diff: &Diff<'_>,
    conflict_paths: &[PathBuf],
    side: &str,
) -> Result<PatchChangeSet> {
    let allowed = conflict_paths.iter().cloned().collect::<BTreeSet<_>>();
    let mut changes = PatchChangeSet::default();
    for delta in diff.deltas() {
        for path in delta_paths(&delta) {
            if allowed.contains(&path) {
                let file = changes.paths.entry(path).or_default();
                file.binary |= delta.old_file().is_binary() || delta.new_file().is_binary();
            }
        }
    }

    let mut budget = DiffRetentionBudget::default();
    let print_result = diff.print(DiffFormat::Patch, |delta, _hunk, line| {
        let origin = line.origin();
        if !matches!(origin, '+' | '-') {
            return true;
        }
        let Some(path) = diff_line_path(&delta, origin) else {
            return true;
        };
        if !allowed.contains(path) {
            return true;
        }
        if !budget.retain(line.content().len()) {
            return false;
        }
        let text = match std::str::from_utf8(line.content()) {
            Ok(text) => text.to_string(),
            Err(_) => {
                let file = changes.paths.entry(path.to_path_buf()).or_default();
                file.invalid_utf8 = true;
                String::from_utf8_lossy(line.content()).into_owned()
            }
        };
        let file = changes.paths.entry(path.to_path_buf()).or_default();
        match origin {
            '+' => {
                if let Some(line_number) = line.new_lineno().map(|line| line as usize) {
                    file.current_lines.insert(line_number);
                    file.added_text.push((line_number, text));
                }
            }
            '-' => {
                if let Some(line_number) = line.old_lineno().map(|line| line as usize) {
                    file.base_lines.insert(line_number);
                    file.removed_text.push((line_number, text));
                }
            }
            _ => {}
        }
        true
    });
    if let Err(error) = print_result {
        if budget.exhausted {
            changes.degraded = true;
            changes.notes.push(format!(
                "{side} conflict diff exceeded the bounded line or retained-text budget"
            ));
            for file in changes.paths.values_mut() {
                file.truncated = true;
            }
        } else {
            return Err(error).with_context(|| format!("failed to inspect {side} conflict diff"));
        }
    }
    Ok(changes)
}

fn delta_paths(delta: &git2::DiffDelta<'_>) -> Vec<PathBuf> {
    let mut paths = BTreeSet::new();
    if let Some(path) = delta.old_file().path() {
        paths.insert(path.to_path_buf());
    }
    if let Some(path) = delta.new_file().path() {
        paths.insert(path.to_path_buf());
    }
    paths.into_iter().collect()
}

fn diff_line_path<'a>(delta: &'a git2::DiffDelta<'_>, origin: char) -> Option<&'a Path> {
    if origin == '-' {
        delta.old_file().path().or_else(|| delta.new_file().path())
    } else {
        delta.new_file().path().or_else(|| delta.old_file().path())
    }
}

fn classify_side(
    map: Option<&repo_semantic::SemanticRepoMap>,
    path: &Path,
    changes: &FilePatchChanges,
    side: &str,
) -> (SemanticConflictSide, Vec<String>) {
    let mut notes = Vec::new();
    if !changes.has_changes() {
        notes.push(format!(
            "{side} conflict diff did not expose text changes for this path"
        ));
    }
    if changes.binary {
        notes.push(format!(
            "{side} conflict path is binary or exceeds the semantic blob-size threshold"
        ));
    }
    if changes.truncated {
        notes.push(format!("{side} conflict lines were truncated"));
    }
    if changes.invalid_utf8 {
        notes.push(format!(
            "{side} conflict lines were not valid UTF-8 and were decoded lossily"
        ));
    }

    let raw_symbols = map
        .map(|map| touched_semantic_symbols(map, path, changes))
        .unwrap_or_default();
    let mut touched_symbols = raw_symbols
        .iter()
        .filter(|symbol| {
            !matches!(
                symbol.kind,
                SemanticSymbolKind::Impl | SemanticSymbolKind::Module
            )
        })
        .map(semantic_conflict_symbol)
        .collect::<Vec<_>>();
    let mut touched_impls = raw_symbols
        .iter()
        .filter(|symbol| symbol.kind == SemanticSymbolKind::Impl)
        .map(semantic_conflict_symbol)
        .collect::<Vec<_>>();
    let mut touched_modules = map
        .map(|map| touched_semantic_modules(map, path, &raw_symbols))
        .unwrap_or_default();
    let mut touched_imports = map
        .map(|map| touched_semantic_imports(map, path, changes))
        .unwrap_or_default();
    let formatting_only = changes.formatting_only();
    let import_only = semantic_import_only(map, path, changes, &touched_imports);
    let signature_level = raw_symbols
        .iter()
        .any(|symbol| signature_changed(symbol, changes));

    if map.is_none() {
        notes.push(format!(
            "{side} semantic map is unavailable; symbol, impl, module, and import details are degraded"
        ));
    } else if changes.has_changes()
        && touched_symbols.is_empty()
        && touched_impls.is_empty()
        && touched_imports.is_empty()
    {
        notes.push(format!(
            "{side} semantic map did not resolve changed lines to symbols, impls, or imports"
        ));
    }
    if let Some(map) = map {
        if map.errors.iter().any(|error| {
            normalize_map_path(&map.root, &error.file) == normalize_map_path(&map.root, path)
        }) {
            notes.push(format!(
                "{side} semantic map reported parse or read errors for this path"
            ));
        }
    }
    if changes.current_lines.is_empty() && !changes.base_lines.is_empty() {
        notes.push(format!(
            "{side} changes are removal-only; the current semantic map cannot resolve removed declarations"
        ));
    }

    touched_symbols.sort();
    touched_symbols.dedup();
    touched_impls.sort();
    touched_impls.dedup();
    touched_modules.sort();
    touched_modules.dedup();
    touched_imports.sort();
    touched_imports.dedup();
    let touched_symbols = truncate_items(touched_symbols, "touched symbols", &mut notes);
    let touched_impls = truncate_items(touched_impls, "touched impls", &mut notes);
    let touched_modules = truncate_items(touched_modules, "touched modules", &mut notes);
    let touched_imports = truncate_items(touched_imports, "touched imports", &mut notes);

    (
        SemanticConflictSide {
            touched_symbols,
            touched_impls,
            touched_modules,
            touched_imports,
            formatting_only,
            import_only,
            signature_level,
            current_line_ranges: line_ranges(&changes.current_lines),
            base_line_ranges: line_ranges(&changes.base_lines),
        },
        notes,
    )
}

fn touched_semantic_symbols(
    map: &repo_semantic::SemanticRepoMap,
    path: &Path,
    changes: &FilePatchChanges,
) -> Vec<SemanticSymbol> {
    let normalized_path = normalize_map_path(&map.root, path);
    let mut symbols =
        map.symbols
            .iter()
            .filter(|symbol| {
                normalize_map_path(&map.root, &symbol.file) == normalized_path
                    && changes.current_lines.iter().any(|line| {
                        symbol.span.start_line <= *line && *line <= symbol.span.end_line
                    })
            })
            .cloned()
            .collect::<Vec<_>>();
    symbols.sort_by_key(semantic_symbol_key);
    symbols.dedup_by(|left, right| semantic_symbol_key(left) == semantic_symbol_key(right));
    symbols
}

fn touched_semantic_modules(
    map: &repo_semantic::SemanticRepoMap,
    path: &Path,
    symbols: &[SemanticSymbol],
) -> Vec<String> {
    let normalized_path = normalize_map_path(&map.root, path);
    let mut modules = map
        .files
        .iter()
        .filter(|file| normalize_map_path(&map.root, &file.path) == normalized_path)
        .map(|file| file.module_path.join("::"))
        .collect::<BTreeSet<_>>();
    modules.extend(
        symbols
            .iter()
            .filter(|symbol| symbol.kind == SemanticSymbolKind::Module)
            .map(|symbol| symbol.qualified_path.join("::")),
    );
    modules
        .into_iter()
        .filter(|module| !module.is_empty())
        .collect()
}

fn touched_semantic_imports(
    map: &repo_semantic::SemanticRepoMap,
    path: &Path,
    changes: &FilePatchChanges,
) -> Vec<SemanticConflictImport> {
    let normalized_path = normalize_map_path(&map.root, path);
    let mut imports =
        map.imports
            .iter()
            .filter(|import| {
                normalize_map_path(&map.root, &import.file) == normalized_path
                    && changes.current_lines.iter().any(|line| {
                        import.span.start_line <= *line && *line <= import.span.end_line
                    })
            })
            .map(|import| SemanticConflictImport {
                path: import.path.clone(),
                alias: import.alias.clone(),
                glob: import.glob,
                visibility: import.visibility.clone(),
            })
            .chain(
                map.re_exports
                    .iter()
                    .filter(|import| {
                        normalize_map_path(&map.root, &import.file) == normalized_path
                            && changes.current_lines.iter().any(|line| {
                                import.span.start_line <= *line && *line <= import.span.end_line
                            })
                    })
                    .map(|import| SemanticConflictImport {
                        path: import.path.clone(),
                        alias: import.alias.clone(),
                        glob: import.glob,
                        visibility: import.visibility.clone(),
                    }),
            )
            .collect::<Vec<_>>();
    imports.sort();
    imports.dedup();
    imports
}

fn semantic_import_only(
    map: Option<&repo_semantic::SemanticRepoMap>,
    path: &Path,
    changes: &FilePatchChanges,
    touched_imports: &[SemanticConflictImport],
) -> bool {
    let meaningful = changes
        .changed_text()
        .filter(|line| meaningful_line(line))
        .collect::<Vec<_>>();
    if meaningful.is_empty() {
        return false;
    }
    if meaningful.iter().all(|line| import_line(line)) {
        return true;
    }
    let Some(map) = map else {
        return false;
    };
    if touched_imports.is_empty() || changes.current_lines.is_empty() {
        return false;
    }
    let normalized_path = normalize_map_path(&map.root, path);
    changes.current_lines.iter().all(|line| {
        map.imports.iter().any(|import| {
            normalize_map_path(&map.root, &import.file) == normalized_path
                && import.span.start_line <= *line
                && *line <= import.span.end_line
        }) || map.re_exports.iter().any(|import| {
            normalize_map_path(&map.root, &import.file) == normalized_path
                && import.span.start_line <= *line
                && *line <= import.span.end_line
        })
    }) && changes
        .removed_text
        .iter()
        .map(|(_, text)| text.as_str())
        .filter(|line| meaningful_line(line))
        .all(import_line)
}

fn meaningful_line(line: &str) -> bool {
    let line = line.trim();
    !line.is_empty() && !line.starts_with("//")
}

fn import_line(line: &str) -> bool {
    let line = line.trim_start();
    line.starts_with("use ")
        || line.starts_with("pub use ")
        || line.starts_with("pub(crate) use ")
        || line.starts_with("pub(super) use ")
        || line.starts_with("pub(self) use ")
        || line.starts_with("extern crate ")
}

fn signature_changed(symbol: &SemanticSymbol, changes: &FilePatchChanges) -> bool {
    changes
        .added_text
        .iter()
        .filter(|(line, _)| *line == symbol.span.start_line)
        .any(|(_, line)| line_mentions_signature(line, symbol))
        || changes
            .removed_text
            .iter()
            .any(|(_, line)| line_mentions_signature(line, symbol))
}

fn line_mentions_signature(line: &str, symbol: &SemanticSymbol) -> bool {
    let line = line.trim_start();
    match symbol.kind {
        SemanticSymbolKind::Function | SemanticSymbolKind::Method => {
            line.contains(&format!("fn {}", symbol.name))
        }
        SemanticSymbolKind::Struct => line.contains(&format!("struct {}", symbol.name)),
        SemanticSymbolKind::Enum => line.contains(&format!("enum {}", symbol.name)),
        SemanticSymbolKind::Trait => line.contains(&format!("trait {}", symbol.name)),
        SemanticSymbolKind::Module => line.contains(&format!("mod {}", symbol.name)),
        SemanticSymbolKind::Const => line.contains(&format!("const {}", symbol.name)),
        SemanticSymbolKind::TypeAlias => line.contains(&format!("type {}", symbol.name)),
        SemanticSymbolKind::Impl => line.starts_with("impl "),
    }
}

fn semantic_conflict_symbol(symbol: &SemanticSymbol) -> SemanticConflictSymbol {
    SemanticConflictSymbol {
        name: symbol.name.clone(),
        qualified_path: symbol.qualified_path.clone(),
        kind: symbol.kind,
        visibility: symbol.visibility.clone(),
        impl_target: symbol.impl_target.clone(),
        impl_trait: symbol.impl_trait.clone(),
        file: symbol.file.clone(),
    }
}

fn semantic_symbol_key(
    symbol: &SemanticSymbol,
) -> (
    PathBuf,
    SemanticSymbolKind,
    Vec<String>,
    Option<String>,
    Option<String>,
) {
    (
        symbol.file.clone(),
        symbol.kind,
        symbol.qualified_path.clone(),
        symbol.impl_target.clone(),
        symbol.impl_trait.clone(),
    )
}

fn conflict_symbol_key(
    symbol: &SemanticConflictSymbol,
) -> (
    PathBuf,
    SemanticSymbolKind,
    Vec<String>,
    Option<String>,
    Option<String>,
) {
    (
        symbol.file.clone(),
        symbol.kind,
        symbol.qualified_path.clone(),
        symbol.impl_target.clone(),
        symbol.impl_trait.clone(),
    )
}

fn common_touched_symbols(
    primary: &[SemanticConflictSymbol],
    candidate: &[SemanticConflictSymbol],
) -> Vec<SemanticConflictSymbol> {
    let candidate_keys = candidate
        .iter()
        .map(conflict_symbol_key)
        .collect::<BTreeSet<_>>();
    let mut common = primary
        .iter()
        .filter(|symbol| candidate_keys.contains(&conflict_symbol_key(symbol)))
        .cloned()
        .collect::<Vec<_>>();
    common.sort();
    common.dedup();
    common
}

fn overlap_kind(
    primary: &SemanticConflictSide,
    candidate: &SemanticConflictSide,
    common_symbols: &[SemanticConflictSymbol],
    common_impls: &[SemanticConflictSymbol],
    common_modules: &[String],
) -> SemanticConflictOverlapKind {
    if primary.import_only && candidate.import_only {
        SemanticConflictOverlapKind::ImportOnly
    } else if primary.formatting_only && candidate.formatting_only {
        SemanticConflictOverlapKind::FormattingOnly
    } else if primary.signature_level || candidate.signature_level {
        SemanticConflictOverlapKind::SignatureLevel
    } else if !common_symbols.is_empty() {
        SemanticConflictOverlapKind::SymbolLevel
    } else if !common_impls.is_empty() {
        SemanticConflictOverlapKind::ImplLevel
    } else if !common_modules.is_empty() {
        SemanticConflictOverlapKind::ModuleLevel
    } else if !primary.touched_symbols.is_empty()
        || !candidate.touched_symbols.is_empty()
        || !primary.touched_impls.is_empty()
        || !candidate.touched_impls.is_empty()
    {
        SemanticConflictOverlapKind::FileLevel
    } else {
        SemanticConflictOverlapKind::Unresolved
    }
}

fn overlap_risk(kind: SemanticConflictOverlapKind) -> SemanticConflictRisk {
    match kind {
        SemanticConflictOverlapKind::ImportOnly | SemanticConflictOverlapKind::FormattingOnly => {
            SemanticConflictRisk::Low
        }
        SemanticConflictOverlapKind::SignatureLevel => SemanticConflictRisk::High,
        SemanticConflictOverlapKind::SymbolLevel
        | SemanticConflictOverlapKind::ImplLevel
        | SemanticConflictOverlapKind::ModuleLevel
        | SemanticConflictOverlapKind::FileLevel => SemanticConflictRisk::Medium,
        SemanticConflictOverlapKind::Unresolved => SemanticConflictRisk::Unknown,
    }
}

fn overlap_confidence(
    kind: SemanticConflictOverlapKind,
    notes: &[String],
) -> SemanticConflictConfidence {
    if kind == SemanticConflictOverlapKind::Unresolved {
        SemanticConflictConfidence::None
    } else if notes.is_empty() {
        SemanticConflictConfidence::High
    } else {
        SemanticConflictConfidence::Low
    }
}

fn aggregate_risk(overlaps: &[SemanticConflictOverlap]) -> SemanticConflictRisk {
    if overlaps
        .iter()
        .any(|overlap| overlap.risk == SemanticConflictRisk::Unknown)
    {
        SemanticConflictRisk::Unknown
    } else if overlaps
        .iter()
        .any(|overlap| overlap.risk == SemanticConflictRisk::High)
    {
        SemanticConflictRisk::High
    } else if overlaps
        .iter()
        .any(|overlap| overlap.risk == SemanticConflictRisk::Medium)
    {
        SemanticConflictRisk::Medium
    } else if overlaps
        .iter()
        .any(|overlap| overlap.risk == SemanticConflictRisk::Low)
    {
        SemanticConflictRisk::Low
    } else {
        SemanticConflictRisk::None
    }
}

fn dependency_impacts_for_path(
    primary: Option<&SemanticRiskReport>,
    candidate: Option<&SemanticRiskReport>,
    path: &Path,
) -> (Vec<PathBuf>, Vec<SemanticConflictDependencyImpact>) {
    let mut impacted_files = BTreeSet::new();
    let mut impacts = Vec::new();
    for (side, report) in [
        (SemanticConflictDependencySide::Primary, primary),
        (SemanticConflictDependencySide::Candidate, candidate),
    ] {
        let Some(report) = report else {
            continue;
        };
        for impact in report
            .dependency_impacts
            .iter()
            .filter(|impact| impact.changed_path == path)
        {
            if let Some(related) = &impact.related_file {
                impacted_files.insert(related.clone());
            }
            impacts.push(SemanticConflictDependencyImpact {
                side,
                impact: impact.clone(),
            });
        }
    }
    impacts.sort_by(|left, right| {
        left.side
            .cmp(&right.side)
            .then_with(|| left.impact.changed_path.cmp(&right.impact.changed_path))
            .then_with(|| left.impact.direction.cmp(&right.impact.direction))
            .then_with(|| left.impact.related_file.cmp(&right.impact.related_file))
            .then_with(|| {
                left.impact
                    .dependency
                    .from_file
                    .cmp(&right.impact.dependency.from_file)
            })
            .then_with(|| {
                left.impact
                    .dependency
                    .kind
                    .cmp(&right.impact.dependency.kind)
            })
            .then_with(|| left.impact.dependency.to.cmp(&right.impact.dependency.to))
    });
    (impacted_files.into_iter().collect(), impacts)
}

fn normalize_map_path(root: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.strip_prefix(root)
            .map(Path::to_path_buf)
            .unwrap_or_else(|_| path.to_path_buf())
    } else {
        path.to_path_buf()
    }
}

fn line_ranges(lines: &BTreeSet<usize>) -> Vec<SemanticConflictLineRange> {
    let mut ranges = Vec::new();
    let mut current: Option<SemanticConflictLineRange> = None;
    for line in lines {
        match current.as_mut() {
            Some(range) if range.end_line.checked_add(1) == Some(*line) => {
                range.end_line = *line;
            }
            Some(_) => {
                if let Some(range) = current.take() {
                    ranges.push(range);
                }
                current = Some(SemanticConflictLineRange {
                    start_line: *line,
                    end_line: *line,
                });
            }
            None => {
                current = Some(SemanticConflictLineRange {
                    start_line: *line,
                    end_line: *line,
                });
            }
        }
    }
    if let Some(range) = current {
        ranges.push(range);
    }
    ranges
}

fn truncate_items<T>(mut items: Vec<T>, label: &str, notes: &mut Vec<String>) -> Vec<T> {
    if items.len() > SEMANTIC_CONFLICT_MAX_ITEMS {
        notes.push(format!(
            "semantic conflict classification truncated {label} to {SEMANTIC_CONFLICT_MAX_ITEMS}"
        ));
        items.truncate(SEMANTIC_CONFLICT_MAX_ITEMS);
    }
    items
}

fn bounded_notes(mut notes: Vec<String>) -> Vec<String> {
    notes.sort();
    notes.dedup();
    if notes.len() > SEMANTIC_CONFLICT_MAX_NOTES {
        notes.truncate(SEMANTIC_CONFLICT_MAX_NOTES.saturating_sub(1));
        notes.push(format!(
            "semantic conflict classification truncated notes to {SEMANTIC_CONFLICT_MAX_NOTES}"
        ));
    }
    notes
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(number: usize, text: &str) -> (usize, String) {
        (number, text.to_string())
    }

    #[test]
    fn formatting_only_is_conservative_about_internal_whitespace() {
        let indentation = FilePatchChanges {
            added_text: vec![line(1, "    value();\n")],
            removed_text: vec![line(1, "value();\n")],
            ..FilePatchChanges::default()
        };
        assert!(indentation.formatting_only());

        let literal_change = FilePatchChanges {
            added_text: vec![line(1, "let value = \"ab\";\n")],
            removed_text: vec![line(1, "let value = \"a b\";\n")],
            ..FilePatchChanges::default()
        };
        assert!(!literal_change.formatting_only());
    }

    #[test]
    fn structured_patch_collection_tracks_current_and_base_lines() {
        let patch = b"diff --git a/src/lib.rs b/src/lib.rs\nindex 1111111..2222222 100644\n--- a/src/lib.rs\n+++ b/src/lib.rs\n@@ -2 +2 @@\n-    1\n+    2\n";
        let diff = Diff::from_buffer(patch).expect("parse test patch");
        let changes = collect_diff_changes(&diff, &[PathBuf::from("src/lib.rs")], "candidate")
            .expect("collect structured diff");
        let file = changes.paths.get(Path::new("src/lib.rs")).expect("path");

        assert_eq!(file.current_lines, BTreeSet::from([2]));
        assert_eq!(file.base_lines, BTreeSet::from([2]));
        assert_eq!(file.added_text, vec![line(2, "    2\n")]);
        assert_eq!(file.removed_text, vec![line(2, "    1\n")]);
    }

    #[test]
    fn import_only_and_formatting_only_are_low_risk() {
        assert_eq!(
            overlap_risk(SemanticConflictOverlapKind::ImportOnly),
            SemanticConflictRisk::Low
        );
        assert_eq!(
            overlap_risk(SemanticConflictOverlapKind::FormattingOnly),
            SemanticConflictRisk::Low
        );
    }
}
