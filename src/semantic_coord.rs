use crate::{
    repo_semantic::{self, SemanticRepoMap, SemanticScanError, SemanticSymbol, SemanticSymbolKind},
    sync::normalize_repo_relative_path,
};
use anyhow::{bail, Context, Result};
use git2::Repository;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{ErrorKind, Write},
    path::{Path, PathBuf},
    process::{self, Command},
    thread,
    time::Duration,
};

const STATE_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
#[serde(transparent)]
pub struct SemanticIntentToken(u64);

impl SemanticIntentToken {
    pub fn from_u64(value: u64) -> Self {
        Self(value)
    }

    pub fn get(self) -> u64 {
        self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct SemanticIntentRequest {
    pub agent_id: String,
    pub paths: Vec<PathBuf>,
    pub symbols: Vec<String>,
    pub modules: Vec<String>,
    pub task_file: Option<PathBuf>,
    pub notes: Vec<String>,
}

impl SemanticIntentRequest {
    pub fn new(agent_id: impl Into<String>) -> Self {
        Self {
            agent_id: agent_id.into(),
            paths: Vec::new(),
            symbols: Vec::new(),
            modules: Vec::new(),
            task_file: None,
            notes: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct SemanticIntent {
    pub token: SemanticIntentToken,
    pub agent_id: String,
    pub paths: Vec<PathBuf>,
    pub symbols: Vec<ResolvedSemanticSymbol>,
    pub modules: Vec<String>,
    pub impacted_files: Vec<PathBuf>,
    pub task_digest: Option<String>,
    pub task_excerpt: Option<String>,
    pub notes: Vec<String>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct ResolvedSemanticSymbol {
    pub id: String,
    pub qualified_path: String,
    pub name: String,
    pub kind: String,
    pub file: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticConflictSeverity {
    Blocking,
    Advisory,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticConflictKind {
    PathOverlap,
    SymbolOverlap,
    ModuleOverlap,
    ModuleHierarchyOverlap,
    ModuleSymbolOverlap,
    ImpactedFileOverlapsActivePath,
    PathOverlapsActiveImpact,
    SemanticScanCaveat,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct SemanticConflict {
    pub severity: SemanticConflictSeverity,
    pub kind: SemanticConflictKind,
    pub requested_token: SemanticIntentToken,
    pub active_token: Option<SemanticIntentToken>,
    pub active_agent_id: Option<String>,
    pub path: Option<PathBuf>,
    pub module: Option<String>,
    pub symbol_id: Option<String>,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct SemanticCoordinationReport {
    pub intent: SemanticIntent,
    pub conflicts: Vec<SemanticConflict>,
    pub has_blocking_conflicts: bool,
    pub has_advisory_conflicts: bool,
    pub blocking_conflict_count: usize,
    pub advisory_conflict_count: usize,
    pub persisted: bool,
    pub active_intent_count: usize,
}

#[derive(Debug, Clone)]
pub struct SemanticIntentStore {
    repo_root: PathBuf,
    state_path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
struct PersistedSemanticState {
    version: u32,
    next_token: u64,
    intents: Vec<SemanticIntent>,
}

impl Default for PersistedSemanticState {
    fn default() -> Self {
        Self {
            version: STATE_VERSION,
            next_token: 1,
            intents: Vec::new(),
        }
    }
}

impl SemanticIntentStore {
    pub fn open(repo_path: impl AsRef<Path>) -> Result<Self> {
        let repo = Repository::discover(repo_path.as_ref()).with_context(|| {
            format!(
                "failed to discover repository from {}",
                repo_path.as_ref().display()
            )
        })?;
        let repo_root = repo
            .workdir()
            .context("semantic intent store requires a non-bare repository")?
            .to_path_buf();
        Ok(Self {
            repo_root,
            state_path: repo
                .commondir()
                .join("maco")
                .join("state")
                .join("semantic_intents.json"),
        })
    }

    pub fn state_path(&self) -> &Path {
        &self.state_path
    }

    pub fn preview(&self, request: SemanticIntentRequest) -> Result<SemanticCoordinationReport> {
        self.preview_with_additional_active(request, &[])
    }

    pub fn preview_with_additional_active(
        &self,
        request: SemanticIntentRequest,
        additional_active: &[SemanticIntent],
    ) -> Result<SemanticCoordinationReport> {
        self.with_locked_read(|state| {
            let token_offset = u64::try_from(additional_active.len())
                .context("additional semantic preview intent count does not fit in token space")?;
            let preview_token = state
                .next_token
                .checked_add(token_offset)
                .context("semantic intent preview token space is exhausted")?;
            let active_capacity = state
                .intents
                .len()
                .checked_add(additional_active.len())
                .context("active semantic intent count overflow")?;
            let mut active = Vec::with_capacity(active_capacity);
            active.extend(state.intents.iter().cloned());
            active.extend(additional_active.iter().cloned());

            let intent = self.build_intent(request, SemanticIntentToken(preview_token))?;
            Ok(report_for_intent(intent, &active, false))
        })
    }

    pub fn claim(&self, request: SemanticIntentRequest) -> Result<SemanticCoordinationReport> {
        self.with_locked_update(|state| {
            let token = SemanticIntentToken(state.next_token);
            let intent = self.build_intent(request, token)?;
            let conflicts = conflicts_for_intent(&intent, &state.intents);
            let has_blocking_conflicts = conflicts
                .iter()
                .any(|conflict| conflict.severity == SemanticConflictSeverity::Blocking);
            if has_blocking_conflicts {
                return Ok(report_from_parts(
                    intent,
                    conflicts,
                    false,
                    state.intents.len(),
                ));
            }

            state.next_token = state
                .next_token
                .checked_add(1)
                .context("semantic intent token space is exhausted")?;
            state.intents.push(intent.clone());
            normalize_state(state);
            Ok(report_from_parts(
                intent,
                conflicts,
                true,
                state.intents.len(),
            ))
        })
    }

    pub fn release(&self, token: SemanticIntentToken) -> Result<SemanticIntent> {
        self.with_locked_update(|state| {
            let Some(index) = state
                .intents
                .iter()
                .position(|intent| intent.token == token)
            else {
                bail!("semantic intent token is not active: {}", token.get());
            };
            Ok(state.intents.remove(index))
        })
    }

    pub fn release_by_agent(&self, agent_id: impl AsRef<str>) -> Result<Vec<SemanticIntent>> {
        let agent_id = normalize_agent_id(agent_id.as_ref())?;
        self.with_locked_update(|state| {
            let mut released = Vec::new();
            state.intents.retain(|intent| {
                if intent.agent_id == agent_id {
                    released.push(intent.clone());
                    false
                } else {
                    true
                }
            });
            released.sort_by_key(|intent| intent.token);
            Ok(released)
        })
    }

    pub fn snapshot(&self) -> Result<Vec<SemanticIntent>> {
        self.with_locked_read(|state| Ok(state.intents.clone()))
    }

    pub fn status(&self) -> Result<Vec<SemanticIntent>> {
        self.snapshot()
    }

    fn with_locked_update<T>(
        &self,
        operation: impl FnOnce(&mut PersistedSemanticState) -> Result<T>,
    ) -> Result<T> {
        let _lock = StateLock::acquire(&self.state_path)?;
        let mut state = self.load_state()?;
        let output = operation(&mut state)?;
        self.save_state(&mut state)?;
        Ok(output)
    }

    fn with_locked_read<T>(
        &self,
        operation: impl FnOnce(&PersistedSemanticState) -> Result<T>,
    ) -> Result<T> {
        let _lock = StateLock::acquire(&self.state_path)?;
        let state = self.load_state()?;
        operation(&state)
    }

    fn load_state(&self) -> Result<PersistedSemanticState> {
        let contents = match fs::read_to_string(&self.state_path) {
            Ok(contents) => contents,
            Err(error) if error.kind() == ErrorKind::NotFound => {
                return Ok(PersistedSemanticState::default())
            }
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "failed to read semantic intent state {}",
                        self.state_path.display()
                    )
                })
            }
        };

        let mut state: PersistedSemanticState =
            serde_json::from_str(&contents).with_context(|| {
                format!(
                    "failed to parse semantic intent state {}",
                    self.state_path.display()
                )
            })?;
        if state.version != STATE_VERSION {
            bail!(
                "unsupported semantic intent state version {} in {}",
                state.version,
                self.state_path.display()
            );
        }
        normalize_state(&mut state);
        Ok(state)
    }

    fn save_state(&self, state: &mut PersistedSemanticState) -> Result<()> {
        let parent = self
            .state_path
            .parent()
            .context("semantic intent state path must have a parent directory")?;
        fs::create_dir_all(parent).with_context(|| {
            format!(
                "failed to create semantic intent state directory {}",
                parent.display()
            )
        })?;

        normalize_state(state);
        let temp_path = temp_state_path(&self.state_path);
        let result = write_state_file(&temp_path, &self.state_path, state);
        if result.is_err() {
            let _ = fs::remove_file(&temp_path);
        }
        result
    }

    fn build_intent(
        &self,
        request: SemanticIntentRequest,
        token: SemanticIntentToken,
    ) -> Result<SemanticIntent> {
        let agent_id = normalize_agent_id(&request.agent_id)?;
        let paths = normalize_paths(request.paths)?;
        let notes = sorted_unique_strings(request.notes);

        if paths.is_empty() && request.symbols.is_empty() && request.modules.is_empty() {
            bail!("semantic intent must include at least one path, symbol, or module");
        }

        let map = repo_semantic::scan_repository(&self.repo_root)?;
        let symbols = resolve_symbols(&map, &request.symbols)?;
        let modules = resolve_modules(&map, &request.modules)?;
        let impact_sources = impact_source_paths(&map, &paths, &symbols, &modules);
        let risk_report = repo_semantic::risk_report_for_paths(&map, impact_sources.iter());
        let mut warnings = scan_warnings(&map.errors);
        warnings.extend(scan_warnings(&risk_report.errors));

        let mut impacted_files = risk_report
            .impacted_files
            .into_iter()
            .map(normalize_repo_relative_path)
            .collect::<std::result::Result<BTreeSet<_>, _>>()?
            .into_iter()
            .collect::<Vec<_>>();
        impacted_files.sort();

        let (task_digest, task_excerpt, task_warnings) = self.task_summary(request.task_file)?;
        warnings.extend(task_warnings);
        warnings.sort();
        warnings.dedup();

        Ok(SemanticIntent {
            token,
            agent_id,
            paths,
            symbols,
            modules,
            impacted_files,
            task_digest,
            task_excerpt,
            notes,
            warnings,
        })
    }

    fn task_summary(
        &self,
        task_file: Option<PathBuf>,
    ) -> Result<(Option<String>, Option<String>, Vec<String>)> {
        let Some(task_file) = task_file else {
            return Ok((None, None, Vec::new()));
        };
        let task_file = normalize_repo_relative_path(task_file)?;
        let full_path = self.repo_root.join(&task_file);
        let contents = match fs::read_to_string(&full_path) {
            Ok(contents) => contents,
            Err(error) => {
                return Ok((
                    None,
                    None,
                    vec![format!(
                        "failed to read task file {}: {error}",
                        task_file.display()
                    )],
                ))
            }
        };

        Ok((
            Some(stable_digest(contents.as_bytes())),
            Some(excerpt(&contents)),
            Vec::new(),
        ))
    }
}

fn report_for_intent(
    intent: SemanticIntent,
    active: &[SemanticIntent],
    persisted: bool,
) -> SemanticCoordinationReport {
    let conflicts = conflicts_for_intent(&intent, active);
    report_from_parts(intent, conflicts, persisted, active.len())
}

fn report_from_parts(
    intent: SemanticIntent,
    mut conflicts: Vec<SemanticConflict>,
    persisted: bool,
    active_intent_count: usize,
) -> SemanticCoordinationReport {
    sort_conflicts(&mut conflicts);
    let blocking_conflict_count = conflicts
        .iter()
        .filter(|conflict| conflict.severity == SemanticConflictSeverity::Blocking)
        .count();
    let advisory_conflict_count = conflicts.len().saturating_sub(blocking_conflict_count);

    SemanticCoordinationReport {
        intent,
        conflicts,
        has_blocking_conflicts: blocking_conflict_count > 0,
        has_advisory_conflicts: advisory_conflict_count > 0,
        blocking_conflict_count,
        advisory_conflict_count,
        persisted,
        active_intent_count,
    }
}

fn conflicts_for_intent(
    requested: &SemanticIntent,
    active: &[SemanticIntent],
) -> Vec<SemanticConflict> {
    let mut conflicts = Vec::new();
    for existing in active {
        path_conflicts(requested, existing, &mut conflicts);
        symbol_conflicts(requested, existing, &mut conflicts);
        module_conflicts(requested, existing, &mut conflicts);
        advisory_impact_conflicts(requested, existing, &mut conflicts);
    }

    for warning in &requested.warnings {
        if warning.starts_with("semantic scan ") {
            conflicts.push(SemanticConflict {
                severity: SemanticConflictSeverity::Advisory,
                kind: SemanticConflictKind::SemanticScanCaveat,
                requested_token: requested.token,
                active_token: None,
                active_agent_id: None,
                path: None,
                module: None,
                symbol_id: None,
                message: warning.clone(),
            });
        }
    }

    sort_conflicts(&mut conflicts);
    conflicts.dedup();
    conflicts
}

fn path_conflicts(
    requested: &SemanticIntent,
    existing: &SemanticIntent,
    conflicts: &mut Vec<SemanticConflict>,
) {
    for requested_path in &requested.paths {
        for active_path in &existing.paths {
            if paths_overlap(requested_path, active_path) {
                conflicts.push(SemanticConflict {
                    severity: SemanticConflictSeverity::Blocking,
                    kind: SemanticConflictKind::PathOverlap,
                    requested_token: requested.token,
                    active_token: Some(existing.token),
                    active_agent_id: Some(existing.agent_id.clone()),
                    path: Some(active_path.clone()),
                    module: None,
                    symbol_id: None,
                    message: format!(
                        "path {} overlaps active intent {} path {}",
                        requested_path.display(),
                        existing.token.get(),
                        active_path.display()
                    ),
                });
            }
        }
    }
}

fn symbol_conflicts(
    requested: &SemanticIntent,
    existing: &SemanticIntent,
    conflicts: &mut Vec<SemanticConflict>,
) {
    let active_symbols = existing
        .symbols
        .iter()
        .map(|symbol| (&symbol.id, symbol))
        .collect::<BTreeMap<_, _>>();
    for symbol in &requested.symbols {
        if active_symbols.contains_key(&symbol.id) {
            conflicts.push(SemanticConflict {
                severity: SemanticConflictSeverity::Blocking,
                kind: SemanticConflictKind::SymbolOverlap,
                requested_token: requested.token,
                active_token: Some(existing.token),
                active_agent_id: Some(existing.agent_id.clone()),
                path: Some(symbol.file.clone()),
                module: None,
                symbol_id: Some(symbol.id.clone()),
                message: format!(
                    "symbol {} overlaps active intent {}",
                    symbol.qualified_path,
                    existing.token.get()
                ),
            });
        }
    }
}

fn module_conflicts(
    requested: &SemanticIntent,
    existing: &SemanticIntent,
    conflicts: &mut Vec<SemanticConflict>,
) {
    for requested_module in &requested.modules {
        for active_module in &existing.modules {
            if requested_module == active_module {
                conflicts.push(SemanticConflict {
                    severity: SemanticConflictSeverity::Blocking,
                    kind: SemanticConflictKind::ModuleOverlap,
                    requested_token: requested.token,
                    active_token: Some(existing.token),
                    active_agent_id: Some(existing.agent_id.clone()),
                    path: None,
                    module: Some(active_module.clone()),
                    symbol_id: None,
                    message: format!(
                        "module {requested_module} overlaps active intent {}",
                        existing.token.get()
                    ),
                });
            } else if modules_overlap(requested_module, active_module) {
                conflicts.push(SemanticConflict {
                    severity: SemanticConflictSeverity::Blocking,
                    kind: SemanticConflictKind::ModuleHierarchyOverlap,
                    requested_token: requested.token,
                    active_token: Some(existing.token),
                    active_agent_id: Some(existing.agent_id.clone()),
                    path: None,
                    module: Some(active_module.clone()),
                    symbol_id: None,
                    message: format!(
                        "module {requested_module} has parent/child overlap with active intent {} module {active_module}",
                        existing.token.get()
                    ),
                });
            }
        }

        for active_symbol in &existing.symbols {
            if module_overlaps_symbol(requested_module, active_symbol) {
                conflicts.push(module_symbol_conflict(
                    requested,
                    existing,
                    requested_module,
                    active_symbol,
                    "requested module contains active symbol",
                ));
            }
        }
    }

    for requested_symbol in &requested.symbols {
        for active_module in &existing.modules {
            if module_overlaps_symbol(active_module, requested_symbol) {
                conflicts.push(module_symbol_conflict(
                    requested,
                    existing,
                    active_module,
                    requested_symbol,
                    "active module contains requested symbol",
                ));
            }
        }
    }
}

fn module_symbol_conflict(
    requested: &SemanticIntent,
    existing: &SemanticIntent,
    module: &str,
    symbol: &ResolvedSemanticSymbol,
    reason: &str,
) -> SemanticConflict {
    SemanticConflict {
        severity: SemanticConflictSeverity::Blocking,
        kind: SemanticConflictKind::ModuleSymbolOverlap,
        requested_token: requested.token,
        active_token: Some(existing.token),
        active_agent_id: Some(existing.agent_id.clone()),
        path: Some(symbol.file.clone()),
        module: Some(module.to_string()),
        symbol_id: Some(symbol.id.clone()),
        message: format!(
            "{reason}: module {module}, symbol {}",
            symbol.qualified_path
        ),
    }
}

fn advisory_impact_conflicts(
    requested: &SemanticIntent,
    existing: &SemanticIntent,
    conflicts: &mut Vec<SemanticConflict>,
) {
    for impacted in &requested.impacted_files {
        for active_path in &existing.paths {
            if paths_overlap(impacted, active_path) {
                conflicts.push(SemanticConflict {
                    severity: SemanticConflictSeverity::Advisory,
                    kind: SemanticConflictKind::ImpactedFileOverlapsActivePath,
                    requested_token: requested.token,
                    active_token: Some(existing.token),
                    active_agent_id: Some(existing.agent_id.clone()),
                    path: Some(impacted.clone()),
                    module: None,
                    symbol_id: None,
                    message: format!(
                        "impacted file {} overlaps active intent {} path {}",
                        impacted.display(),
                        existing.token.get(),
                        active_path.display()
                    ),
                });
            }
        }
    }

    for requested_path in &requested.paths {
        for active_impact in &existing.impacted_files {
            if paths_overlap(requested_path, active_impact) {
                conflicts.push(SemanticConflict {
                    severity: SemanticConflictSeverity::Advisory,
                    kind: SemanticConflictKind::PathOverlapsActiveImpact,
                    requested_token: requested.token,
                    active_token: Some(existing.token),
                    active_agent_id: Some(existing.agent_id.clone()),
                    path: Some(requested_path.clone()),
                    module: None,
                    symbol_id: None,
                    message: format!(
                        "requested path {} overlaps active intent {} impacted file {}",
                        requested_path.display(),
                        existing.token.get(),
                        active_impact.display()
                    ),
                });
            }
        }
    }
}

fn resolve_symbols(
    map: &SemanticRepoMap,
    requested: &[String],
) -> Result<Vec<ResolvedSemanticSymbol>> {
    let mut resolved = BTreeMap::new();
    for query in sorted_unique_strings(requested.iter().cloned()) {
        let symbol = resolve_symbol(map, &query)?;
        resolved.insert(symbol.id.clone(), symbol);
    }
    let mut symbols = resolved.into_values().collect::<Vec<_>>();
    sort_symbols(&mut symbols);
    Ok(symbols)
}

fn resolve_symbol(map: &SemanticRepoMap, query: &str) -> Result<ResolvedSemanticSymbol> {
    let trimmed = query.trim();
    if trimmed.is_empty() {
        bail!("symbol query cannot be empty");
    }

    if let Some(symbol) = map.symbols.iter().find(|symbol| symbol.id == trimmed) {
        return Ok(resolved_symbol(symbol));
    }

    let normalized_path = normalize_symbol_path(trimmed);
    if let Some(symbol) = map
        .symbols
        .iter()
        .find(|symbol| symbol.qualified_path.join("::") == normalized_path)
    {
        return Ok(resolved_symbol(symbol));
    }

    let matches = map
        .symbols
        .iter()
        .filter(|symbol| symbol.name == trimmed)
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [symbol] => Ok(resolved_symbol(symbol)),
        [] => bail!("unresolved semantic symbol: {trimmed}"),
        _ => {
            let mut candidates = matches
                .iter()
                .map(|symbol| {
                    format!(
                        "{} [{}] {}",
                        symbol.qualified_path.join("::"),
                        symbol.id,
                        symbol.file.display()
                    )
                })
                .collect::<Vec<_>>();
            candidates.sort();
            bail!(
                "ambiguous semantic symbol {trimmed}; candidates: {}",
                candidates.join(", ")
            );
        }
    }
}

fn resolved_symbol(symbol: &SemanticSymbol) -> ResolvedSemanticSymbol {
    ResolvedSemanticSymbol {
        id: symbol.id.clone(),
        qualified_path: symbol.qualified_path.join("::"),
        name: symbol.name.clone(),
        kind: symbol_kind_name(symbol.kind).to_string(),
        file: symbol.file.clone(),
    }
}

fn resolve_modules(map: &SemanticRepoMap, requested: &[String]) -> Result<Vec<String>> {
    let mut existing = BTreeSet::new();
    for file in &map.files {
        existing.insert(file.module_path.join("::"));
    }
    for symbol in &map.symbols {
        if symbol.kind == SemanticSymbolKind::Module {
            existing.insert(symbol.qualified_path.join("::"));
        }
    }

    let mut resolved = BTreeSet::new();
    for query in sorted_unique_strings(requested.iter().cloned()) {
        let normalized = normalize_module_path(&query)?;
        if !existing.contains(&normalized) {
            bail!("unresolved semantic module: {query} (normalized: {normalized})");
        }
        resolved.insert(normalized);
    }
    Ok(resolved.into_iter().collect())
}

fn impact_source_paths(
    map: &SemanticRepoMap,
    paths: &[PathBuf],
    symbols: &[ResolvedSemanticSymbol],
    modules: &[String],
) -> Vec<PathBuf> {
    let mut sources = paths.iter().cloned().collect::<BTreeSet<_>>();
    sources.extend(symbols.iter().map(|symbol| symbol.file.clone()));
    sources.extend(module_source_files(map, modules));
    sources.into_iter().collect()
}

fn module_source_files(map: &SemanticRepoMap, modules: &[String]) -> BTreeSet<PathBuf> {
    let mut sources = BTreeSet::new();
    for file in &map.files {
        let file_module = file.module_path.join("::");
        if modules
            .iter()
            .any(|module| module_path_is_or_descendant(&file_module, module))
        {
            sources.insert(file.path.clone());
        }
    }
    for symbol in &map.symbols {
        let symbol_module = symbol.qualified_path.join("::");
        if symbol.kind == SemanticSymbolKind::Module && modules.contains(&symbol_module) {
            sources.insert(symbol.file.clone());
        }
    }
    sources
}

fn normalize_paths(paths: Vec<PathBuf>) -> Result<Vec<PathBuf>> {
    let paths = paths
        .into_iter()
        .map(normalize_repo_relative_path)
        .collect::<std::result::Result<BTreeSet<_>, _>>()?;
    Ok(collapse_covered_paths(paths))
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

fn normalize_agent_id(agent_id: &str) -> Result<String> {
    let trimmed = agent_id.trim();
    if trimmed.is_empty() {
        bail!("agent id cannot be empty");
    }
    if matches!(trimmed, "." | "..") {
        bail!("agent id may only contain ASCII letters, digits, '.', '_' and '-'");
    }
    if !trimmed
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        bail!("agent id may only contain ASCII letters, digits, '.', '_' and '-'");
    }
    Ok(trimmed.to_string())
}

fn sorted_unique_strings<I>(values: I) -> Vec<String>
where
    I: IntoIterator<Item = String>,
{
    values
        .into_iter()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn normalize_symbol_path(query: &str) -> String {
    query
        .split("::")
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join("::")
}

fn normalize_module_path(query: &str) -> Result<String> {
    let mut parts = query
        .trim()
        .split("::")
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .map(str::to_string)
        .collect::<Vec<_>>();
    if parts.is_empty() {
        bail!("module query cannot be empty");
    }
    if parts.first().is_some_and(|part| part != "crate") {
        parts.insert(0, "crate".to_string());
    }
    Ok(parts.join("::"))
}

fn scan_warnings(errors: &[SemanticScanError]) -> Vec<String> {
    errors
        .iter()
        .map(|error| {
            format!(
                "semantic scan {} error in {}: {}",
                scan_error_kind_name(error.kind),
                error.file.display(),
                error.message
            )
        })
        .collect()
}

fn symbol_kind_name(kind: SemanticSymbolKind) -> &'static str {
    match kind {
        SemanticSymbolKind::Module => "module",
        SemanticSymbolKind::Function => "function",
        SemanticSymbolKind::Struct => "struct",
        SemanticSymbolKind::Enum => "enum",
        SemanticSymbolKind::Trait => "trait",
        SemanticSymbolKind::Impl => "impl",
        SemanticSymbolKind::Method => "method",
        SemanticSymbolKind::Const => "const",
        SemanticSymbolKind::TypeAlias => "type_alias",
    }
}

fn scan_error_kind_name(kind: repo_semantic::SemanticScanErrorKind) -> &'static str {
    match kind {
        repo_semantic::SemanticScanErrorKind::Read => "read",
        repo_semantic::SemanticScanErrorKind::Parse => "parse",
    }
}

fn paths_overlap(left: &Path, right: &Path) -> bool {
    left == right || left.starts_with(right) || right.starts_with(left)
}

fn modules_overlap(left: &str, right: &str) -> bool {
    let left_parts = module_parts(left);
    let right_parts = module_parts(right);
    is_prefix(&left_parts, &right_parts) || is_prefix(&right_parts, &left_parts)
}

fn module_contains_symbol(module: &str, symbol_path: &str) -> bool {
    let requested_module_parts = module_parts(module);
    let symbol_parts = module_parts(symbol_path);
    symbol_parts.len() > requested_module_parts.len()
        && is_prefix(&requested_module_parts, &symbol_parts)
}

fn module_overlaps_symbol(module: &str, symbol: &ResolvedSemanticSymbol) -> bool {
    let requested_module_parts = module_parts(module);
    let symbol_parts = module_parts(&symbol.qualified_path);
    if symbol.kind == symbol_kind_name(SemanticSymbolKind::Module)
        && requested_module_parts == symbol_parts
    {
        return true;
    }
    module_contains_symbol(module, &symbol.qualified_path)
}

fn module_path_is_or_descendant(candidate: &str, parent: &str) -> bool {
    let candidate_parts = module_parts(candidate);
    let parent_parts = module_parts(parent);
    candidate_parts == parent_parts
        || (candidate_parts.len() > parent_parts.len()
            && candidate_parts.starts_with(&parent_parts))
}

fn module_parts(path: &str) -> Vec<&str> {
    path.split("::").filter(|part| !part.is_empty()).collect()
}

fn is_prefix(left: &[&str], right: &[&str]) -> bool {
    left.len() < right.len() && right.starts_with(left)
}

fn sort_conflicts(conflicts: &mut [SemanticConflict]) {
    conflicts.sort_by(|left, right| {
        left.severity
            .cmp(&right.severity)
            .then_with(|| left.kind.cmp(&right.kind))
            .then_with(|| left.active_token.cmp(&right.active_token))
            .then_with(|| left.active_agent_id.cmp(&right.active_agent_id))
            .then_with(|| left.path.cmp(&right.path))
            .then_with(|| left.module.cmp(&right.module))
            .then_with(|| left.symbol_id.cmp(&right.symbol_id))
            .then_with(|| left.message.cmp(&right.message))
    });
}

fn normalize_state(state: &mut PersistedSemanticState) {
    state.version = STATE_VERSION;
    for intent in &mut state.intents {
        normalize_intent(intent);
    }
    state.intents.sort_by_key(|intent| intent.token);
    state.intents.dedup_by_key(|intent| intent.token);
    let next_from_intents = state
        .intents
        .iter()
        .map(|intent| intent.token.get().saturating_add(1))
        .max()
        .unwrap_or(1);
    state.next_token = state.next_token.max(next_from_intents).max(1);
}

fn normalize_intent(intent: &mut SemanticIntent) {
    intent.paths = collapse_covered_paths(intent.paths.iter().cloned().collect());
    sort_symbols(&mut intent.symbols);
    intent.symbols.dedup_by(|left, right| left.id == right.id);
    intent.modules = sorted_unique_strings(intent.modules.iter().cloned());
    intent.impacted_files.sort();
    intent.impacted_files.dedup();
    intent.notes = sorted_unique_strings(intent.notes.iter().cloned());
    intent.warnings = sorted_unique_strings(intent.warnings.iter().cloned());
}

fn sort_symbols(symbols: &mut [ResolvedSemanticSymbol]) {
    symbols.sort_by(|left, right| {
        left.qualified_path
            .cmp(&right.qualified_path)
            .then_with(|| left.id.cmp(&right.id))
    });
}

fn write_state_file(
    temp_path: &Path,
    state_path: &Path,
    state: &PersistedSemanticState,
) -> Result<()> {
    let mut file = File::create(temp_path)
        .with_context(|| format!("failed to create temporary state {}", temp_path.display()))?;
    serde_json::to_writer_pretty(&mut file, state)
        .with_context(|| format!("failed to write temporary state {}", temp_path.display()))?;
    file.write_all(b"\n")
        .with_context(|| format!("failed to finish temporary state {}", temp_path.display()))?;
    file.sync_all()
        .with_context(|| format!("failed to flush temporary state {}", temp_path.display()))?;
    drop(file);

    fs::rename(temp_path, state_path).with_context(|| {
        format!(
            "failed to replace semantic intent state {} with {}",
            state_path.display(),
            temp_path.display()
        )
    })
}

fn temp_state_path(state_path: &Path) -> PathBuf {
    let file_name = state_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("semantic_intents.json");
    state_path.with_file_name(format!(".{file_name}.{}.tmp", process::id()))
}

fn stable_digest(bytes: &[u8]) -> String {
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("fnv1a64:{hash:016x}:bytes:{}", bytes.len())
}

fn excerpt(contents: &str) -> String {
    const MAX_CHARS: usize = 2048;
    contents.chars().take(MAX_CHARS).collect()
}

struct StateLock {
    path: PathBuf,
}

impl StateLock {
    fn acquire(state_path: &Path) -> Result<Self> {
        let parent = state_path
            .parent()
            .context("semantic intent state path must have a parent directory")?;
        fs::create_dir_all(parent).with_context(|| {
            format!(
                "failed to create semantic intent state directory {}",
                parent.display()
            )
        })?;

        let path = parent.join("semantic_intents.lock");
        let mut attempts = 0;
        let mut file = loop {
            match OpenOptions::new().write(true).create_new(true).open(&path) {
                Ok(file) => break file,
                Err(error) if error.kind() == ErrorKind::AlreadyExists => {
                    if remove_stale_lock(&path)? {
                        continue;
                    }
                    attempts += 1;
                    if attempts >= 50 {
                        bail!(
                            "semantic intent state is locked at {}; another maco semantic command may be running",
                            path.display()
                        );
                    }
                    thread::sleep(Duration::from_millis(20));
                }
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!("failed to create semantic intent lock {}", path.display())
                    })
                }
            }
        };

        let result = (|| -> Result<()> {
            writeln!(file, "pid={}", process::id()).with_context(|| {
                format!("failed to write semantic intent lock {}", path.display())
            })?;
            file.sync_all().with_context(|| {
                format!("failed to flush semantic intent lock {}", path.display())
            })?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&path);
        }
        result?;

        Ok(Self { path })
    }
}

impl Drop for StateLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn remove_stale_lock(path: &Path) -> Result<bool> {
    let contents = match fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(true),
        Err(error) => {
            return Err(error).with_context(|| {
                format!("failed to inspect semantic intent lock {}", path.display())
            })
        }
    };
    let Some(pid) = parse_lock_pid(&contents) else {
        return Ok(false);
    };
    if process_is_running(pid) {
        return Ok(false);
    }

    fs::remove_file(path).with_context(|| {
        format!(
            "failed to remove stale semantic intent lock {}",
            path.display()
        )
    })?;
    Ok(true)
}

fn parse_lock_pid(contents: &str) -> Option<u32> {
    contents
        .lines()
        .find_map(|line| line.strip_prefix("pid="))
        .and_then(|pid| pid.trim().parse().ok())
}

#[cfg(target_family = "unix")]
fn process_is_running(pid: u32) -> bool {
    if Path::new("/proc").exists() {
        return Path::new("/proc").join(pid.to_string()).exists();
    }

    Command::new("kill")
        .arg("-0")
        .arg(pid.to_string())
        .status()
        .map(|status| status.success())
        .unwrap_or(true)
}

#[cfg(not(target_family = "unix"))]
fn process_is_running(_pid: u32) -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn classifies_path_module_and_symbol_overlaps() {
        let (_temp, repo) = init_repo();
        write_file(
            &repo,
            "src/lib.rs",
            r#"
pub mod api;
"#,
        );
        write_file(
            &repo,
            "src/api.rs",
            r#"
pub fn endpoint() {}
"#,
        );
        let store = SemanticIntentStore::open(&repo).expect("open store");

        let first = store
            .claim(
                request("agent-a")
                    .path("src/api.rs")
                    .module("crate::api")
                    .into(),
            )
            .expect("claim first");
        assert!(first.persisted);

        let symbol_report = store
            .preview(request("agent-b").symbol("endpoint").into())
            .expect("preview symbol");
        assert!(symbol_report.conflicts.iter().any(|conflict| {
            conflict.kind == SemanticConflictKind::ModuleSymbolOverlap
                && conflict.severity == SemanticConflictSeverity::Blocking
        }));

        let path_report = store
            .preview(request("agent-c").path("src").into())
            .expect("preview path");
        assert!(path_report.conflicts.iter().any(|conflict| {
            conflict.kind == SemanticConflictKind::PathOverlap
                && conflict.severity == SemanticConflictSeverity::Blocking
        }));

        let module_report = store
            .preview(request("agent-d").module("crate").into())
            .expect("preview module");
        assert!(module_report.conflicts.iter().any(|conflict| {
            conflict.kind == SemanticConflictKind::ModuleHierarchyOverlap
                && conflict.severity == SemanticConflictSeverity::Blocking
        }));
    }

    #[test]
    fn reports_symbol_resolution_ambiguity() {
        let (_temp, repo) = init_repo();
        write_file(
            &repo,
            "src/lib.rs",
            r#"
mod a { pub fn duplicate() {} }
mod b { pub fn duplicate() {} }
"#,
        );
        let store = SemanticIntentStore::open(&repo).expect("open store");

        let error = store
            .preview(request("agent-a").symbol("duplicate").into())
            .expect_err("ambiguous symbol should fail");

        let message = error.to_string();
        assert!(message.contains("ambiguous semantic symbol duplicate"));
        assert!(message.contains("crate::a::duplicate"));
        assert!(message.contains("crate::b::duplicate"));
    }

    #[test]
    fn reports_advisory_dependency_impact_conflict() {
        let (_temp, repo) = init_repo();
        write_file(&repo, "src/lib.rs", "pub mod api;\npub mod client;\n");
        write_file(&repo, "src/api.rs", "pub fn endpoint() {}\n");
        write_file(
            &repo,
            "src/client.rs",
            "use crate::api::endpoint;\npub fn call() { endpoint(); }\n",
        );
        let store = SemanticIntentStore::open(&repo).expect("open store");

        let first = store
            .claim(request("agent-a").path("src/client.rs").into())
            .expect("claim client");
        assert!(first.persisted);

        let report = store
            .preview(request("agent-b").path("src/api.rs").into())
            .expect("preview api");

        assert!(!report.has_blocking_conflicts);
        assert!(report.conflicts.iter().any(|conflict| {
            conflict.kind == SemanticConflictKind::ImpactedFileOverlapsActivePath
                && conflict.severity == SemanticConflictSeverity::Advisory
                && conflict.path == Some(PathBuf::from("src/client.rs"))
        }));
    }

    #[test]
    fn symbol_only_intent_reports_dependency_impact_against_active_path() {
        let (_temp, repo) = init_repo();
        write_file(&repo, "src/lib.rs", "pub mod api;\npub mod client;\n");
        write_file(&repo, "src/api.rs", "pub fn endpoint() {}\n");
        write_file(
            &repo,
            "src/client.rs",
            "use crate::api::endpoint;\npub fn call() { endpoint(); }\n",
        );
        let store = SemanticIntentStore::open(&repo).expect("open store");

        let first = store
            .claim(request("agent-a").path("src/client.rs").into())
            .expect("claim client");
        assert!(first.persisted);

        let report = store
            .preview(request("agent-b").symbol("endpoint").into())
            .expect("preview endpoint");

        assert!(report.intent.paths.is_empty());
        assert!(report
            .intent
            .impacted_files
            .contains(&PathBuf::from("src/client.rs")));
        assert!(!report.has_blocking_conflicts);
        assert!(report.conflicts.iter().any(|conflict| {
            conflict.kind == SemanticConflictKind::ImpactedFileOverlapsActivePath
                && conflict.severity == SemanticConflictSeverity::Advisory
                && conflict.path == Some(PathBuf::from("src/client.rs"))
        }));
    }

    #[test]
    fn module_source_files_include_inline_module_declaration_file() {
        let (_temp, repo) = init_repo();
        write_file(
            &repo,
            "src/lib.rs",
            r#"
mod inline {
    pub fn nested() {}
}
"#,
        );
        let map = repo_semantic::scan_repository(&repo).expect("scan repo");

        let sources = module_source_files(&map, &[String::from("crate::inline")]);

        assert!(sources.contains(Path::new("src/lib.rs")));
    }

    #[test]
    fn module_symbol_exact_overlap_blocks_module_symbol_claims() {
        let (_temp, repo) = init_repo();
        write_file(&repo, "src/lib.rs", "pub mod api;\n");
        write_file(&repo, "src/api.rs", "pub fn endpoint() {}\n");
        let store = SemanticIntentStore::open(&repo).expect("open store");

        let first = store
            .claim(request("agent-a").symbol("api").into())
            .expect("claim api module symbol");
        assert!(first.persisted);
        assert_eq!(first.intent.symbols[0].kind, "module");
        assert_eq!(first.intent.symbols[0].qualified_path, "crate::api");

        let preview = store
            .preview(request("agent-b").module("crate::api").into())
            .expect("preview api module");
        assert!(preview.conflicts.iter().any(|conflict| {
            conflict.kind == SemanticConflictKind::ModuleSymbolOverlap
                && conflict.severity == SemanticConflictSeverity::Blocking
        }));

        let claim = store
            .claim(request("agent-b").module("crate::api").into())
            .expect("claim api module blocked");
        assert!(!claim.persisted);
        assert!(claim.conflicts.iter().any(|conflict| {
            conflict.kind == SemanticConflictKind::ModuleSymbolOverlap
                && conflict.severity == SemanticConflictSeverity::Blocking
        }));
    }

    #[test]
    fn persists_status_and_releases_intents() {
        let (_temp, repo) = init_repo();
        write_file(&repo, "src/lib.rs", "pub fn root() {}\n");
        let store = SemanticIntentStore::open(&repo).expect("open store");

        let first = store
            .claim(request("agent-a").path("src/lib.rs").into())
            .expect("claim first");
        assert!(first.persisted);
        assert_eq!(first.intent.token.get(), 1);
        assert!(store.state_path().exists());

        let reopened = SemanticIntentStore::open(&repo).expect("reopen store");
        assert_eq!(
            reopened.status().expect("status"),
            vec![first.intent.clone()]
        );

        let blocking = reopened
            .claim(request("agent-b").path("src/lib.rs").into())
            .expect("claim blocked");
        assert!(!blocking.persisted);
        assert_eq!(blocking.intent.token.get(), 2);
        assert_eq!(reopened.snapshot().expect("snapshot").len(), 1);

        let released = reopened.release(first.intent.token).expect("release");
        assert_eq!(released, first.intent);

        let second = reopened
            .claim(request("agent-b").path("src/lib.rs").into())
            .expect("claim second");
        assert!(second.persisted);
        assert_eq!(second.intent.token.get(), 2);

        let third = reopened
            .claim(request("agent-b").path("Cargo.toml").into())
            .expect("claim third");
        assert!(third.persisted);
        let released_by_agent = reopened.release_by_agent("agent-b").expect("release agent");
        assert_eq!(released_by_agent.len(), 2);
        assert!(reopened.snapshot().expect("snapshot").is_empty());
    }

    #[test]
    fn keeps_paths_symbols_modules_intents_and_conflicts_deterministic() {
        let (_temp, repo) = init_repo();
        write_file(
            &repo,
            "src/lib.rs",
            r#"
pub mod zed;
pub mod api;
"#,
        );
        write_file(&repo, "src/api.rs", "pub fn beta() {}\npub fn alpha() {}\n");
        write_file(&repo, "src/zed.rs", "pub fn omega() {}\n");
        let store = SemanticIntentStore::open(&repo).expect("open store");

        let first = store
            .claim(
                request("agent-a")
                    .path("src/api.rs")
                    .path("src")
                    .module("api")
                    .symbol("beta")
                    .symbol("alpha")
                    .note("z")
                    .note("a")
                    .into(),
            )
            .expect("claim first");

        assert_eq!(first.intent.paths, vec![PathBuf::from("src")]);
        assert_eq!(first.intent.modules, vec!["crate::api"]);
        assert_eq!(
            first
                .intent
                .symbols
                .iter()
                .map(|symbol| symbol.qualified_path.as_str())
                .collect::<Vec<_>>(),
            vec!["crate::api::alpha", "crate::api::beta"]
        );
        assert_eq!(first.intent.notes, vec!["a", "z"]);

        let report = store
            .preview(
                request("agent-b")
                    .path("src/api.rs")
                    .module("crate::api")
                    .symbol("alpha")
                    .into(),
            )
            .expect("preview conflicts");
        let kinds = report
            .conflicts
            .iter()
            .map(|conflict| conflict.kind)
            .collect::<Vec<_>>();
        let mut sorted = kinds.clone();
        sorted.sort();
        assert_eq!(kinds, sorted);

        let state = fs::read_to_string(store.state_path()).expect("read state");
        let reparsed: PersistedSemanticState =
            serde_json::from_str(&state).expect("parse persisted state");
        assert_eq!(reparsed.intents, vec![first.intent]);
    }

    fn init_repo() -> (TempDir, PathBuf) {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        fs::create_dir_all(repo_path.join("src")).expect("create src");
        fs::write(
            repo_path.join("Cargo.toml"),
            "[package]\nname = \"t\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )
        .expect("write cargo");
        Repository::init(&repo_path).expect("init repo");
        (temp, repo_path)
    }

    fn write_file(repo: &Path, path: &str, contents: &str) {
        let full_path = repo.join(path);
        if let Some(parent) = full_path.parent() {
            fs::create_dir_all(parent).expect("create parent");
        }
        fs::write(full_path, contents).expect("write file");
    }

    fn request(agent_id: &str) -> RequestBuilder {
        RequestBuilder {
            inner: SemanticIntentRequest::new(agent_id),
        }
    }

    struct RequestBuilder {
        inner: SemanticIntentRequest,
    }

    impl RequestBuilder {
        fn path(mut self, path: &str) -> Self {
            self.inner.paths.push(PathBuf::from(path));
            self
        }

        fn symbol(mut self, symbol: &str) -> Self {
            self.inner.symbols.push(symbol.to_string());
            self
        }

        fn module(mut self, module: &str) -> Self {
            self.inner.modules.push(module.to_string());
            self
        }

        fn note(mut self, note: &str) -> Self {
            self.inner.notes.push(note.to_string());
            self
        }
    }

    impl From<RequestBuilder> for SemanticIntentRequest {
        fn from(builder: RequestBuilder) -> Self {
            builder.inner
        }
    }
}
