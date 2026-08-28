use crate::{
    artifacts::{
        repository_authenticator_key_only,
        state_auth::{AuthenticationDomain, RepositoryAuthBinding},
    },
    authenticated_snapshot::{AuthenticatedSnapshotStore, SnapshotSpec},
    repo_semantic::{self, SemanticRepoMap, SemanticScanError, SemanticSymbol, SemanticSymbolKind},
    safe_state::{stable_checksum, BoundedRegularReader, SafeRoot},
    state_journal::JournalSpec,
    state_migration::{
        decode_checksumless_legacy_semantic_state, finalize_legacy_retirement,
        prepare_legacy_retirement, LegacyAdoption, LEGACY_RETIREMENT_DOMAIN,
    },
    sync::normalize_repo_relative_path,
    sync_store::{
        validate_state_path, RepositoryStateBinding, RepositoryStateLock, RepositoryStateRoot,
    },
};
use anyhow::{bail, Context, Result};
#[cfg(test)]
use git2::Repository;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};

const STATE_VERSION: u32 = 2;
const MAX_SEMANTIC_STATE_BYTES: u64 = 8 * 1024 * 1024;
const MAX_SEMANTIC_INTENTS: usize = 4_096;
const MAX_SEMANTIC_RECORDS: usize = 262_144;
const MAX_AGENT_ID_BYTES: usize = 128;
const MAX_SEMANTIC_STRING_BYTES: usize = 16 * 1024;
const MAX_TASK_EXCERPT_BYTES: usize = 16 * 1024;
const MAX_TASK_FILE_BYTES: u64 = 2 * 1024 * 1024;

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
    repo_path: PathBuf,
    state: RepositoryStateRoot,
}

pub(crate) enum SemanticSnapshotSpec {}

impl JournalSpec for SemanticSnapshotSpec {
    const FORMAT_VERSION: u32 = 1;
    const NAMESPACE: &'static str = "authenticated_semantic";
    const ROOT_NAME: &'static str = "authenticated-semantic-state-v1";
    const ROOT_LOCK_NAME: &'static str = ".authenticated-semantic.lock";
    const INSTANCE_LOCK_NAME: &'static str = ".semantic-snapshot.lock";
    const HEAD_FILE_NAME: &'static str = ".head.json";
    const RECORD_DOMAIN: AuthenticationDomain =
        AuthenticationDomain::new(b"MACO\0authenticated-semantic-record\0v1\0");
    const HEAD_DOMAIN: AuthenticationDomain =
        AuthenticationDomain::new(b"MACO\0authenticated-semantic-head\0v1\0");
    const MAX_RECORDS: usize = 4_096;
    const MAX_RECORD_BYTES: u64 = MAX_SEMANTIC_STATE_BYTES;
    const MAX_TOTAL_BYTES: u64 = 128 * 1024 * 1024;
    const MAX_PHASE_BYTES: usize = 32;
    const MAX_SUBJECT_BYTES: usize = 64;
    const MAX_INSTANCE_ID_BYTES: usize = 128;
}

impl SnapshotSpec for SemanticSnapshotSpec {
    const SNAPSHOT_FORMAT_VERSION: u32 = 1;
    const LOCATOR_DOMAIN: AuthenticationDomain =
        AuthenticationDomain::new(b"MACO\0authenticated-semantic-locator\0v1\0");
}

const SEMANTIC_LOGICAL_ID: &str = "semantic-intents";

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AuthenticatedSemanticState {
    version: u32,
    snapshot_revision: u64,
    repository: RepositoryAuthBinding,
    next_token: u64,
    intents: Vec<SemanticIntent>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PersistedSemanticState {
    version: u32,
    checksum: String,
    repository: RepositoryStateBinding,
    next_token: u64,
    intents: Vec<SemanticIntent>,
}

impl SemanticIntentStore {
    pub fn open(repo_path: impl AsRef<Path>) -> Result<Self> {
        let repo = crate::git_repository::discover(repo_path.as_ref()).with_context(|| {
            format!(
                "failed to discover repository from {}",
                repo_path.as_ref().display()
            )
        })?;
        let repo_root = repo
            .workdir()
            .context("semantic intent store requires a non-bare repository")?
            .to_path_buf();
        let repo_root = SafeRoot::open_existing(&repo_root)
            .context("semantic intent repository root is not safely reachable")?
            .path()
            .to_path_buf();
        let store = Self {
            repo_root,
            repo_path: repo.workdir().unwrap_or_else(|| repo.path()).to_path_buf(),
            state: RepositoryStateRoot::open(
                &repo,
                "semantic_intents.json",
                "semantic_intents.lock",
            )?,
        };
        store.ensure_authenticated_initialized()?;
        Ok(store)
    }

    pub fn state_path(&self) -> &Path {
        self.state.state_path()
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
        let lock = self.state.lock()?;
        let mut store = self.open_authenticated_store(&lock)?;
        let mut state = self.persisted_view(store.current().value.clone())?;
        let output = operation(&mut state)?;
        normalize_state(&mut state);
        validate_semantic_state(&state)?;
        let revision = store
            .current()
            .value
            .snapshot_revision
            .checked_add(1)
            .context("authenticated semantic snapshot revision exhausted")?;
        let value = AuthenticatedSemanticState {
            version: 1,
            snapshot_revision: revision,
            repository: store.current().value.repository.clone(),
            next_token: state.next_token,
            intents: state.intents,
        };
        if revision % 4_096 == 0 {
            let authenticator = repository_authenticator_key_only(&self.repo_path)?;
            store = store.rollover(authenticator, revision, value)?;
        } else {
            store.commit(revision, value)?;
        }
        self.validate_authenticated_store(&store)?;
        self.ensure_legacy_retirement(&store, &lock)?;
        self.state.verify(&lock)?;
        Ok(output)
    }

    fn with_locked_read<T>(
        &self,
        operation: impl FnOnce(&PersistedSemanticState) -> Result<T>,
    ) -> Result<T> {
        let lock = self.state.lock()?;
        let store = self.open_authenticated_store(&lock)?;
        let state = self.persisted_view(store.current().value.clone())?;
        operation(&state)
    }

    fn ensure_authenticated_initialized(&self) -> Result<()> {
        let lock = self.state.lock()?;
        let root_exists = self
            .state
            .root()
            .direct_child_exists(SemanticSnapshotSpec::ROOT_NAME)?;
        if root_exists {
            let authenticator = repository_authenticator_key_only(&self.repo_path)?;
            let initialized = AuthenticatedSnapshotStore::<
                SemanticSnapshotSpec,
                AuthenticatedSemanticState,
            >::initialized(&authenticator, SEMANTIC_LOGICAL_ID)?;
            if initialized {
                let store = AuthenticatedSnapshotStore::<
                    SemanticSnapshotSpec,
                    AuthenticatedSemanticState,
                >::open_instance(authenticator, SEMANTIC_LOGICAL_ID)?;
                self.validate_authenticated_store(&store)?;
                self.ensure_legacy_retirement(&store, &lock)?;
                return self.state.verify(&lock);
            }
        }
        let preparation = prepare_legacy_retirement::<SemanticSnapshotSpec>(
            &self.repo_path,
            "semantic_intents",
            "semantic_intents.json",
            LEGACY_RETIREMENT_DOMAIN,
            &|| self.state.verify(&lock),
        )?;
        let (adoption, writer) = preparation.into_parts();
        let binding = writer.authenticator().binding().clone();
        let initial = match adoption {
            LegacyAdoption::Missing => AuthenticatedSemanticState {
                version: 1,
                snapshot_revision: 1,
                repository: binding,
                next_token: 1,
                intents: Vec::new(),
            },
            LegacyAdoption::Present(bytes) => {
                let (next_token, intents) = match serde_json::from_slice::<PersistedSemanticState>(
                    &bytes,
                ) {
                    Ok(legacy) => {
                        if legacy.version != STATE_VERSION
                            || legacy.repository != *self.state.binding()
                            || legacy.checksum != semantic_state_checksum(&legacy)?
                        {
                            bail!(
                                    "signed legacy semantic state failed repository/checksum validation"
                                );
                        }
                        validate_semantic_state(&legacy)?;
                        (legacy.next_token, legacy.intents)
                    }
                    Err(_) => {
                        // The checksum-less generation-one decoder is reachable only after
                        // `prepare_legacy_retirement` has verified a repository-bound signed
                        // migration manifest for these exact bytes. Normal runtime opening of
                        // an unmanifested checksum-less file remains fail closed.
                        let legacy = decode_checksumless_legacy_semantic_state(&bytes)
                            .context("signed legacy semantic state is malformed")?;
                        (legacy.next_token, legacy.intents)
                    }
                };
                AuthenticatedSemanticState {
                    version: 1,
                    snapshot_revision: 1,
                    repository: binding,
                    next_token,
                    intents,
                }
            }
        };
        let store =
            AuthenticatedSnapshotStore::<SemanticSnapshotSpec, AuthenticatedSemanticState>::create(
                writer.into_authenticator()?,
                SEMANTIC_LOGICAL_ID,
                1,
                initial,
            )?;
        self.validate_authenticated_store(&store)?;
        self.ensure_legacy_retirement(&store, &lock)?;
        self.state.verify(&lock)
    }

    fn open_authenticated_store(
        &self,
        lock: &RepositoryStateLock,
    ) -> Result<AuthenticatedSnapshotStore<SemanticSnapshotSpec, AuthenticatedSemanticState>> {
        self.state.verify(lock)?;
        let authenticator = repository_authenticator_key_only(&self.repo_path)?;
        let store = AuthenticatedSnapshotStore::open_instance(authenticator, SEMANTIC_LOGICAL_ID)?;
        self.validate_authenticated_store(&store)?;
        self.ensure_legacy_retirement(&store, lock)?;
        self.state.verify(lock)?;
        Ok(store)
    }

    fn validate_authenticated_store(
        &self,
        store: &AuthenticatedSnapshotStore<SemanticSnapshotSpec, AuthenticatedSemanticState>,
    ) -> Result<()> {
        let snapshot = store.current();
        if snapshot.value.version != 1
            || snapshot.value.snapshot_revision != snapshot.generation
            || snapshot.value.snapshot_revision != snapshot.token
            || snapshot.value.repository != store.identity().repository
        {
            bail!("authenticated semantic snapshot binding or revision is inconsistent");
        }
        let state = self.persisted_view(snapshot.value.clone())?;
        validate_semantic_state(&state)
    }

    fn ensure_legacy_retirement(
        &self,
        store: &AuthenticatedSnapshotStore<SemanticSnapshotSpec, AuthenticatedSemanticState>,
        lock: &RepositoryStateLock,
    ) -> Result<()> {
        finalize_legacy_retirement::<SemanticSnapshotSpec>(
            &self.repo_path,
            "semantic_intents",
            "semantic_intents.json",
            LEGACY_RETIREMENT_DOMAIN,
            store.identity(),
            store.current().generation,
            &|| self.state.verify(lock),
        )
    }

    fn persisted_view(&self, value: AuthenticatedSemanticState) -> Result<PersistedSemanticState> {
        let mut state = PersistedSemanticState {
            version: STATE_VERSION,
            checksum: String::new(),
            repository: self.state.binding().clone(),
            next_token: value.next_token,
            intents: value.intents,
        };
        normalize_state(&mut state);
        validate_semantic_state(&state)?;
        state.checksum = semantic_state_checksum(&state)?;
        Ok(state)
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
        let contents = match BoundedRegularReader::read_relative_utf8(
            &self.repo_root,
            &task_file,
            MAX_TASK_FILE_BYTES,
        ) {
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
        repo_semantic::SemanticScanErrorKind::Unsupported => "unsupported",
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

fn semantic_state_checksum(state: &PersistedSemanticState) -> Result<String> {
    let payload = serde_json::to_vec(&(
        state.version,
        &state.repository,
        state.next_token,
        &state.intents,
    ))
    .context("failed to encode semantic state checksum payload")?;
    Ok(stable_checksum(&payload))
}

fn validate_semantic_state(state: &PersistedSemanticState) -> Result<()> {
    validate_legacy_semantic_payload(state.next_token, &state.intents)
}

pub(crate) fn validate_legacy_semantic_payload(
    next_token: u64,
    intents: &[SemanticIntent],
) -> Result<()> {
    if next_token == 0 {
        bail!("semantic intent state next_token must be nonzero");
    }
    if intents.len() > MAX_SEMANTIC_INTENTS {
        bail!(
            "semantic intent state exceeds its intent budget of {}",
            MAX_SEMANTIC_INTENTS
        );
    }

    let mut seen_tokens = BTreeSet::new();
    let mut record_count = intents.len();
    let mut max_token = 0u64;
    for intent in intents {
        if intent.token.get() == 0 {
            bail!("semantic intent token must be nonzero");
        }
        if !seen_tokens.insert(intent.token) {
            bail!(
                "semantic intent token appears more than once: {}",
                intent.token.get()
            );
        }
        max_token = max_token.max(intent.token.get());
        validate_semantic_string("agent id", &intent.agent_id, MAX_AGENT_ID_BYTES, false)?;
        if normalize_agent_id(&intent.agent_id)? != intent.agent_id {
            bail!("persisted semantic intent agent id is not canonical");
        }
        add_semantic_records(&mut record_count, intent.paths.len(), "paths")?;
        add_semantic_records(&mut record_count, intent.symbols.len(), "symbols")?;
        add_semantic_records(&mut record_count, intent.modules.len(), "modules")?;
        add_semantic_records(
            &mut record_count,
            intent.impacted_files.len(),
            "impacted files",
        )?;
        add_semantic_records(&mut record_count, intent.notes.len(), "notes")?;
        add_semantic_records(&mut record_count, intent.warnings.len(), "warnings")?;

        for path in intent.paths.iter().chain(&intent.impacted_files) {
            validate_state_path(path)?;
        }
        for symbol in &intent.symbols {
            validate_semantic_string("symbol id", &symbol.id, MAX_SEMANTIC_STRING_BYTES, false)?;
            validate_semantic_string(
                "symbol qualified path",
                &symbol.qualified_path,
                MAX_SEMANTIC_STRING_BYTES,
                false,
            )?;
            validate_semantic_string(
                "symbol name",
                &symbol.name,
                MAX_SEMANTIC_STRING_BYTES,
                false,
            )?;
            validate_semantic_string(
                "symbol kind",
                &symbol.kind,
                MAX_SEMANTIC_STRING_BYTES,
                false,
            )?;
            validate_state_path(&symbol.file)?;
        }
        for module in &intent.modules {
            validate_semantic_string("module", module, MAX_SEMANTIC_STRING_BYTES, false)?;
        }
        if let Some(digest) = &intent.task_digest {
            validate_semantic_string("task digest", digest, MAX_SEMANTIC_STRING_BYTES, false)?;
        }
        if let Some(excerpt) = &intent.task_excerpt {
            validate_semantic_string("task excerpt", excerpt, MAX_TASK_EXCERPT_BYTES, true)?;
        }
        for note in &intent.notes {
            validate_semantic_string("note", note, MAX_SEMANTIC_STRING_BYTES, true)?;
        }
        for warning in &intent.warnings {
            validate_semantic_string("warning", warning, MAX_SEMANTIC_STRING_BYTES, true)?;
        }
    }
    if max_token > 0 && next_token <= max_token {
        bail!(
            "semantic intent next_token {} does not advance past active token {}",
            next_token,
            max_token
        );
    }
    Ok(())
}

fn add_semantic_records(total: &mut usize, count: usize, label: &str) -> Result<()> {
    *total = total
        .checked_add(count)
        .with_context(|| format!("semantic intent {label} record count overflow"))?;
    if *total > MAX_SEMANTIC_RECORDS {
        bail!(
            "semantic intent state exceeds its aggregate record budget of {} while counting {}",
            MAX_SEMANTIC_RECORDS,
            label
        );
    }
    Ok(())
}

fn validate_semantic_string(
    label: &str,
    value: &str,
    max_bytes: usize,
    allow_empty: bool,
) -> Result<()> {
    if (!allow_empty && value.is_empty()) || value.len() > max_bytes {
        bail!(
            "semantic intent {} must contain between {} and {} bytes",
            label,
            usize::from(!allow_empty),
            max_bytes
        );
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
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

        let lock = store.state.lock().expect("semantic lock");
        let authenticated = store
            .open_authenticated_store(&lock)
            .expect("authenticated semantic state");
        let reparsed = store
            .persisted_view(authenticated.current().value.clone())
            .expect("persisted view");
        assert_eq!(reparsed.intents, vec![first.intent]);
    }

    #[test]
    fn retired_legacy_filename_is_not_decodable_as_v2_state() {
        let (_temp, repo) = init_repo();
        write_file(&repo, "src/lib.rs", "pub fn root() {}\n");
        let store = SemanticIntentStore::open(&repo).expect("open store");
        let tombstone = fs::read(store.state_path()).expect("retirement tombstone");
        let value: serde_json::Value = serde_json::from_slice(&tombstone).expect("tombstone JSON");
        assert_eq!(value["version"], 3);
        assert!(serde_json::from_slice::<PersistedSemanticState>(&tombstone).is_err());
    }

    #[test]
    fn semantic_checksum_and_record_budgets_reject_tampered_state() {
        let (_temp, repo) = init_repo();
        write_file(&repo, "src/lib.rs", "pub fn root() {}\n");
        let store = SemanticIntentStore::open(&repo).expect("open store");
        store
            .claim(request("agent-a").path("src/lib.rs").into())
            .expect("claim");
        let template = store.status().expect("status")[0].clone();
        let original = fs::read(store.state_path()).expect("state");
        let mut tampered: serde_json::Value =
            serde_json::from_slice(&original).expect("parse state");
        tampered["snapshot_generation"] = serde_json::json!(999);
        fs::write(
            store.state_path(),
            serde_json::to_vec_pretty(&tampered).expect("tampered JSON"),
        )
        .expect("tamper");
        let error = store.status().expect_err("HMAC mismatch");
        assert!(format!("{error:#}").contains("authentication tag"));
        fs::write(store.state_path(), &original).expect("restore tombstone");
        let mut intents = Vec::with_capacity(MAX_SEMANTIC_INTENTS + 1);
        for index in 0..=MAX_SEMANTIC_INTENTS {
            let mut intent = template.clone();
            intent.token = SemanticIntentToken::from_u64(u64::try_from(index).expect("index") + 1);
            intent.paths = vec![PathBuf::from(format!("generated/path-{index}"))];
            intents.push(intent);
        }
        let lock = store.state.lock().expect("semantic lock");
        let mut authenticated = store
            .open_authenticated_store(&lock)
            .expect("authenticated semantic state");
        let revision = authenticated.current().value.snapshot_revision + 1;
        let oversized = AuthenticatedSemanticState {
            version: 1,
            snapshot_revision: revision,
            repository: authenticated.current().value.repository.clone(),
            next_token: u64::try_from(MAX_SEMANTIC_INTENTS).expect("count") + 2,
            intents,
        };
        authenticated
            .commit(revision, oversized)
            .expect("publish malformed budget snapshot");
        drop(authenticated);
        drop(lock);
        assert!(store
            .status()
            .expect_err("intent budget")
            .to_string()
            .contains("intent budget"));
    }

    #[test]
    fn concurrent_semantic_claims_are_serialized_without_lost_updates() {
        let (_temp, repo) = init_repo();
        write_file(&repo, "src/lib.rs", "pub fn root() {}\n");
        let store = SemanticIntentStore::open(&repo).expect("open store");
        let mut workers = Vec::new();
        for index in 0..12usize {
            let store = store.clone();
            workers.push(std::thread::spawn(move || {
                store.claim(
                    request(&format!("agent-{index}"))
                        .path(&format!("generated/path-{index}"))
                        .into(),
                )
            }));
        }
        for worker in workers {
            let report = worker.join().expect("worker thread").expect("claim");
            assert!(report.persisted);
        }
        assert_eq!(store.status().expect("status").len(), 12);
    }

    #[cfg(unix)]
    #[test]
    fn task_summary_rejects_symlink_and_oversized_input_without_following_it() {
        use std::os::unix::fs::symlink;

        let (temp, repo) = init_repo();
        write_file(&repo, "src/lib.rs", "pub fn root() {}\n");
        let external = temp.path().join("external-task.txt");
        fs::write(&external, "secret task\n").expect("external task");
        symlink(&external, repo.join("task-link.txt")).expect("task symlink");
        let store = SemanticIntentStore::open(&repo).expect("open store");

        let linked = store
            .preview(
                request("agent-a")
                    .path("src/lib.rs")
                    .task("task-link.txt")
                    .into(),
            )
            .expect("linked preview");
        assert!(linked.intent.task_digest.is_none());
        assert!(linked
            .intent
            .warnings
            .iter()
            .any(|warning| warning.contains("failed to read task file")));

        let oversized = vec![b'x'; usize::try_from(MAX_TASK_FILE_BYTES).expect("limit") + 1];
        fs::write(repo.join("large-task.txt"), oversized).expect("large task");
        let large = store
            .preview(
                request("agent-b")
                    .path("Cargo.toml")
                    .task("large-task.txt")
                    .into(),
            )
            .expect("large preview");
        assert!(large.intent.task_digest.is_none());
        assert!(large
            .intent
            .warnings
            .iter()
            .any(|warning| warning.contains("bounded read limit")));
    }

    #[cfg(unix)]
    #[test]
    fn semantic_state_binding_supports_non_utf8_repository_roots() {
        use std::{ffi::OsString, os::unix::ffi::OsStringExt};

        let temp = TempDir::new().expect("tempdir");
        let repo = temp.path().join(OsString::from_vec(b"repo-\x80".to_vec()));
        fs::create_dir_all(repo.join("src")).expect("source directory");
        fs::write(
            repo.join("Cargo.toml"),
            "[package]\nname='t'\nversion='0.1.0'\nedition='2021'\n",
        )
        .expect("Cargo.toml");
        fs::write(repo.join("src/lib.rs"), "pub fn root() {}\n").expect("source");
        Repository::init(&repo).expect("init repository");
        let store = SemanticIntentStore::open(&repo).expect("open store");
        let report = store
            .claim(request("agent-a").path("src/lib.rs").into())
            .expect("persist intent");
        assert!(report.persisted);
        assert_eq!(store.status().expect("status").len(), 1);
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

        fn task(mut self, path: &str) -> Self {
            self.inner.task_file = Some(PathBuf::from(path));
            self
        }
    }

    impl From<RequestBuilder> for SemanticIntentRequest {
        fn from(builder: RequestBuilder) -> Self {
            builder.inner
        }
    }
}
