use super::*;

pub(super) fn discover_repo_root(repo_path: &Path) -> Result<PathBuf> {
    let repo = crate::git_repository::discover(repo_path)
        .with_context(|| format!("failed to discover repository from {}", repo_path.display()))?;
    repo.workdir()
        .map(Path::to_path_buf)
        .context("repository command requires a non-bare repository")
}

pub(super) fn run_dir(repo: &Path, run_id: &RunId) -> PathBuf {
    repo.join(".maco")
        .join("o2")
        .join("runs")
        .join(run_id.as_str())
}

pub(super) fn supervisor_final_report_path(run_dir: &Path) -> PathBuf {
    run_dir.join("reports").join("supervisor-final.json")
}

pub(super) fn normalize_paths(paths: Vec<PathBuf>) -> Result<Vec<PathBuf>> {
    let paths = paths
        .into_iter()
        .map(normalize_repo_relative_path)
        .collect::<std::result::Result<BTreeSet<_>, _>>()?;
    Ok(collapse_covered_paths(paths))
}

pub(super) fn collapse_covered_paths(paths: BTreeSet<PathBuf>) -> Vec<PathBuf> {
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

pub(super) fn normalize_agent_id(value: &str) -> Result<String> {
    let value = value.trim();
    if value.is_empty() {
        bail!("agent id cannot be empty");
    }
    if matches!(value, "." | "..") {
        bail!("agent id cannot be '.' or '..'");
    }
    if !value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        bail!("agent id may only contain ASCII letters, digits, '.', '_' and '-'");
    }
    Ok(value.to_string())
}

pub(super) fn normalize_semantic_symbols(values: &[String]) -> Vec<String> {
    values
        .iter()
        .filter_map(|value| canonical_semantic_path(value, false))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

pub(super) fn normalize_semantic_modules(values: &[String]) -> Vec<String> {
    values
        .iter()
        .filter_map(|value| canonical_semantic_path(value, true))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn canonical_semantic_path(value: &str, require_crate_root: bool) -> Option<String> {
    let mut parts = value
        .trim()
        .split("::")
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .map(str::to_string)
        .collect::<Vec<_>>();
    if parts.is_empty() {
        return None;
    }
    if require_crate_root && parts.first().is_some_and(|part| part != "crate") {
        parts.insert(0, "crate".to_string());
    }
    Some(parts.join("::"))
}

pub(super) fn normalize_spec_fragment_ids(values: Vec<String>) -> Result<Vec<String>> {
    if values.len() > MAX_SPEC_FRAGMENT_IDS {
        bail!(
            "spec fragment id count {} exceeds limit {}",
            values.len(),
            MAX_SPEC_FRAGMENT_IDS
        );
    }
    values
        .into_iter()
        .map(|value| {
            let value = value.trim();
            if value.is_empty() {
                bail!("spec fragment id cannot be empty");
            }
            if value.len() > MAX_SPEC_FRAGMENT_ID_BYTES {
                bail!(
                    "spec fragment id exceeds {} bytes",
                    MAX_SPEC_FRAGMENT_ID_BYTES
                );
            }
            if value.chars().any(char::is_control) {
                bail!("spec fragment id must not contain control characters");
            }
            Ok(value.to_string())
        })
        .collect::<Result<BTreeSet<_>>>()
        .map(BTreeSet::into_iter)
        .map(Iterator::collect)
}

pub(super) fn parent_auditor_id(assignment: &OrchestratorAssignment) -> String {
    format!("{}-review-auditor", assignment.id)
}

pub(super) fn review_lens_auditor_id(
    assignment: &OrchestratorAssignment,
    lens_index: usize,
) -> String {
    format!("{}-review-auditor-lens-{lens_index}", assignment.id)
}

pub(super) fn is_parent_auditor_id(assignment: &OrchestratorAssignment, id: &str) -> bool {
    if id == parent_auditor_id(assignment) {
        return true;
    }
    id.strip_prefix(&format!("{}-review-auditor-lens-", assignment.id))
        .is_some_and(|index| !index.is_empty() && index.bytes().all(|byte| byte.is_ascii_digit()))
}

pub(super) fn owning_assignment_id_for_dispatch_subject<'a>(
    subject: &'a str,
    assignment_ids: &'a [String],
) -> &'a str {
    if let Some(assignment_id) = assignment_ids
        .iter()
        .find(|assignment_id| assignment_id.as_str() == subject)
    {
        return assignment_id;
    }
    assignment_ids
        .iter()
        .find(|assignment_id| {
            let Some(suffix) = subject.strip_prefix(assignment_id.as_str()) else {
                return false;
            };
            suffix == "-review-auditor"
                || suffix
                    .strip_prefix("-review-auditor-lens-")
                    .is_some_and(|index| {
                        !index.is_empty() && index.bytes().all(|byte| byte.is_ascii_digit())
                    })
        })
        .map(String::as_str)
        .unwrap_or(subject)
}

pub(super) fn path_is_covered_by_claim(path: &Path, claim: &Path) -> bool {
    path == claim || path.starts_with(claim)
}

pub(crate) fn validate_max_concurrent_children(max_concurrent_children: usize) -> Result<()> {
    if max_concurrent_children == 0 {
        bail!("--max-concurrent-children must be at least 1");
    }
    Ok(())
}

pub(super) fn display_paths(paths: &[PathBuf]) -> String {
    if paths.is_empty() {
        return "<none>".to_string();
    }
    paths
        .iter()
        .map(|path| path.display().to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

pub(super) fn display_strings(values: &[String]) -> String {
    if values.is_empty() {
        return "<none>".to_string();
    }
    values.join(", ")
}

pub(super) fn display_command_identities(commands: &[(Vec<String>, PathBuf)]) -> String {
    if commands.is_empty() {
        return "<none>".to_string();
    }
    commands
        .iter()
        .map(|(command, cwd)| format!("{} @ {}", display_strings(command), cwd.display()))
        .collect::<Vec<_>>()
        .join("; ")
}

pub(super) fn path_relative_to(repo: &Path, path: &Path) -> PathBuf {
    path.strip_prefix(repo)
        .map(Path::to_path_buf)
        .unwrap_or_else(|_| path.to_path_buf())
}

pub(super) fn default_schema_version() -> u32 {
    SUPERVISOR_SCHEMA_VERSION
}

pub(super) fn default_max_depth() -> u8 {
    2
}

pub(super) fn default_max_child_assignments() -> usize {
    DEFAULT_MAX_CHILD_ASSIGNMENTS
}

pub(super) fn default_max_child_retries() -> u8 {
    DEFAULT_MAX_CHILD_RETRIES
}

pub(super) fn default_max_gate_corrections() -> u8 {
    DEFAULT_MAX_GATE_CORRECTIONS
}

pub(super) fn default_child_timeout_seconds() -> u64 {
    DEFAULT_CHILD_TIMEOUT_SECONDS
}

pub(super) fn default_consultant_runtime() -> String {
    "fake".to_string()
}

pub(super) fn default_max_consultations() -> u32 {
    2
}

pub(super) fn child_orchestrator_role() -> AgentRole {
    AgentRole::ChildOrchestrator
}

pub(super) fn worker_role() -> AgentRole {
    AgentRole::Worker
}

pub fn generated_run_id() -> Result<RunId> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before UNIX epoch")?
        .as_secs();
    RunId::new(format!("o2-{now}"))
}
