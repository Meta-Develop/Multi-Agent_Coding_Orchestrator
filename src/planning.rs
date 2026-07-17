use crate::{
    repo_semantic,
    safe_state::{
        BoundedTreeEntry, BoundedTreeEntryKind, BoundedTreeWalkAction, BoundedTreeWalkLimits,
        BoundedTreeWalker, DirectoryBindingGuard,
    },
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskPathProposal {
    pub paths: Vec<PathBuf>,
    pub diagnostics: TaskPathProposalDiagnostics,
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
    let deadline = Instant::now()
        .checked_add(repository_inventory_max_duration())
        .context("repository inventory deadline overflowed")?;
    let binding = crate::worktree::RepositoryBindingGuard::bind(repo)?;
    let first = collect_git_inventory_snapshot(&binding, deadline)?;
    let second = collect_git_inventory_snapshot(&binding, deadline)?;
    let stable = if first == second {
        second
    } else {
        let retry = collect_git_inventory_snapshot(&binding, deadline)?;
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
    deadline: Instant,
) -> Result<(BTreeSet<PathBuf>, Vec<BoundedTreeEntry>)> {
    let visible = crate::worktree::bounded_repository_visible_paths_bound(
        binding,
        REPOSITORY_INVENTORY_MAX_ENTRIES,
        REPOSITORY_INVENTORY_MAX_TOTAL_PATH_BYTES,
        remaining_inventory_time(deadline, "before bounded Git inventory")?,
    )?
    .into_iter()
    .collect::<BTreeSet<_>>();
    let inventory = collect_descriptor_inventory(binding.worktree_binding(), deadline)?;
    binding.verify()?;
    Ok((visible, inventory))
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
