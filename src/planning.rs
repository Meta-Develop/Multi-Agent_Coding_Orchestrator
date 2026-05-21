use crate::{repo_semantic, sync::normalize_repo_relative_path};
use anyhow::{Context, Result};
use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
};

pub fn propose_task_paths(repo: &Path, title: &str, body: &str) -> Result<Vec<PathBuf>> {
    let text = format!("{title}\n{body}");
    let lowered = text.to_ascii_lowercase();
    let normalized_text = normalize_text(&text);
    let files = collect_repo_files(repo)?;
    let file_set = files.iter().cloned().collect::<BTreeSet<_>>();
    let mut proposed = BTreeSet::new();

    for file in &files {
        let display = file.to_string_lossy().to_ascii_lowercase();
        if contains_path_mention(&lowered, &display) {
            proposed.insert(file.clone());
        }
    }

    propose_docs_paths(&normalized_text, &file_set, &mut proposed);
    propose_rust_paths(repo, &normalized_text, &lowered, &file_set, &mut proposed);

    if proposed.is_empty() {
        if file_set.contains(Path::new("README.md")) {
            proposed.insert(PathBuf::from("README.md"));
        } else if let Some(first) = files.into_iter().next() {
            proposed.insert(first);
        }
    }

    Ok(collapse_covered_paths(proposed))
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
    lowered: &str,
    file_set: &BTreeSet<PathBuf>,
    proposed: &mut BTreeSet<PathBuf>,
) {
    if let Ok(map) = repo_semantic::scan_repository(repo) {
        for file in &map.files {
            if file_set.contains(&file.path)
                && identifier_matches(normalized_text, lowered, &file.path)
            {
                proposed.insert(file.path.clone());
            }
            if let Some(module) = file.module_path.last() {
                if identifier_matches_text(normalized_text, lowered, module) {
                    proposed.insert(file.path.clone());
                }
            }
        }

        for symbol in &map.symbols {
            if identifier_matches_text(normalized_text, lowered, &symbol.name)
                || lowered.contains(&symbol.qualified_path.join("::").to_ascii_lowercase())
            {
                proposed.insert(symbol.file.clone());
            }
        }
    } else {
        for file in file_set {
            if file
                .extension()
                .and_then(|extension| extension.to_str())
                .is_some_and(|extension| extension.eq_ignore_ascii_case("rs"))
                && identifier_matches(normalized_text, lowered, file)
            {
                proposed.insert(file.clone());
            }
        }
    }
}

fn identifier_matches(normalized_text: &str, lowered: &str, path: &Path) -> bool {
    path.file_stem()
        .and_then(|stem| stem.to_str())
        .is_some_and(|stem| identifier_matches_text(normalized_text, lowered, stem))
}

fn identifier_matches_text(normalized_text: &str, lowered: &str, identifier: &str) -> bool {
    identifier_phrases(identifier).into_iter().any(|phrase| {
        if phrase.contains(' ') {
            contains_phrase(normalized_text, &phrase)
        } else {
            contains_phrase(normalized_text, &phrase) || lowered.contains(&phrase)
        }
    })
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
    let mut files = Vec::new();
    collect_repo_files_from(repo, repo, &mut files)?;
    files.sort();
    files.dedup();
    Ok(files)
}

fn collect_repo_files_from(root: &Path, directory: &Path, files: &mut Vec<PathBuf>) -> Result<()> {
    let entries = fs::read_dir(directory)
        .with_context(|| format!("failed to read directory {}", directory.display()))?
        .collect::<std::result::Result<Vec<_>, _>>()
        .with_context(|| format!("failed to read directory entry in {}", directory.display()))?;

    for entry in entries {
        let path = entry.path();
        let name = entry.file_name();
        if path.is_dir() {
            if should_skip_dir(&name.to_string_lossy()) {
                continue;
            }
            collect_repo_files_from(root, &path, files)?;
            continue;
        }
        if !path.is_file() {
            continue;
        }
        let relative = path
            .strip_prefix(root)
            .with_context(|| format!("failed to relativize {}", path.display()))?;
        let relative = normalize_repo_relative_path(relative)?;
        if !is_runtime_path(&relative) {
            files.push(relative);
        }
    }
    Ok(())
}

fn should_skip_dir(name: &str) -> bool {
    matches!(name, ".git" | ".maco" | ".maco-cache" | "target")
}

fn is_runtime_path(path: &Path) -> bool {
    path.components().next().is_some_and(|component| {
        matches!(
            component.as_os_str().to_str(),
            Some(".maco" | ".maco-cache" | "target")
        )
    })
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
