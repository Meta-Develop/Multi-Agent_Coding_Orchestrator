//! Records a bounded source revision and cleanliness for compile-time identity.
//!
//! An explicit packager state (`MACO_SOURCE_STATE`) is used with
//! `MACO_SOURCE_REVISION` and skips git. Otherwise git is probed only at
//! `CARGO_MANIFEST_DIR`. A missing git binary, a failed probe, or a revision
//! that is not 40 hexadecimal digits records `unknown` and an empty revision.
//! A dirty packager revision may also use the Nix form `{40-hex}-dirty`; the
//! suffix is removed and the state stays dirty. Metadata gaps do not fail the
//! build.
//!
//! Rerun directives cover the package inputs plus the git HEAD, index, and
//! current branch ref resolved by git. That includes a linked worktree, where
//! `.git` is a gitfile. Emitting any `rerun-if-changed` path replaces Cargo's
//! default package scan, so those package inputs have to be listed here.

use std::path::Path;
use std::process::{Command, Stdio};

const REVISION_HEX_LEN: usize = 40;

const PACKAGE_INPUTS: &[&str] = &[
    "build.rs",
    "Cargo.toml",
    "Cargo.lock",
    "src",
    "tests",
    "benches",
    "assets",
    "schemas",
    "docs",
    "scripts",
    "flake.nix",
    "README.md",
];

fn main() {
    println!("cargo:rerun-if-env-changed=MACO_SOURCE_REVISION");
    println!("cargo:rerun-if-env-changed=MACO_SOURCE_STATE");
    if let Ok(manifest_dir) = std::env::var("CARGO_MANIFEST_DIR") {
        emit_package_rerun_directives(&manifest_dir);
        emit_git_rerun_directives(&manifest_dir);
    }

    let (revision, state) = match packager_override() {
        Some(recorded) => recorded,
        None => probe_git(),
    };
    let (revision, state) = normalize_recorded(&revision, &state);
    println!("cargo:rustc-env=MACO_SOURCE_REVISION={revision}");
    println!("cargo:rustc-env=MACO_SOURCE_STATE={state}");
}

/// Non-empty `MACO_SOURCE_STATE` is an explicit packager input. Empty or
/// absent state falls through to the git probe.
fn packager_override() -> Option<(String, String)> {
    let state = std::env::var_os("MACO_SOURCE_STATE")?;
    if state.is_empty() {
        return None;
    }
    let state = state.to_str().unwrap_or("").to_string();
    let revision = std::env::var("MACO_SOURCE_REVISION").unwrap_or_default();
    Some((revision, state))
}

fn probe_git() -> (String, String) {
    let Ok(manifest_dir) = std::env::var("CARGO_MANIFEST_DIR") else {
        return unknown_record();
    };
    let Some(head) = run_git(&manifest_dir, &["rev-parse", "HEAD"]) else {
        return unknown_record();
    };
    let Some(revision) = git_stdout_line(&head) else {
        return unknown_record();
    };
    if !is_lowercase_hex_revision(&revision) {
        return unknown_record();
    }
    let Some(status) = run_git(
        &manifest_dir,
        &["status", "--porcelain", "--untracked-files=normal"],
    ) else {
        return unknown_record();
    };
    let state = if status.is_empty() { "clean" } else { "dirty" };
    (revision, state.to_string())
}

fn unknown_record() -> (String, String) {
    (String::new(), "unknown".to_string())
}

/// `git -C <manifest> -c color.ui=false …`, with repository-location variables
/// removed so the probe cannot follow an ambient checkout.
fn run_git(manifest_dir: &str, args: &[&str]) -> Option<Vec<u8>> {
    let output = Command::new("git")
        .arg("-C")
        .arg(manifest_dir)
        .arg("-c")
        .arg("color.ui=false")
        .args(args)
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_INDEX_FILE")
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .current_dir(manifest_dir)
        .output()
        .ok()?;
    if output.status.success() {
        Some(output.stdout)
    } else {
        None
    }
}

fn git_stdout_line(stdout: &[u8]) -> Option<String> {
    let mut text = String::from_utf8(stdout.to_vec()).ok()?;
    if text.ends_with('\n') {
        text.pop();
        if text.ends_with('\r') {
            text.pop();
        }
    }
    Some(text)
}

fn is_lowercase_hex_revision(revision: &str) -> bool {
    revision.len() == REVISION_HEX_LEN
        && revision
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

fn canonical_revision(revision: &str) -> Option<String> {
    if revision.len() != REVISION_HEX_LEN {
        return None;
    }
    if !revision.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    Some(revision.to_ascii_lowercase())
}

fn normalize_recorded(revision: &str, state: &str) -> (String, &'static str) {
    let revision = canonical_revision(revision_for_state(revision, state));
    match (state, revision) {
        ("clean", Some(revision)) => (revision, "clean"),
        ("dirty", Some(revision)) => (revision, "dirty"),
        _ => (String::new(), "unknown"),
    }
}

/// Nix `dirtyRev` is the commit plus a `-dirty` suffix. Only the dirty state
/// accepts that form. Keep this in step with `build_identity::normalize_recorded`.
fn revision_for_state<'a>(revision: &'a str, state: &str) -> &'a str {
    if state == "dirty" {
        revision.strip_suffix("-dirty").unwrap_or(revision)
    } else {
        revision
    }
}

fn emit_package_rerun_directives(manifest_dir: &str) {
    for relative in PACKAGE_INPUTS {
        let path = Path::new(manifest_dir).join(relative);
        if path.exists() {
            if let Some(text) = path.to_str() {
                println!("cargo:rerun-if-changed={text}");
            }
        }
    }
}

/// Watch the git files that change the recorded revision or cleanliness.
/// `git rev-parse` follows a linked-worktree gitfile, so the directive is the
/// real HEAD, index, or branch ref rather than a missing `.git/HEAD`.
fn emit_git_rerun_directives(manifest_dir: &str) {
    emit_existing_git_file(manifest_dir, "HEAD");
    emit_existing_git_file(manifest_dir, "index");
    let Some(stdout) = run_git(manifest_dir, &["symbolic-ref", "-q", "HEAD"]) else {
        return;
    };
    let Some(refname) = git_stdout_line(&stdout) else {
        return;
    };
    if refname.is_empty() || refname.contains(['\n', '\r']) || refname.starts_with('-') {
        return;
    }
    emit_existing_git_file(manifest_dir, &refname);
}

fn emit_existing_git_file(manifest_dir: &str, spec: &str) {
    let Some(path) = absolute_git_path(manifest_dir, spec) else {
        return;
    };
    if std::fs::metadata(&path).is_ok_and(|metadata| metadata.is_file()) {
        println!("cargo:rerun-if-changed={path}");
    }
}

fn absolute_git_path(manifest_dir: &str, spec: &str) -> Option<String> {
    if let Some(stdout) = run_git(
        manifest_dir,
        &["rev-parse", "--path-format=absolute", "--git-path", spec],
    ) {
        if let Some(path) = git_stdout_line(&stdout) {
            if !path.is_empty() {
                return Some(path);
            }
        }
    }
    let git_dir = git_stdout_line(&run_git(
        manifest_dir,
        &["rev-parse", "--absolute-git-dir"],
    )?)?;
    let relative = git_stdout_line(&run_git(manifest_dir, &["rev-parse", "--git-path", spec])?)?;
    let relative_path = Path::new(&relative);
    let resolved = if relative_path.is_absolute() {
        relative_path.to_path_buf()
    } else {
        Path::new(&git_dir).join(relative_path)
    };
    resolved.to_str().map(ToString::to_string)
}
