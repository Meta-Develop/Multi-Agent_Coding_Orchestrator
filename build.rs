//! Records a bounded source revision and cleanliness for compile-time identity.
//!
//! An explicit packager state (`MACO_SOURCE_STATE`) is used with
//! `MACO_SOURCE_REVISION` and skips git. Otherwise git is probed only at
//! `CARGO_MANIFEST_DIR`. A missing git binary, a failed probe, or a revision
//! that is not 40 lowercase hex digits records `unknown` and an empty
//! revision. Metadata gaps do not fail the build.

use std::path::Path;
use std::process::{Command, Stdio};

const REVISION_HEX_LEN: usize = 40;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=MACO_SOURCE_REVISION");
    println!("cargo:rerun-if-env-changed=MACO_SOURCE_STATE");
    if let Ok(manifest_dir) = std::env::var("CARGO_MANIFEST_DIR") {
        emit_rerun_if_file(&manifest_dir, ".git/HEAD");
        emit_rerun_if_file(&manifest_dir, ".git/index");
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
    let revision = canonical_revision(revision);
    match (state, revision) {
        ("clean", Some(revision)) => (revision, "clean"),
        ("dirty", Some(revision)) => (revision, "dirty"),
        _ => (String::new(), "unknown"),
    }
}

/// Emit a rerun directive only when the path is an existing file. A `.git`
/// gitfile has no child `HEAD` or `index`; that absence is ignored.
fn emit_rerun_if_file(manifest_dir: &str, relative: &str) {
    let path = Path::new(manifest_dir).join(relative);
    if let Ok(metadata) = std::fs::metadata(&path) {
        if metadata.is_file() {
            if let Some(text) = path.to_str() {
                println!("cargo:rerun-if-changed={text}");
            }
        }
    }
}
