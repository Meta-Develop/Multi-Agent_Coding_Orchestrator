//! Process-local operator marker for DeepSeek headless qualification.
//!
//! The flag is bound only from explicit CLI intake. Environment variables and
//! serialized plans do not mint it. Binding the flag does not admit writable
//! work: `production_qualified` stays false until a live qualification passes
//! and a later change promotes the capability row.

use anyhow::{bail, Result};
use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
    sync::Mutex,
};

type RunKey = (PathBuf, String);
static OPERATOR_RUNS: Mutex<BTreeSet<RunKey>> = Mutex::new(BTreeSet::new());

pub(crate) struct OperatorRunGuard(RunKey);

impl Drop for OperatorRunGuard {
    fn drop(&mut self) {
        OPERATOR_RUNS
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .remove(&self.0);
    }
}

/// Called only by explicit CLI intake.
pub(crate) fn bind_operator_run(repo: &Path, run_id: &str) -> Result<OperatorRunGuard> {
    if run_id.is_empty() {
        bail!("--qualify-deepseek-headless requires an explicit run id");
    }
    let key = (repo.to_path_buf(), run_id.to_string());
    let mut runs = OPERATOR_RUNS
        .lock()
        .map_err(|_| anyhow::anyhow!("DeepSeek qualification authority lock is poisoned"))?;
    if !runs.insert(key.clone()) {
        bail!("duplicate DeepSeek headless qualification authority for this run");
    }
    Ok(OperatorRunGuard(key))
}

pub(crate) fn operator_flag_bound(repo: &Path, run_id: &str) -> bool {
    OPERATOR_RUNS
        .lock()
        .ok()
        .is_some_and(|runs| runs.contains(&(repo.to_path_buf(), run_id.to_string())))
}

pub(crate) const fn production_qualified() -> bool {
    false
}

pub(crate) fn writable_refusal(operator_flag_bound: bool) -> String {
    crate::runtime_adapter::deepseek::writable_admission_message(
        operator_flag_bound,
        production_qualified(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime_adapter::RuntimeCapabilities;

    #[test]
    fn bound_flag_does_not_admit_writable_work() {
        let dir = tempfile::tempdir().unwrap();
        let unbound = writable_refusal(false);
        assert!(unbound.contains(crate::runtime_adapter::deepseek::WRITABLE_ADMISSION_REFUSAL));
        assert!(unbound.contains("operator flag bound: false"));
        assert!(unbound.contains("production_qualified: false"));
        let _guard = bind_operator_run(dir.path(), "run-1").unwrap();
        assert!(operator_flag_bound(dir.path(), "run-1"));
        assert!(!production_qualified());
        let bound = writable_refusal(operator_flag_bound(dir.path(), "run-1"));
        assert!(bound.contains("operator flag bound: true"));
        assert!(bound.contains("production_qualified: false"));
        assert!(!RuntimeCapabilities::DEEPSEEK.admits_worktree_writable());
        assert!(!RuntimeCapabilities::DEEPSEEK_HEADLESS_READ_ONLY.admits_worktree_writable());
        drop(_guard);
        assert!(!operator_flag_bound(dir.path(), "run-1"));
    }
}
