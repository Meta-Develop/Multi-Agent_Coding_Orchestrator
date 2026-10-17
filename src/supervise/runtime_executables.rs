//! Run-scoped explicit executable bindings for ordinary mixed-runtime supervise.
//! A binding is frozen before reservation, archived as private authenticated
//! evidence, and copied into assignment threads. Without an opt-in binding,
//! single-runtime dispatch retains its existing behavior.

use super::{plan_api, SupervisorRunOptions, SupervisorRuntime};
use crate::{
    artifacts::{ArtifactFileDisposition, ArtifactRunReader, ArtifactRunWriter, RunArtifactFamily},
    external_agent::ExternalAgentCommand,
    orchestrator::RunId,
};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    cell::RefCell,
    marker::PhantomData,
    path::{Path, PathBuf},
    rc::Rc,
    sync::Arc,
};

const SCHEMA_VERSION: u32 = 1;
const ARTIFACT: &str = "runtime_executables/binding.json";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SavedBinding {
    runtime: SupervisorRuntime,
    executable: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SavedAllowlist {
    schema_version: u32,
    run_id: String,
    bindings: Vec<SavedBinding>,
}

#[derive(Debug)]
pub(crate) struct BoundRuntimeExecutables {
    repo: PathBuf,
    run_id: RunId,
    allowlist: plan_api::FrozenHeldOutRuntimeAllowlist,
}

thread_local! {
    static BOUND: RefCell<Option<Arc<BoundRuntimeExecutables>>> = const { RefCell::new(None) };
}

pub(crate) struct RuntimeExecutableGuard {
    previous: Option<Arc<BoundRuntimeExecutables>>,
    _thread_affine: PhantomData<Rc<()>>,
}

impl Drop for RuntimeExecutableGuard {
    fn drop(&mut self) {
        BOUND.with(|slot| *slot.borrow_mut() = self.previous.take());
    }
}

fn install(binding: Option<Arc<BoundRuntimeExecutables>>) -> RuntimeExecutableGuard {
    BOUND.with(|slot| RuntimeExecutableGuard {
        previous: std::mem::replace(&mut *slot.borrow_mut(), binding),
        _thread_affine: PhantomData,
    })
}

pub(crate) fn captured_binding() -> Option<Arc<BoundRuntimeExecutables>> {
    BOUND.with(|slot| slot.borrow().clone())
}

pub(crate) fn install_captured(
    binding: Option<Arc<BoundRuntimeExecutables>>,
) -> RuntimeExecutableGuard {
    install(binding)
}

pub(crate) fn bind_subordinate(
    repo: &Path,
    source_run_id: &RunId,
    subordinate_run_id: &RunId,
) -> Result<Option<RuntimeExecutableGuard>> {
    let Some(source) = captured_binding() else {
        return Ok(None);
    };
    let repo = crate::artifacts::discover_repo_root(repo)?;
    if source.repo != repo || source.run_id != *source_run_id {
        bail!("follow-up source differs from the frozen runtime executable binding");
    }
    let derived = bound_from_allowlist(&repo, subordinate_run_id, source.allowlist.clone());
    Ok(Some(install(Some(derived))))
}

fn require_linux() -> Result<()> {
    if !cfg!(target_os = "linux") {
        bail!("explicit mixed-runtime supervise bindings require Linux containment");
    }
    Ok(())
}

fn bound_from_allowlist(
    repo: &Path,
    run_id: &RunId,
    allowlist: plan_api::FrozenHeldOutRuntimeAllowlist,
) -> Arc<BoundRuntimeExecutables> {
    Arc::new(BoundRuntimeExecutables {
        repo: repo.to_path_buf(),
        run_id: run_id.clone(),
        allowlist,
    })
}

pub(crate) fn bind_new(
    repo: &Path,
    run_id: &RunId,
    primary_runtime: SupervisorRuntime,
    primary_executable: &Path,
    additional: &[(SupervisorRuntime, PathBuf)],
) -> Result<RuntimeExecutableGuard> {
    require_linux()?;
    if additional.is_empty() {
        bail!("explicit mixed-runtime binding requires an additional runtime");
    }
    let repo = crate::artifacts::discover_repo_root(repo)?;
    let allowlist = plan_api::freeze_supervise_runtime_allowlist(
        primary_runtime,
        primary_executable,
        additional,
    )?;
    Ok(install(Some(bound_from_allowlist(
        &repo, run_id, allowlist,
    ))))
}

/// Restore only from a finalized authenticated run. An unfinished source with
/// a binding artifact refuses resume, rather than falling back to the process
/// environment. The supplied paths, when present, must match the saved map.
pub(crate) fn bind_resume(
    repo: &Path,
    run_id: &RunId,
    primary_runtime: SupervisorRuntime,
    supplied_primary: Option<&Path>,
    supplied_additional: &[(SupervisorRuntime, PathBuf)],
) -> Result<Option<(RuntimeExecutableGuard, PathBuf)>> {
    let repo = crate::artifacts::discover_repo_root(repo)?;
    let reader = match ArtifactRunReader::open(&repo, RunArtifactFamily::Supervise, run_id) {
        Ok(reader) => reader,
        Err(error) => {
            let marker = repo
                .join(RunArtifactFamily::Supervise.run_root())
                .join(run_id.as_str())
                .join(ARTIFACT);
            let marker_present = match std::fs::symlink_metadata(&marker) {
                Ok(_) => true,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
                Err(error) => return Err(error).context("cannot inspect runtime binding marker"),
            };
            if marker_present || !supplied_additional.is_empty() {
                bail!("cannot resume explicit runtime bindings from an unfinalized or unauthenticated run: {error:#}");
            }
            return Ok(None);
        }
    };
    let present = reader
        .finalization()
        .files
        .iter()
        .any(|record| record.path.as_path() == Path::new(ARTIFACT));
    if !present {
        if !supplied_additional.is_empty() {
            bail!("existing supervise run has no frozen runtime executable allowlist");
        }
        return Ok(None);
    }
    require_linux()?;
    let saved: SavedAllowlist = serde_json::from_slice(&reader.read(ARTIFACT)?)
        .context("invalid archived runtime executable bindings")?;
    if saved.schema_version != SCHEMA_VERSION || saved.run_id != run_id.as_str() {
        bail!("archived runtime executable binding version or run id mismatch");
    }
    let (first, rest) = saved
        .bindings
        .split_first()
        .context("archived runtime executable allowlist is empty")?;
    if first.runtime != primary_runtime {
        bail!("resumed primary runtime differs from frozen runtime binding");
    }
    let additional = rest
        .iter()
        .map(|entry| (entry.runtime, entry.executable.clone()))
        .collect::<Vec<_>>();
    if additional.is_empty() {
        bail!("archived mixed-runtime allowlist has no additional runtime");
    }
    let allowlist = plan_api::freeze_supervise_runtime_allowlist(
        first.runtime,
        &first.executable,
        &additional,
    )?;
    let current = allowlist
        .bindings()
        .iter()
        .map(|entry| SavedBinding {
            runtime: entry.runtime,
            executable: entry.executable.clone(),
        })
        .collect::<Vec<_>>();
    if current != saved.bindings {
        bail!("archived runtime executable binding changed after canonicalization");
    }
    if let Some(path) = supplied_primary {
        let supplied = super::assignment_execution::canonicalize_explicit_runtime_executable(path)?;
        if supplied != first.executable {
            bail!("--runtime-bin differs from the frozen supervise executable");
        }
    }
    if !supplied_additional.is_empty() {
        let supplied = plan_api::freeze_supervise_runtime_allowlist(
            first.runtime,
            &first.executable,
            supplied_additional,
        )?;
        if supplied != allowlist {
            bail!("--additional-runtime-bin differs from the frozen supervise allowlist");
        }
    }
    let primary = first.executable.clone();
    Ok(Some((
        install(Some(bound_from_allowlist(&repo, run_id, allowlist))),
        primary,
    )))
}

fn require_current(options: &SupervisorRunOptions) -> Result<Option<Arc<BoundRuntimeExecutables>>> {
    let Some(binding) = captured_binding() else {
        return Ok(None);
    };
    let repo = crate::artifacts::discover_repo_root(&options.repo)?;
    if binding.repo != repo || binding.run_id != options.run_id {
        bail!("explicit runtime executable binding belongs to another supervise run");
    }
    Ok(Some(binding))
}

pub(crate) fn selected_program(
    runtime: SupervisorRuntime,
    options: &SupervisorRunOptions,
) -> Result<Option<PathBuf>> {
    let Some(binding) = require_current(options)? else {
        return Ok(None);
    };
    let executable = binding.allowlist.executable_for(runtime).with_context(|| {
        format!(
            "selected runtime '{}' has no frozen executable binding",
            runtime.as_str()
        )
    })?;
    Ok(Some(executable.to_path_buf()))
}

/// Outer `None` means no explicit run binding; inner `None` means this runtime
/// was not declared and its ambient catalog must not be consulted.
pub(crate) fn catalog_program(
    repo: &Path,
    runtime: SupervisorRuntime,
) -> Result<Option<Option<PathBuf>>> {
    let Some(binding) = captured_binding() else {
        return Ok(None);
    };
    let repo = crate::artifacts::discover_repo_root(repo)?;
    if binding.repo != repo {
        bail!("runtime catalog requested for another supervise repository");
    }
    Ok(Some(
        binding
            .allowlist
            .executable_for(runtime)
            .map(Path::to_path_buf),
    ))
}

pub(crate) fn validate_launch(command: &ExternalAgentCommand) -> Result<()> {
    if let Some(binding) = captured_binding() {
        plan_api::validate_held_out_declared_launch(command, &binding.allowlist)
            .context("ordinary supervise refused a command outside its frozen runtime allowlist")?;
    }
    Ok(())
}

pub(crate) fn require_binding_repo_run(repo: &Path, run_id: &RunId) -> Result<()> {
    if let Some(binding) = captured_binding() {
        let repo = crate::artifacts::discover_repo_root(repo)?;
        if binding.repo != repo || binding.run_id != *run_id {
            bail!("explicit runtime executable binding belongs to another supervise run");
        }
    }
    Ok(())
}

pub(crate) fn archive_current(
    writer: &mut ArtifactRunWriter,
    repo: &Path,
    run_id: &RunId,
) -> Result<()> {
    require_binding_repo_run(repo, run_id)?;
    let Some(binding) = captured_binding() else {
        return Ok(());
    };
    let saved = SavedAllowlist {
        schema_version: SCHEMA_VERSION,
        run_id: binding.run_id.as_str().to_string(),
        bindings: binding
            .allowlist
            .bindings()
            .iter()
            .map(|entry| SavedBinding {
                runtime: entry.runtime,
                executable: entry.executable.clone(),
            })
            .collect(),
    };
    writer.write_json(ARTIFACT, &saved, ArtifactFileDisposition::PrivateEvidence)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn explicit_bindings_reject_implicit_duplicate_and_missing_executables() -> Result<()> {
        let (_temporary, repo) = super::super::tests::injected_repository();
        let primary = repo.join("codex-bin");
        let grok = repo.join("grok-bin");
        std::fs::write(&primary, b"codex")?;
        std::fs::write(&grok, b"grok")?;
        let run_id = RunId::new("mixed-runtime-bindings")?;
        let additional = [(SupervisorRuntime::Grok, grok.clone())];
        let guard = bind_new(
            &repo,
            &run_id,
            SupervisorRuntime::Codex,
            &primary,
            &additional,
        )?;
        let held = captured_binding().context("bound allowlist")?;
        assert_eq!(held.allowlist.primary_runtime(), SupervisorRuntime::Codex);
        assert_eq!(
            held.allowlist.executable_for(SupervisorRuntime::Grok),
            Some(grok.as_path())
        );
        assert!(held
            .allowlist
            .executable_for(SupervisorRuntime::Cursor)
            .is_none());
        assert_eq!(
            catalog_program(&repo, SupervisorRuntime::Grok)?,
            Some(Some(grok.clone()))
        );
        assert_eq!(
            catalog_program(&repo, SupervisorRuntime::Cursor)?,
            Some(None)
        );
        let mut grok_command = ExternalAgentCommand::codex(
            &grok,
            &repo,
            repo.join("prompt.txt"),
            repo.join("log.jsonl"),
            repo.join("report.json"),
            std::time::Duration::from_secs(1),
        )
        .with_runtime_adapter(
            SupervisorRuntime::Grok,
            crate::runtime_adapter::RuntimeAdapterConfig::defaults(SupervisorRuntime::Grok),
        );
        validate_launch(&grok_command)?;
        grok_command.program = primary.clone();
        assert!(validate_launch(&grok_command).is_err());
        grok_command.program = grok.clone();
        let subordinate = RunId::new("mixed-runtime-subordinate")?;
        let nested = bind_subordinate(&repo, &run_id, &subordinate)?
            .context("subordinate inherited exact allowlist")?;
        assert_eq!(
            captured_binding().context("subordinate")?.run_id,
            subordinate
        );
        assert_eq!(
            captured_binding().context("subordinate")?.allowlist,
            held.allowlist
        );
        drop(nested);
        assert_eq!(
            captured_binding().context("restored source")?.run_id,
            run_id
        );
        drop(guard);
        assert!(captured_binding().is_none());
        assert_eq!(catalog_program(&repo, SupervisorRuntime::Grok)?, None);

        assert!(bind_new(
            &repo,
            &run_id,
            SupervisorRuntime::Codex,
            Path::new("codex"),
            &additional
        )
        .is_err());
        assert!(bind_new(
            &repo,
            &run_id,
            SupervisorRuntime::Codex,
            &primary,
            &[(SupervisorRuntime::Grok, repo.join("missing"))]
        )
        .is_err());
        assert!(bind_new(
            &repo,
            &run_id,
            SupervisorRuntime::Codex,
            &primary,
            &[(SupervisorRuntime::Codex, grok.clone())]
        )
        .is_err());
        assert!(bind_new(
            &repo,
            &run_id,
            SupervisorRuntime::Codex,
            &primary,
            &[(SupervisorRuntime::Fake, grok.clone())]
        )
        .is_err());
        assert!(bind_new(
            &repo,
            &run_id,
            SupervisorRuntime::Codex,
            &primary,
            &[
                (SupervisorRuntime::Grok, grok.clone()),
                (SupervisorRuntime::Grok, grok)
            ]
        )
        .is_err());
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn finalized_allowlist_restores_exact_paths_and_refuses_substitution() -> Result<()> {
        let (_temporary, repo) = super::super::tests::injected_repository();
        let primary = repo.join("codex-bin");
        let grok = repo.join("grok-bin");
        let other = repo.join("other-bin");
        for path in [&primary, &grok, &other] {
            std::fs::write(path, b"executable")?;
        }
        let run_id = RunId::new("mixed-runtime-resume")?;
        {
            let _guard = bind_new(
                &repo,
                &run_id,
                SupervisorRuntime::Codex,
                &primary,
                &[(SupervisorRuntime::Grok, grok.clone())],
            )?;
            let mut writer = ArtifactRunWriter::reserve(
                &repo,
                RunArtifactFamily::Supervise,
                run_id.clone(),
                "mixed-runtime-test",
            )?;
            archive_current(&mut writer, &repo, &run_id)?;
            let final_path = RunArtifactFamily::Supervise.final_report_relative_path();
            writer.write_json(
                &final_path,
                &serde_json::json!({"run_id": run_id.as_str()}),
                ArtifactFileDisposition::Publishable,
            )?;
            writer.finalize(&final_path, false)?;
        }
        assert!(captured_binding().is_none());
        let (guard, restored_primary) =
            bind_resume(&repo, &run_id, SupervisorRuntime::Codex, None, &[])?
                .context("frozen binding")?;
        assert_eq!(restored_primary, primary);
        assert_eq!(
            captured_binding()
                .context("restored")?
                .allowlist
                .executable_for(SupervisorRuntime::Grok),
            Some(grok.as_path())
        );
        drop(guard);
        assert!(bind_resume(&repo, &run_id, SupervisorRuntime::Grok, None, &[]).is_err());
        assert!(bind_resume(&repo, &run_id, SupervisorRuntime::Codex, Some(&other), &[]).is_err());
        assert!(bind_resume(
            &repo,
            &run_id,
            SupervisorRuntime::Codex,
            None,
            &[(SupervisorRuntime::Grok, other)]
        )
        .is_err());
        Ok(())
    }
}
