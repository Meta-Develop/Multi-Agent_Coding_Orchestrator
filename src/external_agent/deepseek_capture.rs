//! Parent-held DeepSeek launch input and native report handoff.
use super::*;
use crate::runtime_adapter::deepseek;

/// Descriptive public launch evidence; only the live parent holds the snapshot.
#[derive(Clone, PartialEq, Eq, Serialize)]
pub(super) struct LaunchPatch {
    path: PathBuf,
    sha256: String,
    model: String,
    effort: String,
    #[serde(skip)]
    snapshot: crate::process_runner::ReadOnlyInputSnapshot,
}

impl LaunchPatch {
    pub(super) fn snapshot(&self) -> crate::process_runner::ReadOnlyInputSnapshot {
        self.snapshot.clone()
    }

    fn matches(&self, spec: &ExternalAgentCommand) -> Result<()> {
        let model = deepseek::validate_model(spec.model.as_deref())?;
        let effort = deepseek::validate_effort(spec.reasoning_effort.as_deref())?;
        let expected = deepseek::privacy_patch_document(model, effort)?;
        if self.path != deepseek::launch_patch_path(&spec.prompt)
            || self.model != model
            || self.effort != effort
            || self.sha256 != sha256_hex(expected.as_bytes())
        {
            bail!("DeepSeek held launch patch differs from the requested attempt or controls");
        }
        Ok(())
    }
}

pub(super) fn bind_launch(
    spec: &ExternalAgentCommand,
    report: &mut ExternalAgentRun,
) -> Result<()> {
    let model = deepseek::validate_model(spec.model.as_deref())?;
    let effort = deepseek::validate_effort(spec.reasoning_effort.as_deref())?;
    let document = deepseek::privacy_patch_document(model, effort)?;
    let path = deepseek::prepare_launch_patch(&spec.prompt, model, effort)?;
    let sha256 = sha256_hex(document.as_bytes());
    // Capture exact expected bytes, then let the process runner materialize and unlink a
    // private read-only backing before target release. Later path mutation cannot change it.
    let snapshot =
        crate::process_runner::ReadOnlyInputSnapshot::capture_launch_patch(&path, &sha256)?;
    report.stdout.run_metadata.deepseek_launch_patch = Some(LaunchPatch {
        path,
        sha256,
        model: model.into(),
        effort: effort.into(),
        snapshot,
    });
    Ok(())
}

pub(super) fn capture(spec: &ExternalAgentCommand, stdout: &[u8]) -> Result<Vec<u8>> {
    deepseek::validate_model(spec.model.as_deref())?;
    deepseek::validate_effort(spec.reasoning_effort.as_deref())?;
    let parsed = deepseek::parse_event_stream(stdout, spec.model.as_deref())?;
    if !parsed.completed {
        bail!("DeepSeek stream has no unique completed final answer");
    }
    Ok(parsed
        .final_text
        .context("DeepSeek completed final has no text")?
        .into_bytes())
}

impl ExternalAgentRun {
    pub(crate) fn deepseek_research_paths(
        &self,
        spec: &ExternalAgentCommand,
    ) -> Result<Vec<PathBuf>> {
        if spec.invocation != ExternalAgentInvocation::DeepSeek
            || spec.workspace_access != WorkspaceAccess::ReadOnly
            || self.cwd != spec.cwd
            || self.exit_code != Some(0)
            || self.timed_out
            || self.error.is_some()
            || !self.publishable
            || self.stdout.raw_capture_truncated()
        {
            bail!("DeepSeek researcher requires complete successful read-only capture");
        }
        self.stdout
            .run_metadata
            .deepseek_launch_patch
            .as_ref()
            .context("DeepSeek held launch patch evidence is unavailable")?
            .matches(spec)?;
        let parsed = deepseek::parse_event_stream(self.stdout_bytes(), spec.model.as_deref())?;
        let cwd = parsed
            .cwd
            .as_deref()
            .context("DeepSeek session cwd is unavailable")?;
        if !parsed.completed
            || deepseek::normalized_source_path(cwd, &spec.cwd)?
                != deepseek::normalized_source_path(&spec.cwd, &spec.cwd)?
            || parsed.final_text.as_deref().map(str::as_bytes) != self.output_last_message()
        {
            bail!("DeepSeek completed report or workspace differs from its held stream");
        }
        parsed
            .successful_reads
            .iter()
            .map(|path| deepseek::normalized_source_path(path, &spec.cwd))
            .collect()
    }
}
