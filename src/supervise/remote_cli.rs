//! Candidate-only operator route. Native runtime authority is never reconstructed
//! from a remote output file; publication requires a future trusted recapture seam.
use super::*;
use crate::{
    external_agent::executor::{
        lifecycle::{LifecycleSshClient, OperatorTrust},
        *,
    },
    safe_state::BoundedRegularReader,
};

/// Load only explicit operator capabilities. A plan cannot call this loader.
pub fn bind_operator_ssh(path: &Path) -> Result<remote_execution::SupervisedSshBindGuard> {
    remote_execution::bind_supervised_ssh_hosts(operator_ssh_hosts(path)?)
}

/// Construct the same candidate-only hosts used by the CLI, for controlled embedding.
pub fn operator_ssh_hosts(path: &Path) -> Result<Vec<remote_execution::SupervisedSshHost>> {
    let trust = OperatorTrust::load(path)?;
    let mut hosts = Vec::new();
    for (selection, config) in trust.targets() {
        let client = LifecycleSshClient::new(trust.clone(), config)?;
        hosts.push(remote_execution::SupervisedSshHost::configure(
            selection.clone(),
            Some(config.clone()),
            |_| Ok(client),
            Arc::new(CandidateCoordinator),
        )?);
    }
    Ok(hosts)
}

struct CandidateCoordinator;
const MAX_INPUT: u64 = 1024 * 1024;

impl remote_execution::SupervisedSshCoordinator for CandidateCoordinator {
    fn prepare(&self, _: &ExternalAgentCommand) -> Result<remote_execution::SupervisedSshInputs> {
        bail!("SSH candidate preparation requires assignment scopes")
    }

    fn prepare_for_scopes(
        &self,
        command: &ExternalAgentCommand,
        scopes: &[PathBuf],
    ) -> Result<remote_execution::SupervisedSshInputs> {
        if command.invocation != crate::external_agent::ExternalAgentInvocation::CodexSupervisor
            || command.runtime_adapter.is_some()
            || !command.worker_journal_artifacts.is_empty()
            || !command.read_only_input_files.is_empty()
        {
            bail!("SSH candidate route supports plain Codex assignments only; native runtime capabilities require a remote binding");
        }
        let input = |path: &Path, logical: &str, purpose| -> Result<ManifestEntry> {
            Ok(ManifestEntry::input_file(
                LogicalPath::new(logical)?,
                purpose,
                BoundedRegularReader::read_tree_no_follow(path, MAX_INPUT)?,
            )?)
        };
        let mut entries = vec![input(
            &command.prompt,
            "input/prompt",
            ManifestPurpose::Prompt,
        )?];
        let mut args = vec![
            TypedArg::Literal(BoundedLiteral::new(
                command
                    .program
                    .to_str()
                    .context("SSH program is not UTF8")?,
            )?),
            TypedArg::Literal(BoundedLiteral::new("exec")?),
            TypedArg::Literal(BoundedLiteral::new("--json")?),
        ];
        if let Some(schema) = &command.output_schema {
            entries.push(input(schema, "input/schema", ManifestPurpose::Schema)?);
            args.extend([
                TypedArg::Literal(BoundedLiteral::new("--output-schema")?),
                TypedArg::ManifestPath(LogicalPath::new("input/schema")?),
            ]);
        }
        if let Some(model) = &command.model {
            args.extend([
                TypedArg::Literal(BoundedLiteral::new("--model")?),
                TypedArg::Literal(BoundedLiteral::new(model)?),
            ]);
        }
        for (key, value) in [
            ("model_provider", &command.model_provider),
            ("model_reasoning_effort", &command.reasoning_effort),
        ] {
            if let Some(value) = value {
                args.extend([
                    TypedArg::Literal(BoundedLiteral::new("-c")?),
                    TypedArg::Literal(BoundedLiteral::new(format!(
                        "{key}={}",
                        serde_json::to_string(value)?
                    ))?),
                ]);
            }
        }
        args.extend([
            TypedArg::Literal(BoundedLiteral::new("--output-last-message")?),
            TypedArg::ManifestPath(LogicalPath::new("output/result")?),
            TypedArg::FinalStdinMarker,
        ]);
        entries.push(ManifestEntry::output_path(
            LogicalPath::new("output/result")?,
            ManifestPurpose::DeclaredOutput,
            MAX_INPUT,
        )?);
        entries.push(ManifestEntry::output_path(
            LogicalPath::new("output/events")?,
            ManifestPurpose::DeclaredOutput,
            MAX_INPUT,
        )?);
        let repository = Repository::open(&command.cwd)?;
        let index = repository.index()?;
        let mut total = 0;
        for entry in index.iter() {
            let relative = std::str::from_utf8(&entry.path)?;
            let logical = LogicalPath::new(format!("workspace/{relative}"))?;
            if relative.split('/').any(|p| {
                matches!(
                    p,
                    ".env"
                        | ".ssh"
                        | ".maco"
                        | ".codex"
                        | "auth.json"
                        | "credentials.json"
                        | "credentials"
                        | "id_rsa"
                        | "id_ed25519"
                )
            }) {
                bail!("SSH candidate staging refuses hidden or credential-like tracked paths");
            }
            let bytes =
                BoundedRegularReader::read_tree_no_follow(command.cwd.join(relative), MAX_INPUT)?;
            total += bytes.len();
            if total > 16 * 1024 * 1024 || entries.len() >= 1024 {
                bail!("SSH candidate inputs exceed staging bounds");
            }
            entries.push(ManifestEntry::input_file(
                logical,
                ManifestPurpose::WorkspaceInput,
                bytes,
            )?);
        }
        Ok(remote_execution::SupervisedSshInputs {
            manifest: InputManifest::new(entries)?,
            launch: LaunchSpec::new(
                TypedArgv::new(args)?,
                LogicalPath::new("input/prompt")?,
                BoundedMillis::new(u64::try_from(command.timeout.as_millis())?)?,
            ),
            outputs: OutputPolicy::new(
                4 * MAX_INPUT,
                1024,
                scopes
                    .iter()
                    .map(|s| LogicalPath::new(format!("workspace/{}", s.to_string_lossy())))
                    .collect::<std::result::Result<_, _>>()?,
                vec![
                    DeclaredOutput::new(
                        LogicalPath::new("output/result")?,
                        "application/json",
                        MAX_INPUT,
                    )?,
                    DeclaredOutput::new(
                        LogicalPath::new("output/events")?,
                        "application/x-ndjson",
                        MAX_INPUT,
                    )?,
                ],
                2 * MAX_INPUT,
            )?,
        })
    }

    fn import_candidate(&self, _: &ExternalAgentCommand, _: &CollectedResult) -> Result<()> {
        // The authenticated collection journal is the durable local candidate.
        // A worktree mutation is withheld until native recapture can authorize it.
        bail!("SSH candidate persisted for inspection; native runtime recapture/import is not implemented; remote workspace retained")
    }

    fn recapture(&self, _: &ExternalAgentCommand, _: &CollectedResult) -> Result<ExternalAgentRun> {
        bail!("remote candidate bytes cannot create native runtime evidence")
    }
}
