//! Coordinator-facing executor seam for #61 Phase B.
//!
//! This first slice lands a shared [`AgentExecutor`] trait with a working
//! [`LocalExecutor`] and a typed, fail-closed [`SshExecutor`]. It does not open
//! an SSH client, spawn a helper, or take claim/merge authority away from the
//! local coordinator. The existing remote-lifecycle protocol under
//! `external_agent::executor` stays in place for later transport work.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

const MAX_OPAQUE_ID_BYTES: usize = 128;
const MAX_ARG_COUNT: usize = 64;
const MAX_ARG_BYTES: usize = 4096;
const MAX_ARGV_BYTES: usize = 16 * 1024;

/// Operator-selected executor kind. SSH is a named seam only in this slice.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutorKind {
    Local,
    Ssh,
}

/// Bounded assignment the coordinator is willing to hand to an executor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutorRequest {
    pub assignment_id: String,
    pub argv: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub working_directory: Option<PathBuf>,
}

/// Outcome of one executor admission or fail-closed refusal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutorOutcome {
    pub assignment_id: String,
    pub kind: ExecutorKind,
    pub status: ExecutorStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutorStatus {
    Admitted,
    Refused { reason: String },
}

/// Shared Local/SSH executor contract. Local is implemented; SSH refuses live use.
pub trait AgentExecutor: Send + Sync {
    fn kind(&self) -> ExecutorKind;
    fn execute(&self, request: &ExecutorRequest) -> Result<ExecutorOutcome>;
}

/// Local compatibility executor. It validates a request and forwards a caller
/// runner; it does not reconstruct process launch, review, or merge.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct LocalExecutor;

impl LocalExecutor {
    pub fn run<R, T>(&self, request: &ExecutorRequest, runner: R) -> Result<T>
    where
        R: FnOnce(&ExecutorRequest) -> Result<T>,
    {
        validate_executor_request(request).context("LocalExecutor rejected the assignment")?;
        runner(request)
    }
}

impl AgentExecutor for LocalExecutor {
    fn kind(&self) -> ExecutorKind {
        ExecutorKind::Local
    }

    fn execute(&self, request: &ExecutorRequest) -> Result<ExecutorOutcome> {
        self.run(request, |request| {
            Ok(ExecutorOutcome {
                assignment_id: request.assignment_id.clone(),
                kind: ExecutorKind::Local,
                status: ExecutorStatus::Admitted,
            })
        })
    }
}

/// Typed SSH seam. Construction records a host identity only; execution fails
/// closed and never opens a network socket or SSH client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshExecutor {
    host_id: String,
}

impl SshExecutor {
    pub fn new(host_id: impl Into<String>) -> Result<Self> {
        let host_id = host_id.into();
        validate_opaque_id("host_id", &host_id)?;
        Ok(Self { host_id })
    }

    pub fn host_id(&self) -> &str {
        &self.host_id
    }
}

impl AgentExecutor for SshExecutor {
    fn kind(&self) -> ExecutorKind {
        ExecutorKind::Ssh
    }

    fn execute(&self, request: &ExecutorRequest) -> Result<ExecutorOutcome> {
        validate_executor_request(request).context("SshExecutor rejected the assignment")?;
        bail!(
            "SshExecutor host '{}' is an unimplemented seam; live SSH execution is not available",
            self.host_id
        )
    }
}

/// Owned handle used when the coordinator selects an executor by kind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecutorHandle {
    Local(LocalExecutor),
    Ssh(SshExecutor),
}

impl ExecutorHandle {
    pub fn local() -> Self {
        Self::Local(LocalExecutor)
    }

    pub fn ssh(host_id: impl Into<String>) -> Result<Self> {
        Ok(Self::Ssh(SshExecutor::new(host_id)?))
    }

    pub fn kind(&self) -> ExecutorKind {
        match self {
            Self::Local(_) => ExecutorKind::Local,
            Self::Ssh(_) => ExecutorKind::Ssh,
        }
    }
}

impl AgentExecutor for ExecutorHandle {
    fn kind(&self) -> ExecutorKind {
        match self {
            Self::Local(_) => ExecutorKind::Local,
            Self::Ssh(_) => ExecutorKind::Ssh,
        }
    }

    fn execute(&self, request: &ExecutorRequest) -> Result<ExecutorOutcome> {
        match self {
            Self::Local(executor) => executor.execute(request),
            Self::Ssh(executor) => executor.execute(request),
        }
    }
}

fn validate_executor_request(request: &ExecutorRequest) -> Result<()> {
    validate_opaque_id("assignment_id", &request.assignment_id)?;
    if request.argv.is_empty() {
        bail!("executor argv must contain at least one argument");
    }
    if request.argv.len() > MAX_ARG_COUNT {
        bail!(
            "executor argv contains {} arguments but at most {MAX_ARG_COUNT} are allowed",
            request.argv.len()
        );
    }
    let mut total_bytes = 0usize;
    for (index, argument) in request.argv.iter().enumerate() {
        if argument.is_empty() {
            bail!("executor argv[{index}] cannot be empty");
        }
        if argument.len() > MAX_ARG_BYTES {
            bail!(
                "executor argv[{index}] contains {} bytes but at most {MAX_ARG_BYTES} are allowed",
                argument.len()
            );
        }
        total_bytes = total_bytes
            .checked_add(argument.len())
            .context("executor argv byte count overflowed")?;
        if total_bytes > MAX_ARGV_BYTES {
            bail!("executor argv exceeds its {MAX_ARGV_BYTES}-byte aggregate limit");
        }
    }
    if let Some(working_directory) = request.working_directory.as_deref() {
        validate_working_directory(working_directory)?;
    }
    Ok(())
}

fn validate_working_directory(path: &Path) -> Result<()> {
    if path.as_os_str().is_empty() {
        bail!("executor working_directory cannot be empty");
    }
    if !path.is_absolute() {
        bail!("executor working_directory must be an absolute path");
    }
    Ok(())
}

fn validate_opaque_id(field: &str, value: &str) -> Result<()> {
    if value.is_empty() {
        bail!("executor {field} cannot be empty");
    }
    if value.len() > MAX_OPAQUE_ID_BYTES {
        bail!("executor {field} is too long");
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        bail!("executor {field} must contain only ASCII letters, digits, '.', '-', or '_'");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn local_request() -> ExecutorRequest {
        ExecutorRequest {
            assignment_id: "assign-001".to_string(),
            argv: vec!["codex".to_string(), "exec".to_string()],
            working_directory: Some(PathBuf::from("/tmp/maco-local-executor")),
        }
    }

    #[test]
    fn local_executor_admits_and_forwards_a_valid_request() {
        let executor = LocalExecutor;
        let request = local_request();
        let calls = AtomicUsize::new(0);
        let forwarded = executor
            .run(&request, |received| {
                calls.fetch_add(1, Ordering::SeqCst);
                assert_eq!(received, &request);
                Ok(received.assignment_id.clone())
            })
            .expect("forward local request");
        assert_eq!(forwarded, "assign-001");
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        let outcome = executor.execute(&request).expect("admit local request");
        assert_eq!(outcome.kind, ExecutorKind::Local);
        assert_eq!(outcome.status, ExecutorStatus::Admitted);
        assert_eq!(outcome.assignment_id, "assign-001");
    }

    #[test]
    fn local_executor_rejects_invalid_requests() {
        let executor = LocalExecutor;
        let missing_id = ExecutorRequest {
            assignment_id: String::new(),
            argv: vec!["codex".to_string()],
            working_directory: None,
        };
        let error = executor
            .execute(&missing_id)
            .expect_err("empty assignment id");
        let message = format!("{error:#}");
        assert!(
            message.contains("assignment_id cannot be empty"),
            "{message}"
        );

        let relative = ExecutorRequest {
            assignment_id: "assign-001".to_string(),
            argv: vec!["codex".to_string()],
            working_directory: Some(PathBuf::from("relative/work")),
        };
        let error = executor
            .execute(&relative)
            .expect_err("relative working directory");
        let message = format!("{error:#}");
        assert!(
            message.contains("working_directory must be an absolute path"),
            "{message}"
        );
    }

    #[test]
    fn ssh_executor_is_a_fail_closed_seam_without_live_ssh() {
        let error = SshExecutor::new("").expect_err("empty host");
        assert!(error.to_string().contains("host_id cannot be empty"));

        let executor = SshExecutor::new("home-lxc-a").expect("typed ssh seam");
        assert_eq!(executor.host_id(), "home-lxc-a");
        assert_eq!(executor.kind(), ExecutorKind::Ssh);
        let error = executor
            .execute(&local_request())
            .expect_err("live SSH must stay closed");
        let message = error.to_string();
        assert!(message.contains("unimplemented seam"), "{message}");
        assert!(message.contains("live SSH"), "{message}");
        assert!(!message.contains("ssh -"), "{message}");
    }

    #[test]
    fn executor_handle_selects_local_or_the_ssh_seam() {
        let local = ExecutorHandle::local();
        assert_eq!(local.kind(), ExecutorKind::Local);
        let object_safe: &dyn AgentExecutor = &local;
        let outcome = object_safe
            .execute(&local_request())
            .expect("local handle admits");
        assert_eq!(outcome.status, ExecutorStatus::Admitted);

        let ssh = ExecutorHandle::ssh("home-lxc-a").expect("ssh handle");
        assert_eq!(ssh.kind(), ExecutorKind::Ssh);
        let object_safe: &dyn AgentExecutor = &ssh;
        let error = object_safe
            .execute(&local_request())
            .expect_err("ssh handle stays closed");
        assert!(error.to_string().contains("unimplemented seam"));
    }
}
