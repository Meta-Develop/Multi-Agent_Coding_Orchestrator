use super::*;
use crate::executor::{OpenSshTransport, SshConfig};
use std::{
    process::{Command, Stdio},
    sync::Arc,
    time::{Duration, Instant},
};

#[derive(Clone)]
pub struct LifecycleSshClient {
    trust: Arc<OperatorTrust>,
    config: SshConfig,
}

impl LifecycleSshClient {
    pub fn new(trust: Arc<OperatorTrust>, config: &SshConfig) -> Result<Self> {
        trust.validate()?;
        if !trust.targets().iter().any(|(_, c)| c == config) {
            bail!("configuration is not in operator trust");
        }
        Ok(Self {
            trust,
            config: config.clone(),
        })
    }

    fn call<T: DeserializeOwned + Send + 'static>(
        &self,
        request: Request,
        maximum: u64,
    ) -> TransportCall<T> {
        let mut spawned = false;
        match self.exchange(request, maximum, &mut spawned) {
            Ok(reply) => TransportCall::Response(reply),
            Err(error) if !spawned => {
                TransportCall::NotStarted(TransportNotStarted::new(format!("{error:#}")))
            }
            Err(error) => TransportCall::LostResponse {
                detail: format!("lifecycle transport failed: {error:#}"),
            },
        }
    }

    fn exchange<T: DeserializeOwned + Send + 'static>(
        &self,
        request: Request,
        maximum: u64,
        spawned: &mut bool,
    ) -> Result<T> {
        let timeout = Duration::from_millis(self.config.limits().execution_timeout_millis);
        let deadline = Instant::now()
            .checked_add(timeout)
            .context("SSH deadline overflow")?;
        self.trust.validate_until(Some(deadline))?;
        let target = request.target();
        if !self
            .trust
            .targets()
            .iter()
            .any(|(s, c)| s.ssh_target() == Some(target) && c == &self.config)
        {
            bail!("request target differs from operator trust");
        }
        let limits = self.config.limits();
        if let Request::Stage(stage) = &request {
            let entries = stage.stage.manifest().entries();
            let total: usize = entries
                .iter()
                .map(|e| e.input_bytes().map_or(0, <[u8]>::len))
                .sum();
            if entries.len() > limits.max_workspace_entries
                || total > limits.max_workspace_bytes
                || entries.iter().any(|e| {
                    e.input_bytes()
                        .is_some_and(|b| b.len() > limits.max_file_bytes)
                })
            {
                bail!("staged inputs exceed operator limits");
            }
        }
        let mut payload = Vec::new();
        write_frame_until(
            &mut payload,
            &request,
            limits.max_request_bytes as u64,
            Some(deadline),
        )?;
        // Only share option construction with the atomic client, never its wire protocol.
        let (identity, known_hosts) = self.trust.credential_paths(&self.config)?;
        let mut args =
            OpenSshTransport::command_arguments_with_trust(&self.config, &identity, &known_hosts);
        args.extend([
            "__supervised-ssh-helper".into(),
            self.config.remote_root().into(),
            self.config.host_id().into(),
        ]);
        let mut command = Command::new(self.trust.binary_path());
        command
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .env_remove("SSH_AUTH_SOCK")
            .env_remove("SSH_ASKPASS")
            .env_remove("DISPLAY")
            .env("SSH_ASKPASS_REQUIRE", "never");
        let maximum = maximum.min(limits.max_receipt_bytes as u64).min(MAX_FRAME);
        let response = super::process::run(
            command,
            self.trust.binary_fd(),
            &payload,
            maximum,
            deadline,
            timeout,
            spawned,
        )?;
        check_deadline(Some(deadline))?;
        let response = serde_json::from_reader(DeadlineReader {
            inner: std::io::Cursor::new(response),
            deadline,
        })
        .context("invalid lifecycle payload")?;
        check_deadline(Some(deadline))?;
        Ok(response)
    }
}

impl SshTransport for LifecycleSshClient {
    fn preflight(&self) -> ExecutorResult<()> {
        (|| -> Result<()> {
            let deadline = Instant::now()
                .checked_add(Duration::from_millis(
                    self.config.limits().execution_timeout_millis,
                ))
                .context("SSH preflight deadline overflow")?;
            self.trust.validate_until(Some(deadline))?;
            super::process::preflight(deadline)
        })()
        .map_err(|error| TransportNotStarted::new(format!("{error:#}")).into())
    }

    fn stage(&self, r: StageTransportRequest) -> TransportCall<StageTransportReceipt> {
        self.call(Request::Stage(r), 64 * 1024)
    }
    fn launch(&self, r: LaunchTransportRequest) -> TransportCall<LaunchReceipt> {
        self.call(Request::Launch(r), 64 * 1024)
    }
    fn status(&self, r: StatusTransportRequest) -> TransportCall<StatusReceipt> {
        self.call(Request::Status(r), 64 * 1024)
    }
    fn wait(&self, r: WaitTransportRequest) -> TransportCall<WaitReceipt> {
        self.call(Request::Wait(r), 64 * 1024)
    }
    fn control(&self, r: ControlTransportRequest) -> TransportCall<ControlReceipt> {
        self.call(Request::Control(r), 64 * 1024)
    }
    fn collect(&self, r: CollectionTransportRequest) -> TransportCall<CollectionReceipt> {
        // JSON encodes byte vectors as decimal arrays. The frame bound accounts
        // for that expansion; the typed receipt is independently checked below.
        let max = r.read_limits.receipt_max_bytes().saturating_mul(4);
        let limits = r.read_limits.clone();
        match self.call(Request::Collect(r), max) {
            TransportCall::Response(r) => {
                let r: CollectionReceipt = r;
                match CollectionReceipt::from_wire_bounded(
                    r.protocol_version,
                    r.key,
                    r.identity,
                    r.policy_digest,
                    r.patch,
                    r.changed_paths,
                    r.outputs,
                    r.manifest_digest,
                    &limits,
                ) {
                    Ok(r) => TransportCall::Response(r),
                    Err(e) => TransportCall::LostResponse {
                        detail: e.to_string(),
                    },
                }
            }
            lost => lost,
        }
    }
    fn cleanup(&self, r: CleanupTransportRequest) -> TransportCall<CleanupReceipt> {
        self.call(Request::Cleanup(r), 64 * 1024)
    }
}

struct DeadlineReader<R> {
    inner: R,
    deadline: Instant,
}
impl<R: Read> Read for DeadlineReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        if Instant::now() >= self.deadline {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "response decoding deadline expired",
            ));
        }
        self.inner.read(buffer)
    }
}
