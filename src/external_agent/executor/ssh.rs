use super::types::*;

/// Object-safe remote executor lifecycle used internally by the future supervisor
/// integration seam. [`LocalExecutor`](super::LocalExecutor) intentionally preserves
/// the existing atomic callback instead of pretending to implement this lifecycle.
pub trait AgentExecutor: Send + Sync {
    fn stage(&self, request: StageRequest) -> ExecutorResult<Effect<StagedAssignment>>;
    fn launch(&self, request: LaunchRequest) -> ExecutorResult<Effect<LaunchReceipt>>;
    fn status(&self, request: StatusRequest) -> ExecutorResult<ExecutionStatus>;
    fn wait(&self, request: WaitRequest) -> ExecutorResult<WaitOutcome>;
    fn terminate(&self, request: TerminateRequest) -> ExecutorResult<Effect<TerminationReceipt>>;
    fn collect(&self, request: CollectRequest) -> ExecutorResult<Effect<CollectedResult>>;
}

/// Typed transport boundary for the fixed remote helper.
///
/// Implementations receive structured envelopes only. This interface exposes no
/// command string, shell interpolation surface, process launcher, or credential.
/// Every implementation must enforce the request's [`TransportReadLimits`] while
/// decoding length prefixes and before allocating response buffers. The bounded
/// artifact constructors are a second validation layer, not permission to decode
/// an unbounded remote response first.
pub trait SshTransport: Send + Sync {
    fn stage(&self, request: StageTransportRequest) -> TransportCall<StageTransportReceipt>;
    fn launch(&self, request: LaunchTransportRequest) -> TransportCall<LaunchReceipt>;
    fn status(&self, request: StatusTransportRequest) -> TransportCall<StatusReceipt>;
    fn wait(&self, request: WaitTransportRequest) -> TransportCall<WaitReceipt>;
    fn control(&self, request: ControlTransportRequest) -> TransportCall<ControlReceipt>;
    fn collect(&self, request: CollectionTransportRequest) -> TransportCall<CollectionReceipt>;
    fn cleanup(&self, request: CleanupTransportRequest) -> TransportCall<CleanupReceipt>;
}

#[derive(Debug)]
pub struct SshExecutor<T> {
    target: SshTargetConfig,
    transport: T,
}

impl<T> SshExecutor<T> {
    pub fn new(target: SshTargetConfig, transport: T) -> Self {
        Self { target, transport }
    }

    pub fn target(&self) -> &SshTargetConfig {
        &self.target
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }
}

impl<T: SshTransport> AgentExecutor for SshExecutor<T> {
    fn stage(&self, request: StageRequest) -> ExecutorResult<Effect<StagedAssignment>> {
        self.require_target_host(&request.identity.host_id)?;
        request.manifest.revalidate()?;
        let expected_key =
            derive_assignment_key("stage", &request.identity, request.manifest.digest());
        if request.key != expected_key {
            return Err(ExecutorError::InvalidField {
                field: "stage idempotency key",
                reason: "is not bound to the host/run/assignment/nonce/manifest digest".to_string(),
            });
        }
        let key = request.key.clone();
        let reconciliation_key = key.clone();
        let call = self.transport.stage(StageTransportRequest {
            target: self.target.clone(),
            stage: request.clone(),
        });
        let receipt = match call {
            TransportCall::Response(receipt) => receipt,
            TransportCall::LostResponse { detail } => {
                return Ok(Effect::Uncertain(Box::new(UncertainEffect {
                    operation: Operation::Stage,
                    key: reconciliation_key.clone(),
                    reconciliation: ReconciliationTarget::StageOperator(StageLookup {
                        identity: request.identity,
                        manifest_digest: request.manifest.digest().clone(),
                        stage_key: reconciliation_key,
                        operator_only: true,
                    }),
                    detail,
                })));
            }
        };
        require_protocol(Operation::Stage, receipt.protocol_version)?;
        require_equal(
            Operation::Stage,
            &receipt.key,
            &key,
            "idempotency key does not match the request",
        )?;
        require_equal(
            Operation::Stage,
            &receipt.identity,
            &request.identity,
            "assignment identity does not match the request",
        )?;
        require_equal(
            Operation::Stage,
            &receipt.staged_digest,
            request.manifest.digest(),
            "staged digest does not match the manifest",
        )?;
        Ok(Effect::Confirmed(StagedAssignment {
            identity: request.identity,
            staged_digest: receipt.staged_digest,
            session_id: receipt.session_id,
            workspace_id: receipt.workspace_id,
            manifest: request.manifest,
        }))
    }

    fn launch(&self, request: LaunchRequest) -> ExecutorResult<Effect<LaunchReceipt>> {
        self.require_target_host(&request.staged.identity.host_id)?;
        validate_launch_manifest(&request)?;
        let submitted = SubmittedLaunchIdentity::for_launch(&request.staged, &request.spec);
        let call = self.transport.launch(LaunchTransportRequest {
            target: self.target.clone(),
            submitted: submitted.clone(),
            argv: request.spec.argv,
            stdin: request.spec.stdin,
            deadline: request.spec.deadline,
        });
        let receipt = match call {
            TransportCall::Response(receipt) => receipt,
            TransportCall::LostResponse { detail } => {
                return Ok(Effect::Uncertain(Box::new(UncertainEffect {
                    operation: Operation::Launch,
                    key: submitted.launch_key.clone(),
                    reconciliation: ReconciliationTarget::Execution(ExecutionQuery::Submitted(
                        submitted,
                    )),
                    detail,
                })));
            }
        };
        validate_launch_receipt(&submitted, &receipt)?;
        Ok(Effect::Confirmed(receipt))
    }

    fn status(&self, request: StatusRequest) -> ExecutorResult<ExecutionStatus> {
        self.require_query_host(&request.query)?;
        let key = derive_query_key("status", &request.query);
        let call = self.transport.status(StatusTransportRequest {
            target: self.target.clone(),
            key: key.clone(),
            query: request.query.clone(),
        });
        let receipt = match call {
            TransportCall::Response(receipt) => receipt,
            TransportCall::LostResponse { detail } => {
                return Err(ExecutorError::TransportLost {
                    operation: Operation::Status,
                    detail,
                });
            }
        };
        require_protocol(Operation::Status, receipt.protocol_version)?;
        require_equal(
            Operation::Status,
            &receipt.key,
            &key,
            "idempotency key does not match the request",
        )?;
        require_equal(
            Operation::Status,
            &receipt.query,
            &request.query,
            "status query does not match the request",
        )?;
        if let Some(identity) = receipt.status.identity() {
            require_identity_matches_query(Operation::Status, identity, &request.query)?;
        }
        Ok(receipt.status)
    }

    fn wait(&self, request: WaitRequest) -> ExecutorResult<WaitOutcome> {
        self.require_target_host(&request.identity.host_id)?;
        let key = derive_wait_key("wait", &request.identity, request.spec.max_wait);
        let receipt = self.call_wait(
            Operation::Wait,
            key,
            request.identity,
            request.spec.max_wait,
        )?;
        Ok(receipt.outcome)
    }

    fn terminate(&self, request: TerminateRequest) -> ExecutorResult<Effect<TerminationReceipt>> {
        self.require_target_host(&request.identity.host_id)?;
        let query =
            ReconciliationTarget::Execution(ExecutionQuery::Known(request.identity.clone()));

        let term_key = derive_control_key(
            "terminate-term",
            &request.identity,
            ControlSignal::Term,
            &request.policy,
        );
        let term = match self.call_control(
            Operation::TerminateTerm,
            term_key.clone(),
            request.identity.clone(),
            ControlSignal::Term,
        )? {
            Effect::Confirmed(receipt) => receipt,
            Effect::Uncertain(mut uncertain) => {
                uncertain.reconciliation = query.clone();
                return Ok(Effect::Uncertain(uncertain));
            }
        };

        let grace_key = derive_wait_key(
            "terminate-grace-wait",
            &request.identity,
            request.policy.term_grace,
        );
        let after_term = match self.call_wait_effect(
            Operation::TerminateGraceWait,
            grace_key,
            request.identity.clone(),
            request.policy.term_grace,
        )? {
            Effect::Confirmed(receipt) => receipt.outcome,
            Effect::Uncertain(mut uncertain) => {
                uncertain.reconciliation = query.clone();
                return Ok(Effect::Uncertain(uncertain));
            }
        };

        if !after_term.is_running() {
            return Ok(Effect::Confirmed(TerminationReceipt {
                term,
                after_term,
                kill: None,
                after_kill: None,
            }));
        }

        let kill_key = derive_control_key(
            "terminate-kill",
            &request.identity,
            ControlSignal::Kill,
            &request.policy,
        );
        let kill = match self.call_control(
            Operation::TerminateKill,
            kill_key,
            request.identity.clone(),
            ControlSignal::Kill,
        )? {
            Effect::Confirmed(receipt) => receipt,
            Effect::Uncertain(mut uncertain) => {
                uncertain.reconciliation = query.clone();
                return Ok(Effect::Uncertain(uncertain));
            }
        };

        let kill_wait_key = derive_wait_key(
            "terminate-kill-wait",
            &request.identity,
            request.policy.kill_wait,
        );
        let after_kill = match self.call_wait_effect(
            Operation::TerminateKillWait,
            kill_wait_key,
            request.identity.clone(),
            request.policy.kill_wait,
        )? {
            Effect::Confirmed(receipt) => receipt.outcome,
            Effect::Uncertain(mut uncertain) => {
                uncertain.reconciliation = query;
                return Ok(Effect::Uncertain(uncertain));
            }
        };

        Ok(Effect::Confirmed(TerminationReceipt {
            term,
            after_term,
            kill: Some(kill),
            after_kill: Some(after_kill),
        }))
    }

    fn collect(&self, request: CollectRequest) -> ExecutorResult<Effect<CollectedResult>> {
        self.require_target_host(&request.identity.host_id)?;
        request.policy.revalidate()?;
        let policy_digest = request.policy.digest().clone();
        let key = derive_collection_key(&request.identity, &policy_digest);
        let read_limits = TransportReadLimits::for_policy(&request.policy)?;
        let call = self.transport.collect(CollectionTransportRequest {
            target: self.target.clone(),
            key: key.clone(),
            identity: request.identity.clone(),
            policy: request.policy.clone(),
            policy_digest: policy_digest.clone(),
            read_limits,
        });
        let receipt = match call {
            TransportCall::Response(receipt) => receipt,
            TransportCall::LostResponse { detail } => {
                return Ok(Effect::Uncertain(Box::new(UncertainEffect {
                    operation: Operation::Collect,
                    key: key.clone(),
                    reconciliation: ReconciliationTarget::Collection(CollectionLookup {
                        identity: request.identity,
                        policy_digest,
                        collection_key: key,
                    }),
                    detail,
                })));
            }
        };
        let validated = validate_collection(
            &request.identity,
            &request.policy,
            &policy_digest,
            &key,
            receipt,
        );
        let cleanup = self.cleanup(&request.identity);
        let validated = match validated {
            Ok(validated) => validated,
            Err(error) => {
                return Err(ExecutorError::CollectionRejected {
                    reason: error.to_string(),
                    cleanup: Box::new(cleanup),
                });
            }
        };
        Ok(Effect::Confirmed(CollectedResult {
            identity: request.identity,
            patch: validated.patch,
            patch_digest: validated.patch_digest,
            changed_paths: validated.changed_paths,
            outputs: validated.outputs,
            cleanup,
            candidate_evidence_only: true,
        }))
    }
}

impl<T: SshTransport> SshExecutor<T> {
    fn require_target_host(&self, host: &HostId) -> ExecutorResult<()> {
        if host == &self.target.host_id {
            Ok(())
        } else {
            Err(ExecutorError::InvalidField {
                field: "host id",
                reason: "does not match the operator-selected SSH target".to_string(),
            })
        }
    }

    fn require_query_host(&self, query: &ExecutionQuery) -> ExecutorResult<()> {
        match query {
            ExecutionQuery::Submitted(submitted) => {
                self.require_target_host(&submitted.assignment.host_id)
            }
            ExecutionQuery::Known(identity) => self.require_target_host(&identity.host_id),
        }
    }

    fn call_wait(
        &self,
        operation: Operation,
        key: IdempotencyKey,
        identity: ExecutionIdentity,
        max_wait: BoundedMillis,
    ) -> ExecutorResult<WaitReceipt> {
        match self.call_wait_effect(operation, key, identity, max_wait)? {
            Effect::Confirmed(receipt) => Ok(receipt),
            Effect::Uncertain(uncertain) => Err(ExecutorError::TransportLost {
                operation: uncertain.operation,
                detail: uncertain.detail,
            }),
        }
    }

    fn call_wait_effect(
        &self,
        operation: Operation,
        key: IdempotencyKey,
        identity: ExecutionIdentity,
        max_wait: BoundedMillis,
    ) -> ExecutorResult<Effect<WaitReceipt>> {
        let call = self.transport.wait(WaitTransportRequest {
            target: self.target.clone(),
            key: key.clone(),
            identity: identity.clone(),
            max_wait,
        });
        let receipt = match call {
            TransportCall::Response(receipt) => receipt,
            TransportCall::LostResponse { detail } => {
                return Ok(Effect::Uncertain(Box::new(UncertainEffect {
                    operation,
                    key,
                    reconciliation: ReconciliationTarget::Execution(ExecutionQuery::Known(
                        identity,
                    )),
                    detail,
                })));
            }
        };
        require_protocol(operation, receipt.protocol_version)?;
        require_equal(
            operation,
            &receipt.key,
            &key,
            "idempotency key does not match the request",
        )?;
        require_equal(
            operation,
            &receipt.identity,
            &identity,
            "execution identity does not match the request",
        )?;
        Ok(Effect::Confirmed(receipt))
    }

    fn call_control(
        &self,
        operation: Operation,
        key: IdempotencyKey,
        identity: ExecutionIdentity,
        signal: ControlSignal,
    ) -> ExecutorResult<Effect<ControlReceipt>> {
        let call = self.transport.control(ControlTransportRequest {
            target: self.target.clone(),
            key: key.clone(),
            identity: identity.clone(),
            signal,
        });
        let receipt = match call {
            TransportCall::Response(receipt) => receipt,
            TransportCall::LostResponse { detail } => {
                return Ok(Effect::Uncertain(Box::new(UncertainEffect {
                    operation,
                    key,
                    reconciliation: ReconciliationTarget::Execution(ExecutionQuery::Known(
                        identity,
                    )),
                    detail,
                })));
            }
        };
        require_protocol(operation, receipt.protocol_version)?;
        require_equal(
            operation,
            &receipt.key,
            &key,
            "idempotency key does not match the request",
        )?;
        require_equal(
            operation,
            &receipt.identity,
            &identity,
            "execution identity does not match the request",
        )?;
        require_equal(
            operation,
            &receipt.signal,
            &signal,
            "control signal does not match the request",
        )?;
        Ok(Effect::Confirmed(receipt))
    }

    fn cleanup(&self, identity: &ExecutionIdentity) -> Effect<CleanupReceipt> {
        let key = derive_execution_key("cleanup", identity);
        let lookup = CleanupLookup {
            identity: identity.clone(),
            workspace_id: identity.workspace_id.clone(),
            cleanup_key: key.clone(),
        };
        let call = self.transport.cleanup(CleanupTransportRequest {
            target: self.target.clone(),
            key: key.clone(),
            identity: identity.clone(),
            workspace_id: identity.workspace_id.clone(),
        });
        let receipt = match call {
            TransportCall::Response(receipt) => receipt,
            TransportCall::LostResponse { detail } => {
                return Effect::Uncertain(Box::new(UncertainEffect {
                    operation: Operation::Cleanup,
                    key,
                    reconciliation: ReconciliationTarget::Cleanup(lookup),
                    detail,
                }));
            }
        };
        let validation = require_protocol(Operation::Cleanup, receipt.protocol_version)
            .and_then(|()| {
                require_equal(
                    Operation::Cleanup,
                    &receipt.key,
                    &key,
                    "idempotency key does not match the request",
                )
            })
            .and_then(|()| {
                require_equal(
                    Operation::Cleanup,
                    &receipt.identity,
                    identity,
                    "execution identity does not match the request",
                )
            })
            .and_then(|()| {
                require_equal(
                    Operation::Cleanup,
                    &receipt.workspace_id,
                    &identity.workspace_id,
                    "workspace identity does not match the cleanup request",
                )
            });
        match validation {
            Ok(()) => Effect::Confirmed(receipt),
            Err(error) => Effect::Uncertain(Box::new(UncertainEffect {
                operation: Operation::Cleanup,
                key,
                reconciliation: ReconciliationTarget::Cleanup(lookup),
                detail: error.to_string(),
            })),
        }
    }
}

fn validate_launch_manifest(request: &LaunchRequest) -> ExecutorResult<()> {
    request.staged.manifest.revalidate()?;
    request.spec.revalidate()?;
    if &request.staged.staged_digest != request.staged.manifest.digest() {
        return Err(ExecutorError::InvalidField {
            field: "staged digest",
            reason: "does not match the immutable input manifest".to_string(),
        });
    }
    let stdin_entry = request
        .staged
        .manifest
        .entry(&request.spec.stdin)
        .ok_or_else(|| ExecutorError::InvalidField {
            field: "launch stdin",
            reason: "does not name a staged manifest entry".to_string(),
        })?;
    if stdin_entry.purpose() != ManifestPurpose::Prompt || stdin_entry.input_bytes().is_none() {
        return Err(ExecutorError::InvalidField {
            field: "launch stdin",
            reason: "must name the staged Prompt input entry".to_string(),
        });
    }
    for argument in request.spec.argv.arguments() {
        if let TypedArg::ManifestPath(path) = argument {
            if !request.staged.manifest.declares(path) {
                return Err(ExecutorError::InvalidField {
                    field: "manifest argv path",
                    reason: format!("'{path}' is not declared by the staged manifest"),
                });
            }
        }
    }
    Ok(())
}

fn validate_launch_receipt(
    submitted: &SubmittedLaunchIdentity,
    receipt: &LaunchReceipt,
) -> ExecutorResult<()> {
    require_protocol(Operation::Launch, receipt.protocol_version)?;
    require_equal(
        Operation::Launch,
        &receipt.key,
        &submitted.launch_key,
        "idempotency key does not match the submission",
    )?;
    let identity = &receipt.identity;
    if identity.pid == 0 || identity.pgid == 0 {
        return Err(ExecutorError::MalformedReceipt {
            operation: Operation::Launch,
            reason: "PID and process-group ID must be nonzero".to_string(),
        });
    }
    require_submitted_identity(Operation::Launch, identity, submitted)
}

fn require_identity_matches_query(
    operation: Operation,
    identity: &ExecutionIdentity,
    query: &ExecutionQuery,
) -> ExecutorResult<()> {
    match query {
        ExecutionQuery::Submitted(submitted) => {
            require_submitted_identity(operation, identity, submitted)
        }
        ExecutionQuery::Known(expected) => require_equal(
            operation,
            identity,
            expected,
            "returned execution identity does not match the query",
        ),
    }
}

fn require_submitted_identity(
    operation: Operation,
    identity: &ExecutionIdentity,
    submitted: &SubmittedLaunchIdentity,
) -> ExecutorResult<()> {
    let matches = identity.host_id == submitted.assignment.host_id
        && identity.run_id == submitted.assignment.run_id
        && identity.assignment_id == submitted.assignment.assignment_id
        && identity.nonce == submitted.assignment.nonce
        && identity.staged_digest == submitted.staged_digest
        && identity.session_id == submitted.session_id
        && identity.workspace_id == submitted.workspace_id
        && identity.launch_spec_digest == submitted.launch_spec_digest
        && identity.launch_key == submitted.launch_key
        && identity.pid != 0
        && identity.pgid != 0;
    if matches {
        Ok(())
    } else {
        Err(ExecutorError::MalformedReceipt {
            operation,
            reason: "execution identity is not bound to the submitted host/run/assignment/nonce/digest/session/workspace/launch key"
                .to_string(),
        })
    }
}

struct ValidatedCollection {
    patch: Vec<u8>,
    patch_digest: Digest,
    changed_paths: Vec<LogicalPath>,
    outputs: Vec<CollectedOutput>,
}

fn validate_collection(
    expected_identity: &ExecutionIdentity,
    policy: &OutputPolicy,
    policy_digest: &Digest,
    expected_key: &IdempotencyKey,
    receipt: CollectionReceipt,
) -> ExecutorResult<ValidatedCollection> {
    require_protocol(Operation::Collect, receipt.protocol_version)?;
    require_equal(
        Operation::Collect,
        &receipt.key,
        expected_key,
        "idempotency key does not match the request",
    )?;
    require_equal(
        Operation::Collect,
        &receipt.identity,
        expected_identity,
        "execution identity does not match the request",
    )?;
    require_equal(
        Operation::Collect,
        &receipt.policy_digest,
        policy_digest,
        "output policy digest does not match the request",
    )?;
    let expected_manifest_digest = CollectionReceipt::canonical_manifest_digest(
        receipt.protocol_version,
        &receipt.key,
        &receipt.identity,
        &receipt.policy_digest,
        &receipt.patch,
        &receipt.changed_paths,
        &receipt.outputs,
    );
    require_equal(
        Operation::Collect,
        &receipt.manifest_digest,
        &expected_manifest_digest,
        "collection manifest digest does not bind the complete receipt",
    )?;
    validate_blob("patch", &receipt.patch, policy.patch_max_bytes)?;
    if receipt.changed_paths.len() > policy.changed_paths_max {
        return Err(ExecutorError::LimitExceeded {
            what: "changed path count",
            limit: policy.changed_paths_max as u64,
        });
    }
    let mut changed_paths = Vec::with_capacity(receipt.changed_paths.len());
    for raw_path in receipt.changed_paths {
        let path = LogicalPath::new(raw_path)?;
        if !policy
            .assignment_scopes
            .iter()
            .any(|scope| path.is_within(scope))
        {
            return Err(ExecutorError::ChangedPathOutsideScope(path.to_string()));
        }
        changed_paths.push(path);
    }
    require_sorted_unique("changed path", &changed_paths)?;
    let patch_paths = parse_patch_paths(&receipt.patch.bytes)?;
    require_equal(
        Operation::Collect,
        &patch_paths,
        &changed_paths,
        "patch header paths do not exactly match changed_paths",
    )?;

    if receipt.outputs.len() > policy.declared_outputs.len() {
        return Err(ExecutorError::LimitExceeded {
            what: "collected output count",
            limit: policy.declared_outputs.len() as u64,
        });
    }
    let mut outputs = Vec::with_capacity(receipt.outputs.len());
    let mut output_paths = Vec::with_capacity(receipt.outputs.len());
    let mut aggregate = 0_u64;
    for envelope in receipt.outputs {
        let path = LogicalPath::new(envelope.path)?;
        let declaration = policy
            .declared_outputs
            .iter()
            .find(|declared| declared.path == path)
            .ok_or_else(|| ExecutorError::UndeclaredOutput(path.to_string()))?;
        if envelope.media_type != declaration.media_type {
            return Err(ExecutorError::MalformedReceipt {
                operation: Operation::Collect,
                reason: format!("media type for '{path}' does not match its declaration"),
            });
        }
        validate_blob(path.as_str(), &envelope.blob, declaration.max_bytes)?;
        aggregate = aggregate.checked_add(envelope.blob.declared_size).ok_or(
            ExecutorError::LimitExceeded {
                what: "collected output aggregate bytes",
                limit: policy.output_aggregate_max_bytes,
            },
        )?;
        if aggregate > policy.output_aggregate_max_bytes {
            return Err(ExecutorError::LimitExceeded {
                what: "collected output aggregate bytes",
                limit: policy.output_aggregate_max_bytes,
            });
        }
        output_paths.push(path.clone());
        outputs.push(CollectedOutput {
            path,
            media_type: envelope.media_type,
            bytes: envelope.blob.bytes,
            digest: envelope.blob.digest,
        });
    }
    require_sorted_unique("collected output path", &output_paths)?;
    Ok(ValidatedCollection {
        patch: receipt.patch.bytes,
        patch_digest: receipt.patch.digest,
        changed_paths,
        outputs,
    })
}

#[derive(Debug)]
struct PatchBlock {
    path: LogicalPath,
    old_header: Option<String>,
    new_header: Option<String>,
}

fn parse_patch_paths(bytes: &[u8]) -> ExecutorResult<Vec<LogicalPath>> {
    if bytes.contains(&0) {
        return Err(malformed_patch("contains NUL"));
    }
    let text = std::str::from_utf8(bytes).map_err(|_| malformed_patch("is not UTF-8"))?;
    let mut paths = Vec::new();
    let mut current: Option<PatchBlock> = None;
    for line in text.lines() {
        if let Some(header) = line.strip_prefix("diff --git ") {
            if let Some(block) = current.take() {
                finish_patch_block(block, &mut paths)?;
            }
            if header.contains('"') || header.contains('\\') || header.contains('\t') {
                return Err(malformed_patch("uses quoted or escaped diff paths"));
            }
            let mut parts = header.split(' ');
            let old = parts
                .next()
                .ok_or_else(|| malformed_patch("has a missing old path"))?;
            let new = parts
                .next()
                .ok_or_else(|| malformed_patch("has a missing new path"))?;
            if parts.next().is_some() {
                return Err(malformed_patch("has extra diff header fields"));
            }
            let old = old
                .strip_prefix("a/")
                .ok_or_else(|| malformed_patch("old path lacks the a/ namespace"))?;
            let new = new
                .strip_prefix("b/")
                .ok_or_else(|| malformed_patch("new path lacks the b/ namespace"))?;
            let old_path = LogicalPath::new(old.to_string())?;
            let new_path = LogicalPath::new(new.to_string())?;
            if old_path != new_path {
                return Err(malformed_patch("rename/copy path changes are unsupported"));
            }
            current = Some(PatchBlock {
                path: old_path,
                old_header: None,
                new_header: None,
            });
        } else if let Some(path) = line.strip_prefix("--- ") {
            let block = current
                .as_mut()
                .ok_or_else(|| malformed_patch("old header precedes diff header"))?;
            if block.old_header.replace(path.to_string()).is_some() {
                return Err(malformed_patch("contains duplicate old headers"));
            }
        } else if let Some(path) = line.strip_prefix("+++ ") {
            let block = current
                .as_mut()
                .ok_or_else(|| malformed_patch("new header precedes diff header"))?;
            if block.new_header.replace(path.to_string()).is_some() {
                return Err(malformed_patch("contains duplicate new headers"));
            }
        } else if line.starts_with("rename ")
            || line.starts_with("copy ")
            || line.starts_with("Binary files ")
            || line == "GIT binary patch"
            || line.starts_with("diff --")
        {
            return Err(malformed_patch("contains an unsupported patch header"));
        } else if current.is_none() && !line.is_empty() {
            return Err(malformed_patch(
                "contains content before the first diff header",
            ));
        }
    }
    if let Some(block) = current {
        finish_patch_block(block, &mut paths)?;
    }
    require_sorted_unique("patch path", &paths)?;
    Ok(paths)
}

fn finish_patch_block(block: PatchBlock, paths: &mut Vec<LogicalPath>) -> ExecutorResult<()> {
    let old = block
        .old_header
        .ok_or_else(|| malformed_patch("is missing its old file header"))?;
    let new = block
        .new_header
        .ok_or_else(|| malformed_patch("is missing its new file header"))?;
    let expected_old = format!("a/{}", block.path);
    let expected_new = format!("b/{}", block.path);
    let old_is_null = old == "/dev/null";
    let new_is_null = new == "/dev/null";
    if old_is_null && new_is_null {
        return Err(malformed_patch("uses /dev/null on both sides"));
    }
    if (!old_is_null && old != expected_old) || (!new_is_null && new != expected_new) {
        return Err(malformed_patch(
            "file headers do not match the namespaced diff header",
        ));
    }
    if old.contains('"')
        || old.contains('\\')
        || old.contains('\t')
        || new.contains('"')
        || new.contains('\\')
        || new.contains('\t')
    {
        return Err(malformed_patch(
            "uses unsafe quoted or escaped file headers",
        ));
    }
    paths.push(block.path);
    Ok(())
}

fn malformed_patch(reason: impl Into<String>) -> ExecutorError {
    ExecutorError::MalformedReceipt {
        operation: Operation::Collect,
        reason: format!("malformed patch: {}", reason.into()),
    }
}

fn validate_blob(object: &str, blob: &CollectedBlob, max_bytes: u64) -> ExecutorResult<()> {
    if blob.declared_size != blob.bytes.len() as u64 {
        return Err(ExecutorError::MalformedReceipt {
            operation: Operation::Collect,
            reason: format!("declared size for '{object}' does not match its bytes"),
        });
    }
    if blob.declared_size > max_bytes {
        return Err(ExecutorError::LimitExceeded {
            what: "collected object bytes",
            limit: max_bytes,
        });
    }
    if Digest::for_bytes(&blob.bytes) != blob.digest {
        return Err(ExecutorError::ChecksumMismatch {
            object: object.to_string(),
        });
    }
    Ok(())
}

fn require_sorted_unique(what: &'static str, paths: &[LogicalPath]) -> ExecutorResult<()> {
    for pair in paths.windows(2) {
        if pair[0] >= pair[1] {
            return Err(ExecutorError::MalformedReceipt {
                operation: Operation::Collect,
                reason: format!("{what} manifest must be sorted and unique"),
            });
        }
    }
    Ok(())
}

fn require_protocol(operation: Operation, version: u32) -> ExecutorResult<()> {
    if version == EXECUTOR_PROTOCOL_VERSION {
        Ok(())
    } else {
        Err(ExecutorError::MalformedReceipt {
            operation,
            reason: format!(
                "protocol version {version} does not match {EXECUTOR_PROTOCOL_VERSION}"
            ),
        })
    }
}

fn require_equal<T: PartialEq>(
    operation: Operation,
    actual: &T,
    expected: &T,
    reason: &'static str,
) -> ExecutorResult<()> {
    if actual == expected {
        Ok(())
    } else {
        Err(ExecutorError::MalformedReceipt {
            operation,
            reason: reason.to_string(),
        })
    }
}
