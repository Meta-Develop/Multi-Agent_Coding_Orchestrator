use super::*;
use std::{
    fs::{self, File, OpenOptions},
    os::{
        fd::AsRawFd,
        unix::{
            fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
            process::{CommandExt, ExitStatusExt},
        },
    },
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

/// Internal fixed subcommands, intercepted before the ordinary CLI/router.
pub fn maybe_run_helper() -> std::io::Result<bool> {
    let args: Vec<_> = std::env::args_os().collect();
    let Some(operation) = args.get(1).and_then(|a| a.to_str()) else {
        return Ok(false);
    };
    let result = match operation {
        "__supervised-ssh-helper" if args.len() == 4 => {
            serve(Path::new(&args[2]), &args[3].to_string_lossy())
        }
        "__supervised-ssh-runner" if args.len() == 3 => runner(Path::new(&args[2])),
        "__supervised-ssh-helper" | "__supervised-ssh-runner" => {
            Err(anyhow::anyhow!("invalid helper arguments"))
        }
        _ => return Ok(false),
    };
    result.map(|()| true).map_err(std::io::Error::other)
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StageState {
    request: StageTransportRequest,
    receipt: StageTransportReceipt,
}

fn private_dir(path: &Path) -> Result<()> {
    let m = fs::symlink_metadata(path)?;
    // SAFETY: geteuid has no preconditions.
    if !m.is_dir() || m.uid() != unsafe { libc::geteuid() } || m.mode() & 0o077 != 0 {
        bail!("helper directory must be an owned private directory");
    }
    if fs::canonicalize(path)? != path {
        bail!("helper directory must be canonical without symlinks");
    }
    Ok(())
}

fn create_dir(path: &Path) -> Result<()> {
    match fs::create_dir(path) {
        Ok(()) => fs::set_permissions(path, fs::Permissions::from_mode(0o700))?,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => (),
        Err(e) => return Err(e.into()),
    }
    private_dir(path)
}

fn atomic(path: &Path, value: &impl Serialize) -> Result<()> {
    let bytes = serialize_bounded(value, MAX_FRAME, None)?;
    if bytes.len() as u64 > MAX_FRAME {
        bail!("helper state exceeds byte limit");
    }
    let mut temp = tempfile::NamedTempFile::new_in(path.parent().context("state parent")?)?;
    temp.write_all(&bytes)?;
    temp.as_file().sync_all()?;
    temp.persist(path).map_err(|e| e.error)?;
    File::open(path.parent().context("state parent")?)?.sync_all()?;
    Ok(())
}

fn read_bytes(path: &Path, max: u64) -> Result<Vec<u8>> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let m = file.metadata()?;
    if !m.is_file() || m.nlink() != 1 || m.len() > max {
        bail!("unsafe or oversized helper file");
    }
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(max + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max {
        bail!("helper file grew beyond bound");
    }
    Ok(bytes)
}

fn read<T: DeserializeOwned>(path: &Path) -> Result<T> {
    Ok(serde_json::from_slice(&read_bytes(path, MAX_FRAME)?)?)
}

fn serve(root: &Path, host: &str) -> Result<()> {
    private_dir(root)?;
    HostId::new(host)?;
    let request: Request = read_frame(&mut std::io::stdin().lock(), MAX_FRAME)?;
    if request.target().host_id.as_str() != host
        || request.target().root.as_str() != root.to_string_lossy()
    {
        bail!("helper host/root binding mismatch");
    }
    if fs::canonicalize(request.target().helper.as_str())?
        != fs::canonicalize(std::env::current_exe()?)?
    {
        bail!("helper executable binding mismatch");
    }
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(root.join(".lifecycle.lock"))?;
    // SAFETY: lock is an open descriptor held through request processing.
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let reply = dispatch(root, request)?;
    write_frame(&mut std::io::stdout().lock(), &reply, MAX_FRAME)
}

#[derive(Serialize)]
#[serde(untagged)]
#[allow(clippy::large_enum_variant)]
enum Reply {
    Stage(StageTransportReceipt),
    Launch(LaunchReceipt),
    Status(StatusReceipt),
    Wait(WaitReceipt),
    Control(ControlReceipt),
    Collect(CollectionReceipt),
    Cleanup(CleanupReceipt),
}

fn dispatch(root: &Path, request: Request) -> Result<Reply> {
    match request {
        Request::Stage(request) => {
            let stage = &request.stage;
            // Reconstruct authority rather than trust deserialized cached digests.
            stage.manifest.revalidate()?;
            stage.launch_spec.revalidate()?;
            for arg in stage.launch_spec.argv().arguments() {
                if let TypedArg::Literal(value) = arg {
                    BoundedLiteral::new(value.as_str())?;
                }
            }
            TypedArgv::new(stage.launch_spec.argv().arguments().to_vec())?;
            BoundedMillis::new(stage.launch_spec.deadline().get())?;
            let rebuilt = StageRequest::new(
                stage.identity.clone(),
                stage.manifest.clone(),
                stage.launch_spec.clone(),
                stage.collection.policy().clone(),
            )?;
            if &rebuilt != stage || stage.identity.host_id != request.target.host_id {
                bail!("invalid stage authority");
            }
            super::super::ssh::validate_manifest_launch_spec(&stage.manifest, &stage.launch_spec)?;
            let dir = root.join(stage.key.as_str());
            if dir.exists() {
                let old: StageState = read(&dir.join("stage.json"))?;
                if old.request != request {
                    bail!("stage key collision");
                }
                return Ok(Reply::Stage(old.receipt));
            }
            create_dir(&dir)?;
            let files = dir.join("files");
            create_dir(&files)?;
            create_dir(&files.join("workspace"))?;
            for entry in stage.manifest.entries() {
                let logical = entry.path().as_str();
                let prefix = match entry.purpose() {
                    ManifestPurpose::WorkspaceInput => "workspace/",
                    ManifestPurpose::Prompt | ManifestPurpose::Schema => "input/",
                    _ => "output/",
                };
                if !logical.starts_with(prefix)
                    || logical
                        .split('/')
                        .any(|part| part.eq_ignore_ascii_case(".git"))
                {
                    bail!("manifest path is outside its namespace or uses reserved Git metadata");
                }
                let path = files.join(logical);
                fs::create_dir_all(path.parent().context("manifest parent")?)?;
                if let Some(bytes) = entry.input_bytes() {
                    let mut file = OpenOptions::new()
                        .create_new(true)
                        .write(true)
                        .mode(0o600)
                        .open(path)?;
                    file.write_all(bytes)?;
                    file.sync_all()?;
                }
            }
            // Only workspace inputs enter the baseline. Prompt/schema/output are separate.
            let repo = git2::Repository::init(&files)?;
            let mut index = repo.index()?;
            for entry in stage
                .manifest
                .entries()
                .iter()
                .filter(|e| e.purpose() == ManifestPurpose::WorkspaceInput)
            {
                index.add_path(Path::new(entry.path().as_str()))?;
            }
            index.write()?;
            let tree_id = index.write_tree()?;
            let tree = repo.find_tree(tree_id)?;
            let signature = git2::Signature::new(
                "maco lifecycle",
                "lifecycle@invalid",
                &git2::Time::new(0, 0),
            )?;
            repo.commit(
                Some("HEAD"),
                &signature,
                &signature,
                "staged inputs",
                &tree,
                &[],
            )?;
            let receipt = StageTransportReceipt::from_wire(
                EXECUTOR_PROTOCOL_VERSION,
                stage.key.clone(),
                stage.identity.clone(),
                stage.manifest.digest().clone(),
                SessionId::new(stage.key.as_str())?,
                WorkspaceId::new(stage.key.as_str())?,
            );
            atomic(
                &dir.join("stage.json"),
                &StageState {
                    request,
                    receipt: receipt.clone(),
                },
            )?;
            Ok(Reply::Stage(receipt))
        }
        Request::Launch(request) => {
            let dir = session(root, request.submitted.session_id())?;
            let state: StageState = read(&dir.join("stage.json"))?;
            let expected = submitted(&state);
            if request.submitted != expected
                || request.argv != state.request.stage.launch_spec.argv
                || request.stdin != state.request.stage.launch_spec.stdin
                || request.deadline != state.request.stage.launch_spec.deadline
            {
                bail!("launch does not match staged authority");
            }
            let intent = dir.join("launch-intent.json");
            if !intent.exists() {
                atomic(&intent, &request)?;
                let mut command = Command::new(std::env::current_exe()?);
                command
                    .arg("__supervised-ssh-runner")
                    .arg(&dir)
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null());
                // SAFETY: setsid is async-signal-safe; detach from the SSH session.
                unsafe {
                    command.pre_exec(|| {
                        if libc::setsid() < 0 {
                            return Err(std::io::Error::last_os_error());
                        }
                        Ok(())
                    });
                }
                // Custody belongs to the durable runner after spawn. A lost reply never respawns it.
                let _child = command.spawn()?;
            } else if read::<LaunchTransportRequest>(&intent)? != request {
                bail!("launch intent collision");
            }
            let started = Instant::now();
            while !dir.join("launch.json").exists() {
                if started.elapsed() > Duration::from_secs(5) {
                    bail!("launch intent unresolved; query only");
                }
                thread::sleep(Duration::from_millis(10));
            }
            Ok(Reply::Launch(read::<LaunchReceipt>(
                &dir.join("launch.json"),
            )?))
        }
        Request::Status(request) => {
            let session_id = match &request.query {
                ExecutionQuery::Submitted(s) => s.session_id(),
                ExecutionQuery::Known(i) => i.session_id(),
            };
            let dir = session(root, session_id)?;
            let status = if dir.join("launch.json").exists() {
                let receipt: LaunchReceipt = read(&dir.join("launch.json"))?;
                match &request.query {
                    ExecutionQuery::Submitted(s)
                        if s != &submitted(&read::<StageState>(&dir.join("stage.json"))?) =>
                    {
                        bail!("query binding mismatch")
                    }
                    ExecutionQuery::Known(i) if i != receipt.identity() => {
                        bail!("query identity mismatch")
                    }
                    _ => (),
                }
                status(&dir, receipt.identity())?
            } else {
                ExecutionStatus::NotFound
            };
            Ok(Reply::Status(StatusReceipt::from_wire(
                EXECUTOR_PROTOCOL_VERSION,
                request.key,
                request.query,
                status,
            )))
        }
        Request::Wait(request) => {
            let dir = checked_identity(root, &request.identity)?;
            BoundedMillis::new(request.max_wait.get())?;
            let start = Instant::now();
            let outcome = loop {
                match status(&dir, &request.identity)? {
                    ExecutionStatus::Exited { code, .. } => break WaitOutcome::Exited { code },
                    ExecutionStatus::Signaled { signal, .. } => {
                        break WaitOutcome::Signaled { signal }
                    }
                    _ if start.elapsed() >= Duration::from_millis(request.max_wait.get()) => {
                        break WaitOutcome::RunningAtDeadline
                    }
                    _ => thread::sleep(Duration::from_millis(10)),
                }
            };
            Ok(Reply::Wait(WaitReceipt::from_wire(
                EXECUTOR_PROTOCOL_VERSION,
                request.key,
                request.identity,
                outcome,
            )))
        }
        Request::Control(request) => {
            let dir = checked_identity(root, &request.identity)?;
            if matches!(
                status(&dir, &request.identity)?,
                ExecutionStatus::Running(_)
            ) {
                if process_token(request.identity.pid())?.as_ref()
                    != Some(request.identity.start_token())
                {
                    bail!("runner identity is uncertain; retain workspace for reconciliation");
                }
                // Only the native containment owner delivers TERM/KILL to workload descendants.
                atomic(&dir.join("cancel.json"), &request)?;
            }
            Ok(Reply::Control(ControlReceipt::from_wire(
                EXECUTOR_PROTOCOL_VERSION,
                request.key,
                request.identity,
                request.signal,
            )))
        }
        Request::Collect(request) => {
            let dir = checked_identity(root, &request.identity)?;
            if matches!(
                status(&dir, &request.identity)?,
                ExecutionStatus::Running(_)
            ) {
                bail!("collection requires terminal custody");
            }
            let authority = request.identity.collection_authority();
            if &request.policy != authority.policy()
                || &request.key != authority.collection_key()
                || &request.policy_digest != authority.policy_digest()
                || request.read_limits != TransportReadLimits::for_policy(&request.policy)?
            {
                bail!("collection authority mismatch");
            }
            let path = dir.join("collection.json");
            if path.exists() {
                return Ok(Reply::Collect(read::<CollectionReceipt>(&path)?));
            }
            let files = dir.join("files");
            bound_candidate_tree(&files.join("workspace"))?;
            let repo = git2::Repository::open(&files)?;
            let mut options = git2::DiffOptions::new();
            options
                .pathspec("workspace")
                .include_untracked(true)
                .recurse_untracked_dirs(true)
                .show_untracked_content(true);
            let diff = repo.diff_tree_to_workdir_with_index(
                Some(&repo.head()?.peel_to_tree()?),
                Some(&mut options),
            )?;
            let mut patch = Vec::new();
            diff.print(git2::DiffFormat::Patch, |_, _, line| {
                append_patch_line(
                    &mut patch,
                    line.origin(),
                    line.content(),
                    request.read_limits.patch_max_bytes(),
                )
            })?;
            let mut paths = Vec::new();
            for delta in diff.deltas() {
                let p = delta
                    .new_file()
                    .path()
                    .or_else(|| delta.old_file().path())
                    .context("diff path missing")?;
                paths.push(p.to_str().context("non-UTF8 candidate path")?.to_string());
            }
            paths.sort();
            paths.dedup();
            let patch = CollectedBlob::checksummed(patch, request.read_limits.patch_max_bytes())?;
            let mut outputs = Vec::new();
            for output in request.policy.declared_outputs() {
                let path = safe_output(&files, output.path())?;
                outputs.push(CollectedOutputEnvelope::from_wire(
                    output.path().to_string(),
                    output.media_type().into(),
                    CollectedBlob::checksummed(
                        read_bytes(&path, output.max_bytes())?,
                        output.max_bytes(),
                    )?,
                )?);
            }
            let digest = CollectionReceipt::canonical_manifest_digest(
                EXECUTOR_PROTOCOL_VERSION,
                &request.key,
                &request.identity,
                &request.policy_digest,
                &patch,
                &paths,
                &outputs,
            );
            let receipt = CollectionReceipt::from_wire_bounded(
                EXECUTOR_PROTOCOL_VERSION,
                request.key,
                request.identity.clone(),
                request.policy_digest,
                patch,
                paths,
                outputs,
                digest,
                &request.read_limits,
            )?;
            super::super::ssh::restore_collection_receipt(&request.identity, receipt.clone())?;
            atomic(&path, &receipt)?;
            Ok(Reply::Collect(receipt))
        }
        Request::Cleanup(request) => {
            let dir = checked_identity(root, &request.identity)?;
            let expected = super::super::types::derive_execution_key("cleanup", &request.identity);
            if request.workspace_id != *request.identity.workspace_id()
                || request.key != expected
                || !dir.join("collection.json").exists()
                || matches!(
                    status(&dir, &request.identity)?,
                    ExecutionStatus::Running(_)
                )
            {
                bail!("cleanup authority or terminal collection missing");
            }
            let receipt = CleanupReceipt::from_wire(
                EXECUTOR_PROTOCOL_VERSION,
                request.key,
                request.identity,
                request.workspace_id,
                true,
            );
            atomic(&dir.join("cleanup-intent.json"), &receipt)?;
            let files = dir.join("files");
            if files.exists() {
                private_dir(&files)?;
                fs::remove_dir_all(files)?;
            }
            atomic(&dir.join("cleanup.json"), &receipt)?;
            // Keep bounded receipts and the identity tombstone for exact-key reconciliation.
            Ok(Reply::Cleanup(receipt))
        }
    }
}

fn submitted(state: &StageState) -> SubmittedLaunchIdentity {
    SubmittedLaunchIdentity::for_launch(&StagedAssignment {
        identity: state.request.stage.identity.clone(),
        staged_digest: state.receipt.staged_digest.clone(),
        session_id: state.receipt.session_id.clone(),
        workspace_id: state.receipt.workspace_id.clone(),
        manifest: state.request.stage.manifest.clone(),
        launch_spec: state.request.stage.launch_spec.clone(),
        collection: state.request.stage.collection.clone(),
    })
}

fn session(root: &Path, id: &SessionId) -> Result<PathBuf> {
    // Session names are derived stage digests, never arbitrary remote paths.
    Digest::new(id.as_str())?;
    let path = root.join(id.as_str());
    private_dir(&path)?;
    Ok(path)
}

fn checked_identity(root: &Path, identity: &ExecutionIdentity) -> Result<PathBuf> {
    let dir = session(root, identity.session_id())?;
    let receipt: LaunchReceipt = read(&dir.join("launch.json"))?;
    if receipt.identity() != identity {
        bail!("execution identity mismatch");
    }
    Ok(dir)
}

fn append_patch_line(patch: &mut Vec<u8>, origin: char, bytes: &[u8], maximum: u64) -> bool {
    let prefix = matches!(origin, ' ' | '+' | '-');
    let Some(length) = patch
        .len()
        .checked_add(bytes.len())
        .and_then(|n| n.checked_add(usize::from(prefix)))
    else {
        return false;
    };
    if length as u64 > maximum || patch.try_reserve_exact(length - patch.len()).is_err() {
        return false;
    }
    if prefix {
        patch.push(origin as u8);
    }
    patch.extend_from_slice(bytes);
    true
}

fn bound_candidate_tree(root: &Path) -> Result<()> {
    let mut pending = vec![root.to_path_buf()];
    let mut count = 0usize;
    let mut total = 0u64;
    while let Some(path) = pending.pop() {
        count += 1;
        if count > 4096 {
            bail!("candidate tree exceeds entry limit");
        }
        if path
            .file_name()
            .is_some_and(|name| name.to_string_lossy().eq_ignore_ascii_case(".git"))
        {
            bail!("candidate contains reserved Git metadata");
        }
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.is_dir() {
            for entry in fs::read_dir(path)? {
                if pending.len() + count >= 4096 {
                    bail!("candidate tree exceeds entry limit");
                }
                pending.push(entry?.path());
            }
        } else if metadata.is_file() && metadata.nlink() == 1 {
            total = total
                .checked_add(metadata.len())
                .context("candidate size overflow")?;
            if metadata.len() > 8 * 1024 * 1024 || total > 32 * 1024 * 1024 {
                bail!("candidate tree exceeds byte limit");
            }
        } else {
            bail!("candidate tree contains a link or special file");
        }
    }
    Ok(())
}

fn safe_output(root: &Path, logical: &LogicalPath) -> Result<PathBuf> {
    let path = root.join(logical.as_str());
    if fs::canonicalize(&path)? != path {
        bail!("candidate output traverses a symlink");
    }
    Ok(path)
}

fn process_token(pid: u32) -> Result<Option<StartToken>> {
    let stat = match fs::read_to_string(format!("/proc/{pid}/stat")) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let fields: Vec<_> = stat
        .rsplit_once(')')
        .context("invalid process stat")?
        .1
        .split_whitespace()
        .collect();
    if fields[0] == "Z" {
        return Ok(None);
    }
    let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
    Ok(Some(StartToken::new(format!(
        "{}-{}",
        boot.trim(),
        fields.get(19).context("process start missing")?
    ))?))
}

fn status(dir: &Path, identity: &ExecutionIdentity) -> Result<ExecutionStatus> {
    if dir.join("terminal.json").exists() {
        let outcome: WaitOutcome = read(&dir.join("terminal.json"))?;
        return match outcome {
            WaitOutcome::Exited { code } => Ok(ExecutionStatus::Exited {
                identity: identity.clone(),
                code,
            }),
            WaitOutcome::Signaled { signal } => Ok(ExecutionStatus::Signaled {
                identity: identity.clone(),
                signal,
            }),
            _ => Err(anyhow::anyhow!("invalid terminal receipt")),
        };
    }
    // PID disappearance does not establish native process-tree quiescence.
    if process_token(identity.pid())?.as_ref() != Some(identity.start_token()) {
        bail!("native runner custody is uncertain; retain workspace for reconciliation");
    }
    Ok(ExecutionStatus::Running(identity.clone()))
}

fn runner(dir: &Path) -> Result<()> {
    private_dir(dir)?;
    let request: LaunchTransportRequest = read(&dir.join("launch-intent.json"))?;
    let state: StageState = read(&dir.join("stage.json"))?;
    if submitted(&state) != request.submitted {
        bail!("runner launch binding mismatch");
    }
    let pid = std::process::id();
    let assignment = request.submitted.assignment();
    let identity = ExecutionIdentity::from_wire(
        assignment.host_id().clone(),
        assignment.run_id().clone(),
        assignment.assignment_id().clone(),
        assignment.nonce().clone(),
        request.submitted.staged_digest().clone(),
        request.submitted.session_id().clone(),
        request.submitted.workspace_id().clone(),
        request.submitted.launch_spec_digest().clone(),
        request.submitted.collection_authority().clone(),
        pid,
        pid,
        process_token(pid)?.context("runner start missing")?,
        request.submitted.launch_key().clone(),
    )?;
    if dir.join("launch.json").exists() {
        bail!("runner already started");
    }
    atomic(
        &dir.join("launch.json"),
        &LaunchReceipt::from_wire(
            EXECUTOR_PROTOCOL_VERSION,
            identity.launch_key().clone(),
            identity,
        ),
    )?;
    let files = dir.join("files");
    let mut args = Vec::new();
    for arg in request.argv.arguments() {
        args.push(match arg {
            TypedArg::Literal(s) => s.as_str().to_string(),
            TypedArg::ManifestPath(p) => files.join(p.as_str()).to_string_lossy().into_owned(),
            TypedArg::FinalStdinMarker => "-".into(),
        });
    }
    use crate::process_runner::{
        run_process_cancellable, EnvironmentMode, ProcessCancellation, ProcessSpec,
        SideEffectConfinementProfile, StdinMode, StrictOfflineWorkspaceProfile,
    };
    // Operator-installed programs may live in the private root's fixed bin directory.
    // Literal executable names remain distinct from translated manifest paths.
    let installed = dir
        .parent()
        .context("session root")?
        .join("bin")
        .join(&args[0]);
    let program = if !Path::new(&args[0]).is_absolute() && installed.exists() {
        private_dir(installed.parent().context("program parent")?)?;
        if fs::canonicalize(&installed)? != installed {
            bail!("installed program must not be a symlink");
        }
        installed
    } else {
        PathBuf::from(&args[0])
    };
    let profile = StrictOfflineWorkspaceProfile::read_write(files.join("workspace"))
        .with_visible_read_only_root(files.join("input"))
        .with_writable_artifact_root(files.join("output"));
    let profile = if program.is_absolute() {
        profile.with_visible_read_only_file(&program)
    } else {
        profile
    };
    let spec = ProcessSpec::direct(
        "supervised SSH candidate",
        &program,
        &args[1..],
        files.join("workspace"),
        1024 * 1024,
    )
    .with_environment(EnvironmentMode::ClearAndSet(
        std::collections::BTreeMap::from([
            ("PATH".into(), "/usr/local/bin:/usr/bin:/bin".into()),
            ("LANG".into(), "C.UTF-8".into()),
        ]),
    ))
    .with_stdin(StdinMode::Bytes(read_bytes(
        &safe_output(&files, &request.stdin)?,
        8 * 1024 * 1024,
    )?))
    .with_timeout(Some(Duration::from_millis(request.deadline.get())))
    .with_side_effect_confinement(SideEffectConfinementProfile::StrictOfflineWorkspace(
        profile,
    ))
    .with_private_runtime_home(true);
    let cancellation = ProcessCancellation::new();
    let monitor_cancel = cancellation.clone();
    let cancel_path = dir.join("cancel.json");
    let finished = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let monitor_finished = finished.clone();
    let monitor = thread::spawn(move || {
        while !monitor_finished.load(std::sync::atomic::Ordering::SeqCst) {
            if cancel_path.exists() {
                monitor_cancel.cancel();
            }
            thread::sleep(Duration::from_millis(10));
        }
    });
    let result = run_process_cancellable(spec, &cancellation);
    finished.store(true, std::sync::atomic::Ordering::SeqCst);
    let _ = monitor.join();
    let output = match result {
        Ok(output) => output,
        Err(error) => {
            atomic(&dir.join("runner-error.json"), &error.to_string())?;
            return Err(error.into());
        }
    };
    if !output.process_tree.is_verified_empty() || !output.side_effects.is_verified() {
        bail!("native runner could not prove terminal containment");
    }
    if let Some(entry) = state
        .request
        .stage
        .manifest
        .entries()
        .iter()
        .find(|e| e.path().as_str() == "output/events")
    {
        let path = files.join(entry.path().as_str());
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)?;
        file.write_all(output.stdout.as_bytes())?;
        file.sync_all()?;
    }
    let exit = output.status.context("native runner omitted exit status")?;
    let outcome = match exit.code() {
        Some(code) => WaitOutcome::Exited { code },
        None => WaitOutcome::Signaled {
            signal: ProcessSignal::new(exit.signal().unwrap_or(libc::SIGKILL) as u16)?,
        },
    };
    atomic(&dir.join("terminal.json"), &outcome)
}

#[cfg(test)]
mod bound_tests {
    use super::*;
    #[test]
    fn oversized_patch_line_does_not_grow_buffer() {
        let mut patch = b"keep".to_vec();
        let capacity = patch.capacity();
        assert!(!append_patch_line(&mut patch, '+', &[0; 4096], 16));
        assert_eq!(patch, b"keep");
        assert_eq!(patch.capacity(), capacity);
        assert!(append_patch_line(&mut patch, '+', b"ok", 7));
        assert_eq!(patch, b"keep+ok");
    }
}
