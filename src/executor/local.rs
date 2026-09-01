use super::ssh::{build_workspace_manifest, new_run_id, reconcile_workspace, staged_input_digest};
use super::{
    CancellationToken, CapturedOutput, CleanupStatus, EffectReconciliation, ExecutionReport,
    ExecutionSemantics, ExecutionStatus, ExecutorKind, ExecutorLifecycleEvent, ExecutorLimits,
    ExecutorRequest, ExecutorUsage, RecoveryTarget,
};
use anyhow::{Context, Result};
use std::io::Read;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

pub(super) fn execute(
    request: &ExecutorRequest,
    cancellation: &CancellationToken,
    limits: &ExecutorLimits,
) -> Result<ExecutionReport> {
    super::validate_executor_request(request).context("LocalExecutor rejected the assignment")?;
    limits
        .validate()
        .context("LocalExecutor rejected its limits")?;

    let mut events = vec![ExecutorLifecycleEvent::Validated];
    if cancellation.is_cancelled() {
        events.push(ExecutorLifecycleEvent::CancelRequested);
        super::validate_event_bounds(&events, limits)
            .context("LocalExecutor could not represent pre-launch events within bounds")?;
        return Ok(report_without_process(request, events));
    }

    let manifest = build_workspace_manifest(request.working_directory.as_deref(), limits)
        .context("LocalExecutor could not validate the workspace")?;
    events.push(ExecutorLifecycleEvent::Staged);
    let workspace_bytes = manifest
        .entries
        .iter()
        .try_fold(0usize, |total, entry| {
            total.checked_add(entry.contents.len())
        })
        .context("LocalExecutor workspace byte count overflowed")?;
    let staged_input_digest = staged_input_digest(&manifest)
        .context("LocalExecutor could not bind the staged workspace")?;
    // Nonce generation is fallible and must complete before process creation.
    let run_id = new_run_id().context("LocalExecutor could not create a run nonce")?;
    let recovery = RecoveryTarget {
        assignment_id: request.assignment_id.clone(),
        executor_run_id: run_id,
        host_id: "local".to_string(),
        workspace: request
            .working_directory
            .as_deref()
            .and_then(|path| path.to_str())
            .unwrap_or("")
            .to_string(),
        staged_input_digest,
        remote_process: None,
    };

    let executable = request
        .argv
        .first()
        .context("validated executor argv unexpectedly became empty")?;
    let mut command = Command::new(executable);
    command.args(request.argv.iter().skip(1));
    if let Some(working_directory) = request.working_directory.as_deref() {
        command.current_dir(working_directory);
    }
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    configure_process_group(&mut command);

    let mut child = command
        .spawn()
        .context("LocalExecutor could not launch argv[0]")?;
    events.push(ExecutorLifecycleEvent::Launched);
    let Some(stdout) = child.stdout.take() else {
        let reason = cleanup_after_local_failure(
            &mut child,
            limits,
            &mut events,
            "LocalExecutor child stdout pipe is unavailable",
        );
        return Ok(local_uncertain_report(
            request,
            recovery,
            manifest.entries.len(),
            workspace_bytes,
            events,
            reason,
        ));
    };
    let Some(stderr) = child.stderr.take() else {
        drop(stdout);
        let reason = cleanup_after_local_failure(
            &mut child,
            limits,
            &mut events,
            "LocalExecutor child stderr pipe is unavailable",
        );
        return Ok(local_uncertain_report(
            request,
            recovery,
            manifest.entries.len(),
            workspace_bytes,
            events,
            reason,
        ));
    };
    let stdout_limit = limits.max_stdout_bytes;
    let stderr_limit = limits.max_stderr_bytes;
    let stdout_reader = thread::spawn(move || read_bounded(stdout, stdout_limit));
    let stderr_reader = thread::spawn(move || read_bounded(stderr, stderr_limit));

    let (mut status, mut cleanup) =
        wait_for_terminal(&mut child, cancellation, limits, &mut events, &recovery);
    let (stdout, stderr) = if cleanup == CleanupStatus::Complete {
        let deadline = Instant::now() + Duration::from_millis(limits.cancellation_grace_millis);
        let stdout = join_reader_until(
            stdout_reader,
            "stdout",
            deadline,
            Duration::from_millis(limits.poll_interval_millis),
        );
        let stderr = join_reader_until(
            stderr_reader,
            "stderr",
            deadline,
            Duration::from_millis(limits.poll_interval_millis),
        );
        match (stdout, stderr) {
            (Ok(Some(stdout)), Ok(Some(stderr))) => {
                events.push(ExecutorLifecycleEvent::Collected);
                (stdout, stderr)
            }
            (stdout, stderr) => {
                let reason = match (stdout, stderr) {
                    (Err(stdout), Err(stderr)) => format!(
                        "local output collection failed for stdout ({stdout}) and stderr ({stderr})"
                    ),
                    (Err(error), _) => format!("local stdout collection failed: {error}"),
                    (_, Err(error)) => format!("local stderr collection failed: {error}"),
                    _ => "local output pipes remained open after process-tree cleanup".to_string(),
                };
                status = ExecutionStatus::Uncertain {
                    reason,
                    recovery: recovery.clone(),
                };
                cleanup = CleanupStatus::Residual {
                    recovery: recovery.clone(),
                };
                events.push(ExecutorLifecycleEvent::CleanupResidual);
                (empty_capture(), empty_capture())
            }
        }
    } else {
        // A detached reader retains only the already-bounded pipe and avoids
        // converting an explicitly uncertain live-process state into an
        // unbounded caller wait.
        drop(stdout_reader);
        drop(stderr_reader);
        events.push(ExecutorLifecycleEvent::CleanupResidual);
        (empty_capture(), empty_capture())
    };

    let effects = match &status {
        ExecutionStatus::Uncertain { recovery, .. } => EffectReconciliation::Uncertain {
            recovery: recovery.clone(),
        },
        _ => match build_workspace_manifest(request.working_directory.as_deref(), limits)
            .context("could not inspect the post-execution workspace")
            .and_then(|after| reconcile_workspace(&manifest, &after, limits))
        {
            Ok(effects) => {
                events.push(ExecutorLifecycleEvent::Reconciled);
                events.push(ExecutorLifecycleEvent::CleanupComplete);
                effects
            }
            Err(error) => {
                status = ExecutionStatus::Uncertain {
                    reason: format!("local candidate effect reconciliation failed: {error:#}"),
                    recovery: recovery.clone(),
                };
                cleanup = CleanupStatus::Residual {
                    recovery: recovery.clone(),
                };
                events.push(ExecutorLifecycleEvent::CleanupResidual);
                EffectReconciliation::Uncertain {
                    recovery: recovery.clone(),
                }
            }
        },
    };
    let complete = !stdout.truncated
        && !stderr.truncated
        && !matches!(
            status,
            ExecutionStatus::Uncertain { .. } | ExecutionStatus::TimedOut
        );
    let usage = ExecutorUsage {
        workspace_entries: manifest.entries.len(),
        workspace_bytes,
        stdout_bytes: stdout.bytes.len(),
        stderr_bytes: stderr.bytes.len(),
        event_count: events.len(),
        complete,
    };
    if let Err(error) = super::validate_event_bounds(&events, limits) {
        return Ok(local_uncertain_report(
            request,
            recovery,
            manifest.entries.len(),
            workspace_bytes,
            vec![
                ExecutorLifecycleEvent::Validated,
                ExecutorLifecycleEvent::Staged,
                ExecutorLifecycleEvent::Launched,
                ExecutorLifecycleEvent::CleanupResidual,
            ],
            format!("LocalExecutor internal lifecycle construction failed: {error:#}"),
        ));
    }

    Ok(ExecutionReport {
        assignment_id: request.assignment_id.clone(),
        kind: ExecutorKind::Local,
        semantics: ExecutionSemantics {
            status,
            stdout,
            stderr,
            usage,
            events,
            effects,
            cleanup,
        },
    })
}

fn report_without_process(
    request: &ExecutorRequest,
    events: Vec<ExecutorLifecycleEvent>,
) -> ExecutionReport {
    ExecutionReport {
        assignment_id: request.assignment_id.clone(),
        kind: ExecutorKind::Local,
        semantics: ExecutionSemantics {
            status: ExecutionStatus::Cancelled,
            stdout: CapturedOutput {
                bytes: Vec::new(),
                truncated: false,
            },
            stderr: CapturedOutput {
                bytes: Vec::new(),
                truncated: false,
            },
            usage: ExecutorUsage {
                workspace_entries: 0,
                workspace_bytes: 0,
                stdout_bytes: 0,
                stderr_bytes: 0,
                event_count: events.len(),
                complete: true,
            },
            events,
            effects: EffectReconciliation::CandidateOnly {
                changed_paths: Vec::new(),
            },
            cleanup: CleanupStatus::NotStarted,
        },
    }
}

fn local_uncertain_report(
    request: &ExecutorRequest,
    recovery: RecoveryTarget,
    workspace_entries: usize,
    workspace_bytes: usize,
    mut events: Vec<ExecutorLifecycleEvent>,
    reason: String,
) -> ExecutionReport {
    if events.last() != Some(&ExecutorLifecycleEvent::CleanupResidual) {
        events.push(ExecutorLifecycleEvent::CleanupResidual);
    }
    ExecutionReport {
        assignment_id: request.assignment_id.clone(),
        kind: ExecutorKind::Local,
        semantics: ExecutionSemantics {
            status: ExecutionStatus::Uncertain {
                reason,
                recovery: recovery.clone(),
            },
            stdout: empty_capture(),
            stderr: empty_capture(),
            usage: ExecutorUsage {
                workspace_entries,
                workspace_bytes,
                stdout_bytes: 0,
                stderr_bytes: 0,
                event_count: events.len(),
                complete: false,
            },
            events,
            effects: EffectReconciliation::Uncertain {
                recovery: recovery.clone(),
            },
            cleanup: CleanupStatus::Residual { recovery },
        },
    }
}

fn cleanup_after_local_failure(
    child: &mut Child,
    limits: &ExecutorLimits,
    events: &mut Vec<ExecutorLifecycleEvent>,
    initial: &str,
) -> String {
    let poll = Duration::from_millis(limits.poll_interval_millis);
    let process_group = child.id();
    let mut reasons = vec![initial.to_string()];
    events.push(ExecutorLifecycleEvent::TermSent);
    if let Err(error) = send_term(child) {
        reasons.push(format!("TERM failed: {error}"));
    }
    let deadline = Instant::now() + Duration::from_millis(limits.cancellation_grace_millis);
    match wait_for_process_tree_absence(child, process_group, deadline, poll) {
        Ok(true) => return reasons.join("; "),
        Ok(false) => reasons.push("process tree remained after TERM".to_string()),
        Err(error) => reasons.push(format!("process state after TERM was unavailable: {error}")),
    }
    events.push(ExecutorLifecycleEvent::KillSent);
    if let Err(error) = send_kill(child) {
        reasons.push(format!("KILL failed: {error}"));
    }
    let deadline = Instant::now() + Duration::from_millis(limits.cancellation_grace_millis);
    match wait_for_process_tree_absence(child, process_group, deadline, poll) {
        Ok(true) => {}
        Ok(false) => reasons.push("process tree remained after KILL".to_string()),
        Err(error) => reasons.push(format!("process state after KILL was unavailable: {error}")),
    }
    reasons.join("; ")
}

fn empty_capture() -> CapturedOutput {
    CapturedOutput {
        bytes: Vec::new(),
        truncated: false,
    }
}

fn wait_for_terminal(
    child: &mut Child,
    cancellation: &CancellationToken,
    limits: &ExecutorLimits,
    events: &mut Vec<ExecutorLifecycleEvent>,
    recovery: &RecoveryTarget,
) -> (ExecutionStatus, CleanupStatus) {
    let poll = Duration::from_millis(limits.poll_interval_millis);
    let process_group = child.id();
    let execution_deadline =
        Instant::now() + Duration::from_millis(limits.execution_timeout_millis);
    let mut timed_out = false;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                if let Err(reason) =
                    cleanup_descendants_after_exit(process_group, limits, events, poll)
                {
                    return uncertain(reason, recovery);
                }
                return (
                    ExecutionStatus::Exited {
                        code: status.code(),
                    },
                    CleanupStatus::Complete,
                );
            }
            Ok(None) if !cancellation.is_cancelled() && Instant::now() < execution_deadline => {
                thread::sleep(poll)
            }
            Ok(None) if !cancellation.is_cancelled() => {
                timed_out = true;
                break;
            }
            Ok(None) => break,
            Err(error) => {
                let reason = cleanup_after_local_failure(
                    child,
                    limits,
                    events,
                    &format!("could not inspect local child state: {error}"),
                );
                return uncertain(reason, recovery);
            }
        }
    }

    if timed_out {
        events.push(ExecutorLifecycleEvent::TimeoutExpired);
    } else {
        events.push(ExecutorLifecycleEvent::CancelRequested);
    }
    events.push(ExecutorLifecycleEvent::TermSent);
    if let Err(error) = send_term(child) {
        return uncertain(
            format!("could not send TERM to the identity-bound local process: {error}"),
            recovery,
        );
    }

    let deadline = Instant::now() + Duration::from_millis(limits.cancellation_grace_millis);
    match wait_for_process_tree_absence(child, process_group, deadline, poll) {
        Ok(true) => {
            let status = if timed_out {
                ExecutionStatus::TimedOut
            } else {
                ExecutionStatus::Cancelled
            };
            return (status, CleanupStatus::Complete);
        }
        Ok(false) => {}
        Err(error) => {
            return uncertain(
                format!("lost local process state after TERM: {error}"),
                recovery,
            );
        }
    }

    events.push(ExecutorLifecycleEvent::KillSent);
    if let Err(error) = send_kill(child) {
        return uncertain(
            format!("could not send KILL to the identity-bound local process: {error}"),
            recovery,
        );
    }
    let deadline = Instant::now() + Duration::from_millis(limits.cancellation_grace_millis);
    match wait_for_process_tree_absence(child, process_group, deadline, poll) {
        Ok(true) => {
            let status = if timed_out {
                ExecutionStatus::TimedOut
            } else {
                ExecutionStatus::Cancelled
            };
            (status, CleanupStatus::Complete)
        }
        Ok(false) => uncertain(
            "could not prove local process-group absence after KILL".to_string(),
            recovery,
        ),
        Err(error) => uncertain(
            format!("could not prove local process-group absence after KILL: {error}"),
            recovery,
        ),
    }
}

#[cfg(unix)]
fn cleanup_descendants_after_exit(
    process_group: u32,
    limits: &ExecutorLimits,
    events: &mut Vec<ExecutorLifecycleEvent>,
    poll: Duration,
) -> std::result::Result<(), String> {
    if !process_group_is_present(process_group).map_err(|error| error.to_string())? {
        return Ok(());
    }
    events.push(ExecutorLifecycleEvent::TermSent);
    signal_process_group(process_group, libc::SIGTERM)
        .map_err(|error| format!("could not send TERM to lingering local descendants: {error}"))?;
    let deadline = Instant::now() + Duration::from_millis(limits.cancellation_grace_millis);
    if wait_for_group_absence(process_group, deadline, poll)? {
        return Ok(());
    }
    events.push(ExecutorLifecycleEvent::KillSent);
    signal_process_group(process_group, libc::SIGKILL)
        .map_err(|error| format!("could not send KILL to lingering local descendants: {error}"))?;
    let deadline = Instant::now() + Duration::from_millis(limits.cancellation_grace_millis);
    if wait_for_group_absence(process_group, deadline, poll)? {
        Ok(())
    } else {
        Err("could not prove lingering local descendant absence after KILL".to_string())
    }
}

#[cfg(not(unix))]
fn cleanup_descendants_after_exit(
    _process_group: u32,
    _limits: &ExecutorLimits,
    _events: &mut Vec<ExecutorLifecycleEvent>,
    _poll: Duration,
) -> std::result::Result<(), String> {
    Ok(())
}

fn wait_for_process_tree_absence(
    child: &mut Child,
    process_group: u32,
    deadline: Instant,
    poll: Duration,
) -> std::io::Result<bool> {
    loop {
        let child_exited = child.try_wait()?.is_some();
        let group_absent = !process_group_is_present(process_group)?;
        if child_exited && group_absent {
            return Ok(true);
        }
        if Instant::now() >= deadline {
            return Ok(false);
        }
        thread::sleep(poll);
    }
}

#[cfg(unix)]
fn wait_for_group_absence(
    process_group: u32,
    deadline: Instant,
    poll: Duration,
) -> std::result::Result<bool, String> {
    loop {
        if !process_group_is_present(process_group).map_err(|error| error.to_string())? {
            return Ok(true);
        }
        if Instant::now() >= deadline {
            return Ok(false);
        }
        thread::sleep(poll);
    }
}

#[cfg(unix)]
fn process_group_is_present(process_group: u32) -> std::io::Result<bool> {
    let process_group = i32::try_from(process_group)
        .map_err(|_| std::io::Error::other("local child id does not fit i32"))?;
    // SAFETY: signal 0 performs an existence/permission check without sending
    // a signal; the negative id addresses only the bound child process group.
    let result = unsafe { libc::kill(-process_group, 0) };
    if result == 0 {
        return Ok(true);
    }
    let error = std::io::Error::last_os_error();
    match error.raw_os_error() {
        Some(libc::ESRCH) => Ok(false),
        Some(libc::EPERM) => Ok(true),
        _ => Err(error),
    }
}

#[cfg(not(unix))]
fn process_group_is_present(_process_group: u32) -> std::io::Result<bool> {
    Ok(false)
}

fn uncertain(reason: String, recovery: &RecoveryTarget) -> (ExecutionStatus, CleanupStatus) {
    (
        ExecutionStatus::Uncertain {
            reason,
            recovery: recovery.clone(),
        },
        CleanupStatus::Residual {
            recovery: recovery.clone(),
        },
    )
}

fn read_bounded<R: Read>(reader: R, limit: usize) -> Result<CapturedOutput> {
    let mut reader = reader;
    let mut bytes = Vec::with_capacity(limit.min(64 * 1024));
    let mut truncated = false;
    let mut buffer = [0_u8; 8192];
    loop {
        let read = reader
            .read(&mut buffer)
            .context("could not read child output")?;
        if read == 0 {
            break;
        }
        let remaining = limit.saturating_sub(bytes.len());
        let retained = remaining.min(read);
        bytes.extend_from_slice(&buffer[..retained]);
        truncated |= retained < read;
    }
    Ok(CapturedOutput { bytes, truncated })
}

fn join_reader_until(
    handle: thread::JoinHandle<Result<CapturedOutput>>,
    stream: &str,
    deadline: Instant,
    poll: Duration,
) -> std::result::Result<Option<CapturedOutput>, String> {
    while !handle.is_finished() && Instant::now() < deadline {
        thread::sleep(poll);
    }
    if !handle.is_finished() {
        return Ok(None);
    }
    let output = handle
        .join()
        .map_err(|_| format!("LocalExecutor {stream} reader panicked"))?
        .map_err(|error| format!("LocalExecutor could not collect {stream}: {error:#}"))?;
    Ok(Some(output))
}

#[cfg(unix)]
fn configure_process_group(command: &mut Command) {
    use std::os::unix::process::CommandExt;
    command.process_group(0);
}

#[cfg(not(unix))]
fn configure_process_group(_command: &mut Command) {}

#[cfg(unix)]
fn send_term(child: &mut Child) -> std::io::Result<()> {
    signal_process_tree(child, libc::SIGTERM)
}

#[cfg(not(unix))]
fn send_term(child: &mut Child) -> std::io::Result<()> {
    child.kill()
}

#[cfg(unix)]
fn send_kill(child: &mut Child) -> std::io::Result<()> {
    signal_process_tree(child, libc::SIGKILL)
}

#[cfg(not(unix))]
fn send_kill(child: &mut Child) -> std::io::Result<()> {
    child.kill()
}

#[cfg(unix)]
fn signal_process_tree(child: &Child, signal: i32) -> std::io::Result<()> {
    let process_id = i32::try_from(child.id())
        .map_err(|_| std::io::Error::other("local child id does not fit i32"))?;
    signal_process_group(child.id(), signal)?;
    // The direct child could have escaped its initial process group. Its PID
    // cannot be reused while the Child handle remains unreaped, so targeting it
    // as well is identity-bound and closes that race.
    // SAFETY: `process_id` is the still-owned Child identity.
    let result = unsafe { libc::kill(process_id, signal) };
    if result == 0 {
        Ok(())
    } else {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ESRCH) {
            Ok(())
        } else {
            Err(error)
        }
    }
}

#[cfg(unix)]
fn signal_process_group(process_group: u32, signal: i32) -> std::io::Result<()> {
    let process_group = i32::try_from(process_group)
        .map_err(|_| std::io::Error::other("local child id does not fit i32"))?;
    // SAFETY: the child was launched into a process group whose id is its
    // observed child id; the negative id addresses only that bound group.
    let result = unsafe { libc::kill(-process_group, signal) };
    if result == 0 {
        Ok(())
    } else {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ESRCH) {
            Ok(())
        } else {
            Err(error)
        }
    }
}
