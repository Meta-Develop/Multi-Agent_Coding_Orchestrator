//! One-run parent transport for the pinned Cursor bridge.

#![cfg(target_os = "linux")]

use super::cursor::managed_bridge::{
    bind_managed_bridge_sources, CursorManagedBridgeBinding, MANAGED_BRIDGE_SOURCE,
};
use super::CursorManagedParentEvidence;
use crate::pinned_exec::{PinnedDirectExecutable, SourceBoundMainHelper};
use crate::process_runner::{
    run_process_cancellable, ContainedProcessStartGate, EnvironmentMode, ProcessCancellation,
    ProcessSpec, SideEffectConfinementEvidence, SideEffectConfinementProfile,
    SideEffectConfinementProfileKind, StdinMode, StrictOfflineWorkspaceProfile,
};
use anyhow::{bail, Context, Result};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{CString, OsStr, OsString};
use std::fs;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::net::Shutdown;
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const SOCKET_NAME: &str = "maco-cursor-parent.sock";
const MAX_FRAME_BYTES: usize = 4 * 1024 * 1024;
const MAX_RESOURCE_FILE_BYTES: usize = 1024 * 1024;
const IO_POLL: Duration = Duration::from_millis(100);
const MANAGED_ENTRY_SOURCE: &str = include_str!("managed_entry.cjs");

const RESOLVE_NO_XDEV: u64 = 0x01;
const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
const RESOLVE_NO_SYMLINKS: u64 = 0x04;
const RESOLVE_BENEATH: u64 = 0x08;

#[repr(C)]
struct LinuxOpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

#[derive(Debug, Clone)]
pub(crate) struct CursorManagedInstall {
    binding: CursorManagedBridgeBinding,
    node: PathBuf,
}

impl CursorManagedInstall {
    pub(crate) fn bind(selected_program: &Path) -> Result<Self> {
        let selected_program = fs::canonicalize(selected_program).with_context(|| {
            format!(
                "failed to canonicalize selected Cursor program {}",
                selected_program.display()
            )
        })?;
        let root = cursor_install_root(&selected_program)?;
        let binding = bind_managed_bridge_sources(&root)?;
        let node = bind_executable(&root.join("node"), "Cursor pinned Node runtime")?;
        Ok(Self { binding, node })
    }

    pub(crate) fn root(&self) -> &Path {
        self.binding.root()
    }

    pub(crate) fn node(&self) -> &Path {
        &self.node
    }

    pub(crate) fn eval_source(&self) -> Result<String> {
        let bridge = serde_json::to_string(MANAGED_BRIDGE_SOURCE)?;
        let entry = serde_json::to_string(MANAGED_ENTRY_SOURCE)?;
        Ok(format!(
            r#""use strict";
const Module = require("node:module");
function load(source, filename) {{
  const loaded = new Module(filename, module);
  loaded.filename = filename;
  loaded.paths = Module._nodeModulePaths(require("node:path").dirname(filename));
  loaded._compile(source, filename);
  return loaded.exports;
}}
const bridgeSource = {bridge};
const bridge = load(bridgeSource, "/maco/cursor-managed-bridge.cjs");
const knownRefusalCodes = new Set(Array.from(
  bridgeSource.matchAll(/"(CURSOR_[A-Z0-9_]+)"/g), (match) => match[1],
));
const entry = load({entry}, "/maco/cursor-managed-entry.cjs");
const deadline = Number(process.env.MACO_CURSOR_OPERATION_DEADLINE_UNIX_MILLIS);
entry.runManagedCursor({{
  installPinnedCursorBridge: bridge.installPinnedCursorBridge,
  root: process.env.MACO_CURSOR_PINNED_ROOT,
  socketPath: process.env.MACO_CURSOR_PARENT_SOCKET,
  deadlineUnixMillis: deadline,
  argv: process.argv.slice(1),
}}).then(async (installed) => {{
  if (process.env.MACO_CURSOR_PROVIDERLESS_QUALIFICATION === "1") {{
    const text = JSON.parse(process.env.MACO_CURSOR_PROVIDERLESS_TEXT_JSON);
    if (typeof text !== "string") {{
      throw new Error("Cursor providerless qualification text JSON must encode a string");
    }}
    await installed.runProviderlessQualification({{
      path: process.env.MACO_CURSOR_PROVIDERLESS_PATH,
      text,
      workingDirectory: process.env.MACO_CURSOR_PROVIDERLESS_WORKSPACE,
    }});
    await installed.drainPendingCompletions();
    process.stdout.write("MACO_CURSOR_PROVIDERLESS_GATE2_PASS\n");
    process.exit(0);
  }}
  return installed;
}}).catch((error) => {{
  const name = ["CursorBridgeRefusal", "CursorManagedParentRefusal", "Error", "TypeError", "SyntaxError"]
    .includes(error?.name) ? error.name : "unrecognized";
  const code = knownRefusalCodes.has(error?.code)
    || ["MODULE_NOT_FOUND", "ERR_REQUIRE_ESM", "ERR_DLOPEN_FAILED", "ENOENT", "EACCES", "EPERM"].includes(error?.code)
    ? error.code : null;
  const message = typeof error?.message === "string" ? error.message : "";
  const boundedMessage = Buffer.from(message.slice(0, 1024), "utf8");
  const messageHash = require("node:crypto").createHash("sha256").update(boundedMessage).digest("hex");
  process.stderr.write(`MACO_CURSOR_BOOTSTRAP_REFUSAL ${{JSON.stringify({{
    name, code, message_sha256: messageHash, message_hashed_bytes: boundedMessage.length,
    message_code_units: message.length, message_truncated: message.length > 1024,
  }})}}\n`);
  process.exitCode = 1;
}});
"#
        ))
    }
}

fn cursor_install_root(canonical_program: &Path) -> Result<PathBuf> {
    if canonical_program.file_name() != Some(OsStr::new("cursor-agent")) {
        bail!("selected Cursor program does not have the expected cursor-agent basename");
    }
    let directory = canonical_program
        .parent()
        .context("selected Cursor program has no parent directory")?;
    let parent = directory
        .parent()
        .context("selected Cursor program has no package prefix")?;
    // Recognize exact package layouts after canonicalization; never search ancestors.
    if directory.file_name() == Some(OsStr::new("bin")) {
        return Ok(parent.join("share/cursor-agent"));
    }
    if directory.file_name() == Some(OsStr::new("cursor-agent"))
        && parent.file_name() == Some(OsStr::new("share"))
    {
        return Ok(directory.to_path_buf());
    }
    bail!("selected Cursor program has an unsupported managed launcher layout");
}

fn bind_executable(path: &Path, label: &str) -> Result<PathBuf> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("{label} is unavailable: {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.mode() & 0o111 == 0 {
        bail!("{label} is not a non-symbolic executable regular file");
    }
    Ok(path.to_path_buf())
}

#[derive(Default)]
struct SharedState {
    evidence: CursorManagedParentEvidence,
    refusal: Option<String>,
    authority: Option<CursorManagedAssignmentAuthority>,
    pending_actions: BTreeMap<String, PendingResourceAction>,
    attempts: BTreeMap<String, CursorAttemptUsage>,
    next_action: u64,
    shared_services_authority: SharedServicesAuthority,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
enum SharedServicesAuthority {
    #[default]
    Refuse,
    ProviderlessQualification,
}

#[derive(Debug, Clone)]
struct CursorManagedAssignmentAuthority {
    workspace: PathBuf,
    workspace_dir: Arc<File>,
    workspace_dev: u64,
    workspace_ino: u64,
    assigned: BTreeSet<PathBuf>,
    main_helper_git: Option<(PathBuf, PinnedDirectExecutable)>,
}

#[derive(Debug, Clone)]
struct PeerIdentity {
    pid: u32,
    start_time: String,
    cgroup_path: String,
}

#[derive(Debug, Clone)]
struct OperationBudget {
    cancellation: ProcessCancellation,
    deadline: Instant,
}

#[derive(Debug, Default)]
struct CursorAttemptUsage {
    input_tokens: Option<u64>,
    output_tokens: Option<u64>,
    cache_read_tokens: Option<u64>,
    cache_write_tokens: Option<u64>,
    terminal_observation: Option<[Option<u64>; 4]>,
    usage_seen: bool,
    conflict: bool,
    completed: bool,
}

#[derive(Debug, Clone, PartialEq)]
struct PendingResourceAction {
    kind: String,
    arguments: Value,
}

impl OperationBudget {
    fn check(&self, phase: &str) -> Result<()> {
        if self.cancellation.is_cancelled() {
            bail!("managed Cursor operation was cancelled during {phase}");
        }
        if Instant::now() >= self.deadline {
            bail!("managed Cursor operation deadline elapsed during {phase}");
        }
        Ok(())
    }

    fn timeout(&self) -> Result<Duration> {
        self.check("transport I/O")?;
        Ok(self
            .deadline
            .saturating_duration_since(Instant::now())
            .min(IO_POLL))
    }

    fn remaining(&self, phase: &str) -> Result<Duration> {
        self.check(phase)?;
        let remaining = self.deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            bail!("managed Cursor operation deadline elapsed during {phase}");
        }
        Ok(remaining)
    }
}

fn bind_peer_identity(
    gate: &ContainedProcessStartGate<'_>,
    budget: &OperationBudget,
) -> Result<PeerIdentity> {
    let path = gate.runtime_directory().join("target-pid");
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK);
    let mut file = loop {
        budget.check("target PID binding")?;
        match options.open(&path) {
            Ok(file) => break file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "managed Cursor target PID record is unavailable: {}",
                        path.display()
                    )
                })
            }
        }
    };
    let metadata = file.metadata()?;
    // SAFETY: geteuid has no preconditions.
    let uid = unsafe { libc::geteuid() };
    if !metadata.is_file()
        || metadata.uid() != uid
        || metadata.nlink() != 1
        || metadata.mode() & 0o077 != 0
        || metadata.len() > 32
    {
        bail!("managed Cursor target PID record is not an owner-private regular file");
    }
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    let pid = contents
        .trim()
        .parse::<u32>()
        .context("managed Cursor target PID record is invalid")?;
    if pid == 0 {
        bail!("managed Cursor target PID record contains PID 0");
    }
    let rebound = fs::symlink_metadata(&path)?;
    if !rebound.is_file() || rebound.dev() != metadata.dev() || rebound.ino() != metadata.ino() {
        bail!("managed Cursor target PID record changed while it was read");
    }
    let start_time = crate::agent_lifecycle::process_start_time(pid)?;
    let cgroup_path = expected_cgroup_record(gate.cgroup_path())?;
    let observed = process_cgroup_v2(pid)?;
    if observed != cgroup_path {
        bail!("managed Cursor target PID is outside the exact admitted cgroup");
    }
    Ok(PeerIdentity {
        pid,
        start_time,
        cgroup_path,
    })
}

fn expected_cgroup_record(path: &Path) -> Result<String> {
    let relative = path
        .strip_prefix("/sys/fs/cgroup")
        .context("managed Cursor admitted cgroup is outside the cgroup-v2 mount")?;
    if relative.as_os_str().is_empty()
        || relative
            .components()
            .any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
        bail!("managed Cursor admitted cgroup path is invalid");
    }
    let relative = relative.to_string_lossy().replace('\\', "/");
    Ok(format!("/{relative}"))
}

fn process_cgroup_v2(pid: u32) -> Result<String> {
    let contents = fs::read_to_string(format!("/proc/{pid}/cgroup"))?;
    let mut records = contents.lines().filter_map(|line| line.strip_prefix("0::"));
    let value = records
        .next()
        .context("managed Cursor peer has no cgroup-v2 record")?;
    if records.next().is_some() || !value.starts_with('/') || value.contains("//") {
        bail!("managed Cursor peer cgroup-v2 record is ambiguous");
    }
    Ok(value.to_string())
}

impl CursorManagedAssignmentAuthority {
    fn new(workspace: &Path, assigned_paths: Vec<PathBuf>) -> Result<Self> {
        let workspace = fs::canonicalize(workspace).with_context(|| {
            format!(
                "failed to canonicalize Cursor workspace {}",
                workspace.display()
            )
        })?;
        let mut directory_options = OpenOptions::new();
        directory_options
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW);
        let workspace_dir = directory_options.open(&workspace).with_context(|| {
            format!(
                "failed to hold managed Cursor workspace {}",
                workspace.display()
            )
        })?;
        let held = workspace_dir.metadata()?;
        let named = fs::metadata(&workspace)?;
        if !held.is_dir() || held.dev() != named.dev() || held.ino() != named.ino() {
            bail!("managed Cursor workspace identity changed while it was opened");
        }
        let mut assigned = BTreeSet::new();
        for path in assigned_paths {
            validate_relative_resource_path(&path)?;
            if !assigned.insert(path) {
                bail!("managed Cursor assignment contains a duplicate path");
            }
        }
        Ok(Self {
            workspace,
            workspace_dir: Arc::new(workspace_dir),
            workspace_dev: held.dev(),
            workspace_ino: held.ino(),
            assigned,
            main_helper_git: None,
        })
    }

    fn bind_main_helper_git(
        &mut self,
        helper: SourceBoundMainHelper,
        budget: &OperationBudget,
    ) -> Result<()> {
        budget.check("qualified Git binding")?;
        let git = crate::merge::resolve_trusted_executable("git")?;
        let pinned_git = PinnedDirectExecutable::capture_with_main_helper(&git, helper)
            .context("failed to bind the exact managed Cursor Git executable")?;
        budget.check("qualified Git binding")?;
        self.main_helper_git = Some((git, pinned_git));
        Ok(())
    }

    fn verify_workspace_identity(&self) -> Result<()> {
        let held = self.workspace_dir.metadata()?;
        let named = fs::metadata(&self.workspace)?;
        if !held.is_dir()
            || held.dev() != self.workspace_dev
            || held.ino() != self.workspace_ino
            || named.dev() != self.workspace_dev
            || named.ino() != self.workspace_ino
        {
            bail!("managed Cursor workspace pathname no longer names the held directory");
        }
        Ok(())
    }

    fn admitted_path(&self, value: &Value) -> Result<PathBuf> {
        let relative = value
            .as_str()
            .context("managed Cursor resource path must be a string")?;
        let relative = PathBuf::from(relative);
        validate_relative_resource_path(&relative)?;
        if !self.assigned.contains(&relative) {
            bail!("managed Cursor resource path is outside the exact assignment");
        }
        Ok(relative)
    }

    fn read(&self, arguments: &Value) -> Result<Value> {
        let object = exact_object(arguments, &["path"])?;
        let relative =
            self.admitted_path(object.get("path").context("filesystem read omitted path")?)?;
        let file = open_workspace_relative(
            self.workspace_dir.as_raw_fd(),
            &relative,
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NONBLOCK,
            0,
        )?;
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.nlink() != 1
            || metadata.len() > MAX_RESOURCE_FILE_BYTES as u64
        {
            bail!("assigned Cursor read target is not a bounded single-link regular file");
        }
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        file.take((MAX_RESOURCE_FILE_BYTES + 1) as u64)
            .read_to_end(&mut bytes)?;
        if bytes.len() > MAX_RESOURCE_FILE_BYTES {
            bail!("assigned Cursor read target grew beyond its byte limit");
        }
        let file_size = bytes.len();
        let text = String::from_utf8(bytes).context("assigned Cursor file is not UTF-8")?;
        let total_lines = text.lines().count();
        Ok(json!({
            "path": relative,
            "text": text,
            "totalLines": total_lines,
            "fileSize": file_size
        }))
    }

    fn write(&self, arguments: &Value) -> Result<Value> {
        let object = exact_object(arguments, &["path", "text"])?;
        let relative = self.admitted_path(
            object
                .get("path")
                .context("filesystem write omitted path")?,
        )?;
        let text = object
            .get("text")
            .and_then(Value::as_str)
            .context("filesystem write text must be a string")?;
        if text.len() > MAX_RESOURCE_FILE_BYTES {
            bail!("assigned Cursor write exceeds its byte limit");
        }
        let mut file = open_workspace_relative(
            self.workspace_dir.as_raw_fd(),
            &relative,
            libc::O_WRONLY | libc::O_CREAT | libc::O_CLOEXEC | libc::O_NONBLOCK,
            0o600,
        )?;
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.nlink() != 1 {
            bail!("assigned Cursor write target is not a single-link regular file");
        }
        file.set_len(0)?;
        file.write_all(text.as_bytes())?;
        file.sync_all()?;
        Ok(json!({
            "path": relative,
            "linesCreated": text.lines().count(),
            "fileSize": text.len()
        }))
    }

    fn offline_check(&self, arguments: &Value, budget: &OperationBudget) -> Result<Value> {
        let object = exact_object(arguments, &["check", "workingDirectory"])?;
        if object.get("check").and_then(Value::as_str) != Some("assignedPathsChangedOnlyUtf8") {
            bail!("managed Cursor requested an unknown offline check");
        }
        let requested_cwd = object
            .get("workingDirectory")
            .and_then(Value::as_str)
            .context("managed Cursor offline check omitted its working directory")?;
        if Path::new(requested_cwd) != self.workspace {
            bail!("managed Cursor offline check changed its working directory");
        }
        self.verify_workspace_identity()?;
        let started = Instant::now();
        let repository = git2::Repository::discover(&self.workspace)
            .context("managed Cursor workspace is not inside a Git repository")?;
        let workdir = repository
            .workdir()
            .context("managed Cursor offline check requires a non-bare repository")?;
        if fs::canonicalize(workdir)? != self.workspace {
            bail!("managed Cursor Git workdir does not equal its contained workspace");
        }
        let mut options = git2::StatusOptions::new();
        options
            .include_untracked(true)
            .recurse_untracked_dirs(true)
            .include_ignored(false)
            .exclude_submodules(true);
        let statuses = repository.statuses(Some(&mut options))?;
        let mut changed = Vec::new();
        for status in statuses.iter() {
            let path = status
                .path()
                .map(PathBuf::from)
                .context("managed Cursor Git status contains a non-UTF-8 path")?;
            validate_relative_resource_path(&path)?;
            if !self.assigned.contains(&path) {
                bail!("managed Cursor changed a path outside the exact assignment");
            }
            let absolute = self.workspace.join(&path);
            if absolute.exists() {
                self.read(&json!({"path": path.to_string_lossy()}))?;
            }
            changed.push(path);
        }
        if changed.is_empty() {
            bail!("managed Cursor offline check found no assigned change");
        }
        self.verify_workspace_identity()?;
        budget.check("offline check construction")?;
        let (git, pinned_git) = self
            .main_helper_git
            .as_ref()
            .context("managed Cursor offline check omitted its genuine main helper binding")?;
        pinned_git
            .validated_launch_helper_path()
            .context("failed to revalidate the managed Cursor main helper")?;
        let mut arguments = vec![
            OsString::from("--no-optional-locks"),
            OsString::from("--literal-pathspecs"),
            OsString::from("-c"),
            OsString::from("core.hooksPath=/dev/null"),
            OsString::from("-c"),
            OsString::from("color.ui=false"),
            OsString::from("-c"),
            OsString::from("diff.external="),
            OsString::from("diff"),
            OsString::from("--no-ext-diff"),
            OsString::from("--no-textconv"),
            OsString::from("--check"),
            OsString::from("--"),
        ];
        arguments.extend(changed.iter().map(|path| path.as_os_str().to_os_string()));
        let common_dir = fs::canonicalize(repository.commondir())
            .context("managed Cursor Git common directory could not be resolved")?;
        let mut profile = StrictOfflineWorkspaceProfile::read_only(&self.workspace);
        if !common_dir.starts_with(&self.workspace) {
            profile = profile.with_visible_read_only_root(&common_dir);
        }
        let private_state = common_dir.join("maco");
        if private_state.exists() {
            profile = profile.with_hidden_root(private_state);
        }
        let timeout = budget.remaining("offline check launch")?;
        let output = run_process_cancellable(
            ProcessSpec::direct(
                "managed Cursor assigned-path Git diff check",
                git,
                arguments,
                &self.workspace,
                256 * 1024,
            )
            .with_environment(EnvironmentMode::ClearAndSet(
                crate::merge::minimal_network_environment()?,
            ))
            .with_stdin(StdinMode::Null)
            .with_timeout(Some(timeout))
            .with_side_effect_confinement(SideEffectConfinementProfile::StrictOfflineWorkspace(
                profile,
            ))
            .with_pinned_direct_executable(pinned_git.clone())?,
            &budget.cancellation,
        )
        .context("managed Cursor assigned-path Git diff check failed to run")?;
        if !output.status.is_some_and(|status| status.success())
            || output.timed_out
            || output.process_error.is_some()
            || output.stdin_error.is_some()
            || output.stdout.is_truncated()
            || output.stderr.is_truncated()
            || !output.process_tree.is_verified_empty()
            || output.side_effects
                != SideEffectConfinementEvidence::Verified(
                    SideEffectConfinementProfileKind::StrictOfflineWorkspace,
                )
        {
            use std::os::unix::process::ExitStatusExt;

            #[cfg(test)]
            eprintln!(
                "{}",
                offline_check_failure_diagnostic(&output.stdout, &output.stderr)
            );

            bail!(
                "managed Cursor assigned-path Git diff check did not complete under exact offline confinement: \
                 exit_code={:?}, signal={:?}, timed_out={}, process_error_present={}, \
                 stdin_error_present={}, stdout_truncated={}, stderr_truncated={}, \
                 process_tree={:?}, side_effects={:?}, assigned_path_count={}, git_path_sha256={}",
                output.status.and_then(|status| status.code()),
                output.status.and_then(|status| status.signal()),
                output.timed_out,
                output.process_error.is_some(),
                output.stdin_error.is_some(),
                output.stdout.is_truncated(),
                output.stderr.is_truncated(),
                output.process_tree,
                output.side_effects,
                changed.len(),
                crate::artifacts::state_auth::sha256_hex(git.as_os_str().as_bytes()),
            );
        }
        let execution_time_millis = u64::try_from(started.elapsed().as_millis())
            .context("managed Cursor offline check duration overflowed")?;
        Ok(json!({
            "command": "maco-offline-check assigned-paths-changed-only-utf8",
            "workingDirectory": self.workspace,
            "stdout": format!("{} assigned path(s) changed\n", changed.len()),
            "stderr": "",
            "executionTimeMillis": execution_time_millis
        }))
    }
}

#[cfg(test)]
#[derive(Debug, PartialEq, Eq)]
enum OfflineCheckObservedMessageCategory {
    Unknown,
    MainHelperIdentity,
    Descriptor,
    PinnedSource,
    SealedExec,
    Multiple,
}

#[cfg(test)]
#[derive(Debug, PartialEq, Eq)]
enum OfflineCheckObservedExactRefusal {
    Unknown,
    ManifestDigestRefusal,
    ProtectedPathRefusal,
    ProtectedComponentRefusal {
        component: crate::pinned_exec::ProtectedHelperComponentRole,
        symlink: bool,
        owner_mismatch: bool,
        writable: bool,
    },
}

#[cfg(test)]
fn observed_protected_component_refusal(stderr: &[u8]) -> OfflineCheckObservedExactRefusal {
    use crate::pinned_exec::ProtectedHelperComponentRole::*;
    use OfflineCheckObservedExactRefusal::*;

    let Some(component_and_flags) = stderr.strip_prefix(
        b"Error: fixed helper path was not owner-controlled and immutable; component=",
    ) else {
        return Unknown;
    };
    let components: [(crate::pinned_exec::ProtectedHelperComponentRole, &[u8]); 7] = [
        (FilesystemRoot, b"FilesystemRoot"),
        (NixRoot, b"NixRoot"),
        (PackageRoot, b"PackageRoot"),
        (PackageBin, b"PackageBin"),
        (PackageExecutable, b"PackageExecutable"),
        (PackageShare, b"PackageShare"),
        (PackageMetadataDirectory, b"PackageMetadataDirectory"),
    ];
    for (component, label) in components {
        let Some(flags) = component_and_flags.strip_prefix(label) else {
            continue;
        };
        // Whole suffix equality closes every bit, separator, final newline and end-of-input.
        // All-zero flags cannot describe the preserved refusal predicate.
        let (symlink, owner_mismatch, writable) = match flags {
            b"; symlink=0; owner_mismatch=0; writable=1\n" => (false, false, true),
            b"; symlink=0; owner_mismatch=1; writable=0\n" => (false, true, false),
            b"; symlink=0; owner_mismatch=1; writable=1\n" => (false, true, true),
            b"; symlink=1; owner_mismatch=0; writable=0\n" => (true, false, false),
            b"; symlink=1; owner_mismatch=0; writable=1\n" => (true, false, true),
            b"; symlink=1; owner_mismatch=1; writable=0\n" => (true, true, false),
            b"; symlink=1; owner_mismatch=1; writable=1\n" => (true, true, true),
            _ => return Unknown,
        };
        return ProtectedComponentRefusal {
            component,
            symlink,
            owner_mismatch,
            writable,
        };
    }
    Unknown
}

#[cfg(test)]
fn offline_check_failure_diagnostic(
    stdout: &crate::process_runner::CapturedBytes,
    stderr: &crate::process_runner::CapturedBytes,
) -> String {
    use OfflineCheckObservedMessageCategory::*;

    // Untrusted token observations are not authenticated process-origin or root-cause proof.
    let categories: [(OfflineCheckObservedMessageCategory, &[&[u8]]); 4] = [
        (
            MainHelperIdentity,
            &[
                b"source-bound main helper invocation changed",
                b"loaded main helper identity did not match its package",
                b"source-bound main helper or package identity changed",
            ],
        ),
        (
            Descriptor,
            &[
                b"could not open pinned helper descriptor",
                b"pinned helper descriptor identity or permissions were invalid",
                b"pinned helper descriptor changed while being read",
                b"could not remove consumed pinned helper descriptor",
                b"pinned helper mode did not match its descriptor",
            ],
        ),
        (
            PinnedSource,
            &[
                b"could not open pinned executable source",
                b"pinned executable metadata did not match its binding",
            ],
        ),
        (
            SealedExec,
            &[
                b"could not create sealed executable descriptor",
                b"could not execute the sealed executable",
            ],
        ),
    ];
    let mut observed = Unknown;
    for (category, tokens) in categories {
        if tokens.iter().any(|token| {
            [stdout.as_bytes(), stderr.as_bytes()]
                .into_iter()
                .any(|bytes| bytes.windows(token.len()).any(|window| window == *token))
        }) {
            if observed != Unknown {
                observed = Multiple;
                break;
            }
            observed = category;
        }
    }
    // Whole captured-message equality is still only an untrusted observation.
    // No private prefix/suffix, truncation, or output on another stream is admitted.
    let observed_exact_refusal =
        if stdout.is_truncated() || stderr.is_truncated() || !stdout.as_bytes().is_empty() {
            OfflineCheckObservedExactRefusal::Unknown
        } else {
            match stderr.as_bytes() {
                b"Error: main helper manifest bytes did not match its declaration\n" => {
                    OfflineCheckObservedExactRefusal::ManifestDigestRefusal
                }
                b"Error: fixed helper path was not owner-controlled and immutable\n" => {
                    OfflineCheckObservedExactRefusal::ProtectedPathRefusal
                }
                _ => observed_protected_component_refusal(stderr.as_bytes()),
            }
        };
    format!(
        "managed Cursor offline check captured-output diagnostic: retained_stdout_bytes={}, retained_stderr_bytes={}, observed_opaque_message_category={observed:?}, observed_exact_public_refusal={observed_exact_refusal:?}",
        stdout.as_bytes().len(),
        stderr.as_bytes().len(),
    )
}

fn open_workspace_relative(root_fd: RawFd, relative: &Path, flags: i32, mode: u32) -> Result<File> {
    let path = CString::new(relative.as_os_str().as_bytes())
        .context("managed Cursor resource path contains NUL")?;
    let how = LinuxOpenHow {
        flags: u64::try_from(flags).context("managed Cursor open flags overflowed")?,
        mode: u64::from(mode),
        resolve: RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS | RESOLVE_NO_XDEV,
    };
    // SAFETY: root_fd is a held directory descriptor; path and how remain valid for the syscall.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            root_fd,
            path.as_ptr(),
            &how as *const LinuxOpenHow,
            std::mem::size_of::<LinuxOpenHow>(),
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error()).with_context(|| {
            format!(
                "failed to open mount-confined managed Cursor path {}",
                relative.display()
            )
        });
    }
    // SAFETY: a successful openat2 call returns one owned descriptor.
    Ok(unsafe { File::from_raw_fd(fd as RawFd) })
}

fn validate_relative_resource_path(path: &Path) -> Result<()> {
    if path.as_os_str().is_empty() || path.is_absolute() {
        bail!("managed Cursor resource path must be a non-empty relative path");
    }
    for component in path.components() {
        if !matches!(component, std::path::Component::Normal(_)) {
            bail!("managed Cursor resource path contains a non-normal component");
        }
    }
    if path.starts_with(".git") {
        bail!("managed Cursor may not access Git control paths");
    }
    Ok(())
}

fn exact_object<'a>(value: &'a Value, keys: &[&str]) -> Result<&'a serde_json::Map<String, Value>> {
    let object = value
        .as_object()
        .context("managed Cursor resource arguments must be an object")?;
    if object.len() != keys.len() || keys.iter().any(|key| !object.contains_key(*key)) {
        bail!("managed Cursor resource arguments do not match the exact schema");
    }
    Ok(object)
}

pub(crate) struct CursorManagedParent {
    socket_path: PathBuf,
    stop: Arc<AtomicBool>,
    state: Arc<Mutex<SharedState>>,
    thread: Option<JoinHandle<()>>,
    finished: Option<mpsc::Receiver<()>>,
    budget: OperationBudget,
    active_stream: Arc<Mutex<Option<UnixStream>>>,
}

impl CursorManagedParent {
    pub(crate) fn start(
        gate: &ContainedProcessStartGate<'_>,
        workspace: &Path,
        assigned_paths: Vec<PathBuf>,
        cancellation: ProcessCancellation,
        operation_deadline: Instant,
    ) -> Result<Self> {
        let budget = OperationBudget {
            cancellation: cancellation.clone(),
            deadline: operation_deadline,
        };
        budget.check("main helper binding")?;
        let main_helper = SourceBoundMainHelper::capture_current_packaged()
            .context("managed Cursor requires its genuine source-bound packaged main helper")?;
        budget.check("main helper binding")?;
        Self::start_with_shared_services_authority(
            gate,
            workspace,
            assigned_paths,
            cancellation,
            operation_deadline,
            SharedServicesAuthority::Refuse,
            main_helper,
        )
    }

    #[cfg(test)]
    pub(crate) fn start_providerless_qualification(
        gate: &ContainedProcessStartGate<'_>,
        workspace: &Path,
        assigned_paths: Vec<PathBuf>,
        cancellation: ProcessCancellation,
        operation_deadline: Instant,
        main_helper: SourceBoundMainHelper,
    ) -> Result<Self> {
        Self::start_with_shared_services_authority(
            gate,
            workspace,
            assigned_paths,
            cancellation,
            operation_deadline,
            SharedServicesAuthority::ProviderlessQualification,
            main_helper,
        )
    }

    fn start_with_shared_services_authority(
        gate: &ContainedProcessStartGate<'_>,
        workspace: &Path,
        assigned_paths: Vec<PathBuf>,
        cancellation: ProcessCancellation,
        operation_deadline: Instant,
        shared_services_authority: SharedServicesAuthority,
        main_helper: SourceBoundMainHelper,
    ) -> Result<Self> {
        let budget = OperationBudget {
            cancellation,
            deadline: operation_deadline,
        };
        budget.check("parent setup")?;
        let mut authority = CursorManagedAssignmentAuthority::new(workspace, assigned_paths)?;
        authority.bind_main_helper_git(main_helper, &budget)?;
        let peer = bind_peer_identity(gate, &budget)?;
        let socket_path = gate.runtime_directory().join(SOCKET_NAME);
        if socket_path.exists() {
            bail!("managed Cursor parent socket already exists");
        }
        let listener = UnixListener::bind(&socket_path).with_context(|| {
            format!(
                "failed to bind managed Cursor parent socket {}",
                socket_path.display()
            )
        })?;
        fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600))?;
        listener.set_nonblocking(true)?;
        let stop = Arc::new(AtomicBool::new(false));
        let state = Arc::new(Mutex::new(SharedState {
            authority: Some(authority),
            shared_services_authority,
            ..SharedState::default()
        }));
        let thread_stop = Arc::clone(&stop);
        let thread_state = Arc::clone(&state);
        let thread_budget = budget.clone();
        let active_stream = Arc::new(Mutex::new(None));
        let thread_active_stream = Arc::clone(&active_stream);
        let (finished_tx, finished) = mpsc::channel();
        let thread = thread::Builder::new()
            .name("maco-cursor-parent".to_string())
            .spawn(move || {
                serve(
                    listener,
                    &peer,
                    &thread_budget,
                    thread_stop,
                    thread_state,
                    thread_active_stream,
                );
                let _ = finished_tx.send(());
            })?;
        Ok(Self {
            socket_path,
            stop,
            state,
            thread: Some(thread),
            finished: Some(finished),
            budget,
            active_stream,
        })
    }

    pub(crate) fn finish(mut self) -> Result<CursorManagedParentEvidence> {
        self.request_stop();
        self.join_owned_parent()?;
        let state = self.state.lock().expect("managed Cursor parent state");
        if let Some(refusal) = &state.refusal {
            bail!("managed Cursor parent refused transport: {refusal}");
        }
        if !state.pending_actions.is_empty() {
            bail!("managed Cursor parent stopped with an authorized action still pending");
        }
        Ok(state.evidence.clone())
    }

    fn request_stop(&self) {
        self.stop.store(true, Ordering::Release);
        if let Some(stream) = self
            .active_stream
            .lock()
            .expect("managed Cursor active stream")
            .as_ref()
        {
            let _ = stream.shutdown(Shutdown::Both);
        }
        let _ = UnixStream::connect(&self.socket_path);
    }

    fn join_owned_parent(&mut self) -> Result<()> {
        if self.thread.is_none() {
            return Ok(());
        }
        let remaining = self
            .budget
            .deadline
            .saturating_duration_since(Instant::now());
        let Some(finished) = self.finished.as_ref() else {
            fail_closed_stuck_parent();
        };
        let terminal = if remaining.is_zero() {
            match finished.try_recv() {
                Ok(()) | Err(mpsc::TryRecvError::Disconnected) => true,
                Err(mpsc::TryRecvError::Empty) => false,
            }
        } else {
            match finished.recv_timeout(remaining) {
                Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => true,
                Err(mpsc::RecvTimeoutError::Timeout) => false,
            }
        };
        if !terminal {
            fail_closed_stuck_parent();
        }
        let Some(thread) = self.thread.take() else {
            fail_closed_stuck_parent();
        };
        self.finished.take();
        let joined = thread
            .join()
            .map_err(|_| anyhow::anyhow!("managed Cursor parent thread panicked"));
        let _ = fs::remove_file(&self.socket_path);
        joined
    }
}

impl Drop for CursorManagedParent {
    fn drop(&mut self) {
        self.request_stop();
        if self.thread.is_some() {
            let _ = self.join_owned_parent();
        }
        if self.thread.is_none() {
            let _ = fs::remove_file(&self.socket_path);
        }
    }
}

fn fail_closed_stuck_parent() -> ! {
    let _ = writeln!(
        std::io::stderr().lock(),
        "fatal: managed Cursor parent remained live past its absolute operation deadline; aborting rather than releasing assignment custody"
    );
    std::process::abort()
}

fn serve(
    listener: UnixListener,
    peer: &PeerIdentity,
    budget: &OperationBudget,
    stop: Arc<AtomicBool>,
    state: Arc<Mutex<SharedState>>,
    active_stream: Arc<Mutex<Option<UnixStream>>>,
) {
    while !stop.load(Ordering::Acquire) {
        if let Err(error) = budget.check("socket accept") {
            state.lock().expect("managed Cursor parent state").refusal = Some(error.to_string());
            return;
        }
        match listener.accept() {
            Ok((stream, _)) => {
                if stop.load(Ordering::Acquire) {
                    return;
                }
                match stream.try_clone() {
                    Ok(held) => {
                        *active_stream.lock().expect("managed Cursor active stream") = Some(held);
                    }
                    Err(error) => {
                        state.lock().expect("managed Cursor parent state").refusal =
                            Some(error.to_string());
                        return;
                    }
                }
                let result = serve_stream(stream, peer, budget, &stop, &state);
                active_stream
                    .lock()
                    .expect("managed Cursor active stream")
                    .take();
                if let Err(error) = result {
                    if !stop.load(Ordering::Acquire) {
                        state.lock().expect("managed Cursor parent state").refusal =
                            Some(error.to_string());
                    }
                }
                return;
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => {
                state.lock().expect("managed Cursor parent state").refusal =
                    Some(error.to_string());
                return;
            }
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    id: String,
    method: String,
    payload: Value,
}

fn serve_stream(
    mut stream: UnixStream,
    peer: &PeerIdentity,
    budget: &OperationBudget,
    stop: &AtomicBool,
    state: &Mutex<SharedState>,
) -> Result<()> {
    verify_peer(&stream, peer)?;
    state
        .lock()
        .expect("managed Cursor parent state")
        .evidence
        .peer_verified = true;
    let mut pending = Vec::new();
    let mut chunk = [0_u8; 8192];
    loop {
        if stop.load(Ordering::Acquire) {
            break;
        }
        budget.check("request framing")?;
        stream.set_read_timeout(Some(budget.timeout()?))?;
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(read) => pending.extend_from_slice(&chunk[..read]),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                continue
            }
            Err(error) => return Err(error.into()),
        }
        if pending.len() > MAX_FRAME_BYTES {
            bail!("managed Cursor request exceeded frame limit");
        }
        while let Some(newline) = pending.iter().position(|byte| *byte == b'\n') {
            budget.check("request dispatch")?;
            let mut remainder = pending.split_off(newline + 1);
            pending.pop();
            let request: Request =
                serde_json::from_slice(&pending).context("managed Cursor request is invalid")?;
            pending = std::mem::take(&mut remainder);
            if request.id.is_empty() || request.id.len() > 128 {
                bail!("managed Cursor request id is invalid");
            }
            let response = handle_request(&request, state, budget);
            let mut encoded = serde_json::to_vec(&response)?;
            encoded.push(b'\n');
            if encoded.len() > MAX_FRAME_BYTES {
                bail!("managed Cursor response exceeded frame limit");
            }
            write_bounded(&mut stream, &encoded, budget)?;
        }
    }
    if !pending.is_empty() {
        bail!("managed Cursor transport ended with an incomplete frame");
    }
    Ok(())
}

fn write_bounded(stream: &mut UnixStream, bytes: &[u8], budget: &OperationBudget) -> Result<()> {
    let mut written = 0;
    while written < bytes.len() {
        budget.check("response write")?;
        stream.set_write_timeout(Some(budget.timeout()?))?;
        match stream.write(&bytes[written..]) {
            Ok(0) => bail!("managed Cursor response transport closed"),
            Ok(count) => written += count,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn handle_request(
    request: &Request,
    state: &Mutex<SharedState>,
    budget: &OperationBudget,
) -> Value {
    if let Err(error) = budget.check("request handling") {
        return json!({"id": request.id, "ok": false, "error": error.to_string()});
    }
    let attempt_id = request
        .payload
        .get("attemptId")
        .and_then(Value::as_str)
        .unwrap_or("");
    let mut state = state.lock().expect("managed Cursor parent state");
    let result = match request.method.as_str() {
        "createSharedServices" => match create_shared_services(&request.payload, &mut state) {
            Ok(result) => result,
            Err(error) => {
                state.evidence.shared_services_refusals += 1;
                json!({"ack": false, "reason": error.to_string()})
            }
        },
        "createSessionResources" => {
            state.evidence.session_resource_acks += 1;
            json!({
                "ack": true,
                "policyVersion": 1,
                "moduleId": "../agent-exec/dist/index.js",
                "nativeHostExec": false,
                "mcp": false,
                "hooks": false,
                "subagents": false,
                "resources": [
                    {
                        "kind": "filesystemRead",
                        "exportName": "_A",
                        "protoModule": "../proto/dist/generated/agent/v1/read_exec_pb.js",
                        "argumentTypeName": "agent.v1.ReadArgs",
                        "resultExportName": "sV",
                        "resultTypeName": "agent.v1.ReadResult",
                        "successExportName": "mE",
                        "successTypeName": "agent.v1.ReadSuccess"
                    },
                    {
                        "kind": "filesystemWrite",
                        "exportName": "Ln",
                        "protoModule": "../proto/dist/generated/agent/v1/write_exec_pb.js",
                        "argumentTypeName": "agent.v1.WriteArgs",
                        "resultExportName": "v3",
                        "resultTypeName": "agent.v1.WriteResult",
                        "successExportName": "j6",
                        "successTypeName": "agent.v1.WriteSuccess"
                    },
                    {
                        "kind": "offlineCheck",
                        "exportName": "qk",
                        "protoModule": "../proto/dist/generated/agent/v1/shell_exec_pb.js",
                        "argumentTypeName": "agent.v1.ShellArgs",
                        "resultExportName": "W4",
                        "resultTypeName": "agent.v1.ShellResult",
                        "successExportName": "QR",
                        "successTypeName": "agent.v1.ShellSuccess"
                    }
                ]
            })
        }
        "authorizeResourceAction" => {
            match authorize_resource_action(&request.payload, &mut state) {
                Ok(result) => result,
                Err(error) => {
                    state.evidence.refused_actions += 1;
                    return json!({"id": request.id, "ok": false, "error": error.to_string()});
                }
            }
        }
        "executeResourceAction" => {
            match execute_resource_action(&request.payload, &mut state, budget) {
                Ok(result) => result,
                Err(error) => {
                    state.evidence.refused_actions += 1;
                    return json!({"id": request.id, "ok": false, "error": error.to_string()});
                }
            }
        }
        "admitRpcAttempt" => match admit_rpc_attempt(attempt_id, &mut state) {
            Ok(result) => result,
            Err(error) => return json!({"id": request.id, "ok": false, "error": error.to_string()}),
        },
        "captureRawEvent" => match capture_raw_event(attempt_id, &request.payload, &mut state) {
            Ok(result) => result,
            Err(error) => return json!({"id": request.id, "ok": false, "error": error.to_string()}),
        },
        "completeRpcAttempt" => {
            match complete_rpc_attempt(attempt_id, &request.payload, &mut state) {
                Ok(result) => result,
                Err(error) => {
                    return json!({"id": request.id, "ok": false, "error": error.to_string()})
                }
            }
        }
        "authorizeAction" if !attempt_id.is_empty() => {
            state.evidence.refused_actions += 1;
            return json!({"id": request.id, "ok": false, "error": "effectful Cursor actions remain denied until the reviewed Q/Y owned-resource constructor is installed"});
        }
        _ => {
            return json!({"id": request.id, "ok": false, "error": "unknown managed Cursor parent method"});
        }
    };
    json!({"id": request.id, "ok": true, "result": result})
}

fn valid_attempt_id(value: &str) -> bool {
    value
        .strip_prefix("cursor-rpc-")
        .and_then(|value| value.parse::<u64>().ok())
        .is_some_and(|value| value > 0)
}

fn admit_rpc_attempt(attempt_id: &str, state: &mut SharedState) -> Result<Value> {
    if !valid_attempt_id(attempt_id) || state.attempts.contains_key(attempt_id) {
        bail!("managed Cursor RPC attempt id is invalid or reused");
    }
    state
        .attempts
        .insert(attempt_id.to_string(), CursorAttemptUsage::default());
    state.evidence.admitted_attempts += 1;
    refresh_usage_evidence(state);
    Ok(json!({"ack": true, "attemptId": attempt_id, "cancel": false}))
}

fn capture_raw_event(attempt_id: &str, payload: &Value, state: &mut SharedState) -> Result<Value> {
    let attempt = state
        .attempts
        .get_mut(attempt_id)
        .context("managed Cursor captured an event for an unknown attempt")?;
    if attempt.completed {
        bail!("managed Cursor captured an event after attempt completion");
    }
    state.evidence.captured_events += 1;
    observe_cursor_usage(payload, attempt);
    refresh_usage_evidence(state);
    Ok(json!({"ack": true, "attemptId": attempt_id, "cancel": false}))
}

fn complete_rpc_attempt(
    attempt_id: &str,
    payload: &Value,
    state: &mut SharedState,
) -> Result<Value> {
    let attempt = state
        .attempts
        .get_mut(attempt_id)
        .context("managed Cursor completed an unknown attempt")?;
    if attempt.completed {
        bail!("managed Cursor completed an attempt more than once");
    }
    attempt.completed = true;
    if payload.get("outcome").and_then(Value::as_str) != Some("eof") {
        attempt.conflict = true;
    }
    state.evidence.completed_attempts += 1;
    refresh_usage_evidence(state);
    Ok(json!({"ack": true, "attemptId": attempt_id}))
}

fn observe_cursor_usage(payload: &Value, attempt: &mut CursorAttemptUsage) {
    let Some(message) = payload.pointer("/raw/message") else {
        return;
    };
    if message.get("case").and_then(Value::as_str) != Some("interactionUpdate") {
        return;
    }
    let Some(nested) = message.pointer("/value/message") else {
        return;
    };
    if nested.get("case").and_then(Value::as_str) != Some("turnEnded") {
        return;
    }
    let value = nested.get("value").unwrap_or(&Value::Null);
    let values = [
        encoded_nonnegative_integer(value.get("inputTokens")),
        encoded_nonnegative_integer(value.get("outputTokens")),
        encoded_nonnegative_integer(value.get("cacheReadTokens")),
        encoded_nonnegative_integer(value.get("cacheWriteTokens")),
    ];
    if attempt
        .terminal_observation
        .is_some_and(|prior| prior != values)
    {
        attempt.conflict = true;
    }
    attempt.terminal_observation.get_or_insert(values);
    attempt.usage_seen |= values.iter().any(Option::is_some);
    update_usage_lower_bound(&mut attempt.input_tokens, values[0]);
    update_usage_lower_bound(&mut attempt.output_tokens, values[1]);
    update_usage_lower_bound(&mut attempt.cache_read_tokens, values[2]);
    update_usage_lower_bound(&mut attempt.cache_write_tokens, values[3]);
}

fn update_usage_lower_bound(slot: &mut Option<u64>, value: Option<u64>) {
    if let Some(value) = value {
        *slot = Some(slot.unwrap_or(0).max(value));
    }
}

fn refresh_usage_evidence(state: &mut SharedState) {
    let mut covered = 0_u64;
    let mut incomplete = 0_u64;
    for attempt in state.attempts.values() {
        let complete = attempt.completed
            && attempt.usage_seen
            && !attempt.conflict
            && attempt.input_tokens.is_some()
            && attempt.output_tokens.is_some()
            && attempt.cache_read_tokens.is_some()
            && attempt.cache_write_tokens.is_some();
        if complete {
            covered += 1;
        } else {
            incomplete += 1;
        }
    }
    let (input, input_overflow) =
        aggregate_usage_floor(state.attempts.values().map(|attempt| attempt.input_tokens));
    let (output, output_overflow) =
        aggregate_usage_floor(state.attempts.values().map(|attempt| attempt.output_tokens));
    let (cache_read, cache_read_overflow) = aggregate_usage_floor(
        state
            .attempts
            .values()
            .map(|attempt| attempt.cache_read_tokens),
    );
    let (cache_write, cache_write_overflow) = aggregate_usage_floor(
        state
            .attempts
            .values()
            .map(|attempt| attempt.cache_write_tokens),
    );
    let overflow = input_overflow || output_overflow || cache_read_overflow || cache_write_overflow;
    let all_complete = !state.attempts.is_empty() && incomplete == 0 && !overflow;
    state.evidence.usage_attempts_covered = covered;
    state.evidence.usage_attempts_incomplete = incomplete;
    state.evidence.input_tokens = input;
    state.evidence.output_tokens = output;
    state.evidence.cache_read_tokens = cache_read;
    state.evidence.cache_write_tokens = cache_write;
    state.evidence.usage_is_incomplete = Some(!all_complete);
}

fn aggregate_usage_floor(values: impl Iterator<Item = Option<u64>>) -> (Option<u64>, bool) {
    let mut observed = false;
    let mut total = 0_u64;
    for value in values.flatten() {
        observed = true;
        let Some(next) = total.checked_add(value) else {
            return (Some(total), true);
        };
        total = next;
    }
    (observed.then_some(total), false)
}

fn encoded_nonnegative_integer(value: Option<&Value>) -> Option<u64> {
    match value? {
        Value::Number(number) => number.as_u64(),
        Value::Object(object) if object.len() == 1 => object
            .get("$macoInt")
            .and_then(Value::as_str)
            .and_then(|value| value.parse().ok()),
        _ => None,
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResourceAuthorizationRequest {
    kind: String,
    arguments: Value,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ResourceExecutionRequest {
    kind: String,
    action_id: String,
    arguments: Value,
    cancelled: bool,
}

fn create_shared_services(payload: &Value, state: &mut SharedState) -> Result<Value> {
    let object = exact_object(
        payload,
        &["moduleId", "originalFactoryInvocation", "arguments"],
    )?;
    if object.get("moduleId").and_then(Value::as_str) != Some("./src/acp/shared-services.ts")
        || object
            .get("originalFactoryInvocation")
            .and_then(Value::as_str)
            != Some("forbidden")
        || !object
            .get("arguments")
            .and_then(Value::as_array)
            .is_some_and(Vec::is_empty)
    {
        bail!("managed Cursor shared-services request changed shape");
    }
    if state.shared_services_authority != SharedServicesAuthority::ProviderlessQualification {
        bail!("original shared-services construction remains forbidden");
    }
    state.evidence.shared_services_acks += 1;
    Ok(json!({
        "ack": true,
        "policyVersion": 1,
        "moduleId": "./src/acp/shared-services.ts",
        "providerlessQualification": true,
        "agentEndpoint": "http://127.0.0.1:9",
        "auth": "deny-all-parent-fixed",
        "fixedModel": "maco-providerless-qualification",
        "network": false,
        "nativeHostExec": false,
        "mcp": false,
        "hooks": false,
        "skills": false,
        "subagents": false
    }))
}

fn authorize_resource_action(payload: &Value, state: &mut SharedState) -> Result<Value> {
    let request: ResourceAuthorizationRequest = serde_json::from_value(payload.clone())
        .context("managed Cursor resource authorization payload is invalid")?;
    let authority = state
        .authority
        .clone()
        .context("managed Cursor assignment authority is unavailable")?;
    match request.kind.as_str() {
        "filesystemRead" => {
            let object = exact_object(&request.arguments, &["path"])?;
            authority.admitted_path(object.get("path").context("read path missing")?)?;
        }
        "filesystemWrite" => {
            let object = exact_object(&request.arguments, &["path", "text"])?;
            authority.admitted_path(object.get("path").context("write path missing")?)?;
            let text = object
                .get("text")
                .and_then(Value::as_str)
                .context("write text must be a string")?;
            if text.len() > MAX_RESOURCE_FILE_BYTES {
                bail!("managed Cursor write exceeds its byte limit");
            }
        }
        "offlineCheck" => {
            let object = exact_object(&request.arguments, &["check", "workingDirectory"])?;
            if object.get("check").and_then(Value::as_str) != Some("assignedPathsChangedOnlyUtf8") {
                bail!("managed Cursor requested an unknown offline check");
            }
            let requested_cwd = object
                .get("workingDirectory")
                .and_then(Value::as_str)
                .context("managed Cursor offline check omitted its working directory")?;
            if Path::new(requested_cwd) != authority.workspace {
                bail!("managed Cursor offline check changed its working directory");
            }
            authority.verify_workspace_identity()?;
        }
        _ => bail!("managed Cursor requested an unadmitted resource kind"),
    }
    state.next_action = state
        .next_action
        .checked_add(1)
        .context("managed Cursor resource action counter overflowed")?;
    let action_id = format!("cursor-action-{}", state.next_action);
    state.pending_actions.insert(
        action_id.clone(),
        PendingResourceAction {
            kind: request.kind.clone(),
            arguments: request.arguments,
        },
    );
    Ok(json!({"ack": true, "attemptId": request.kind, "actionId": action_id}))
}

fn execute_resource_action(
    payload: &Value,
    state: &mut SharedState,
    budget: &OperationBudget,
) -> Result<Value> {
    let request: ResourceExecutionRequest = serde_json::from_value(payload.clone())
        .context("managed Cursor resource execution payload is invalid")?;
    let pending = state
        .pending_actions
        .remove(&request.action_id)
        .context("managed Cursor resource action was not authorized")?;
    if pending.kind != request.kind || pending.arguments != request.arguments {
        bail!("managed Cursor resource action changed after authorization");
    }
    if request.cancelled {
        return Ok(json!({
            "ack": true,
            "attemptId": request.kind,
            "actionId": request.action_id,
            "cancelled": true
        }));
    }
    budget.check("resource effect dispatch")?;
    let authority = state
        .authority
        .clone()
        .context("managed Cursor assignment authority is unavailable")?;
    let result = match request.kind.as_str() {
        "filesystemRead" => {
            let result = authority.read(&request.arguments)?;
            state.evidence.filesystem_reads += 1;
            result
        }
        "filesystemWrite" => {
            let result = authority.write(&request.arguments)?;
            state.evidence.filesystem_writes += 1;
            result
        }
        "offlineCheck" => {
            let result = authority.offline_check(&request.arguments, budget)?;
            state.evidence.offline_checks += 1;
            result
        }
        _ => bail!("managed Cursor requested an unadmitted resource kind"),
    };
    budget.check("resource effect completion")?;
    Ok(json!({
        "ack": true,
        "attemptId": request.kind,
        "actionId": request.action_id,
        "result": result
    }))
}

fn verify_peer(stream: &UnixStream, expected: &PeerIdentity) -> Result<()> {
    use std::os::fd::AsRawFd;
    let mut credentials = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: the output pointer and length describe a valid `ucred` value.
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut credentials as *mut libc::ucred).cast(),
            &mut length,
        )
    };
    if result != 0 || credentials.pid <= 0 {
        bail!("managed Cursor peer credentials are unavailable");
    }
    // SAFETY: geteuid has no preconditions.
    if credentials.uid != unsafe { libc::geteuid() } {
        bail!("managed Cursor peer uid does not match the owner");
    }
    let pid = u32::try_from(credentials.pid).context("managed Cursor peer PID is invalid")?;
    let start_time = crate::agent_lifecycle::process_start_time(pid)?;
    let cgroup_path = process_cgroup_v2(pid)?;
    if !peer_identity_matches(pid, &start_time, &cgroup_path, expected) {
        bail!("managed Cursor peer does not match the admitted PID/start/cgroup identity");
    }
    Ok(())
}

fn peer_identity_matches(
    pid: u32,
    start_time: &str,
    cgroup_path: &str,
    expected: &PeerIdentity,
) -> bool {
    pid == expected.pid && start_time == expected.start_time && cgroup_path == expected.cgroup_path
}

pub(crate) fn operation_deadline_unix_millis(timeout: Duration) -> Result<u64> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?;
    u64::try_from(now.saturating_add(timeout).as_millis())
        .context("managed Cursor operation deadline overflowed")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn install_binding_resolves_bin_symlink_to_share_cursor_agent_once() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let prefix = temp.path().join("package");
        let root = prefix.join("share/cursor-agent");
        fs::create_dir_all(prefix.join("bin"))?;
        fs::create_dir_all(&root)?;
        let target = root.join("cursor-agent");
        fs::write(&target, "fixture launcher must never execute\n")?;
        fs::set_permissions(&target, fs::Permissions::from_mode(0o555))?;
        let selected = prefix.join("bin/cursor-agent");
        std::os::unix::fs::symlink("../share/cursor-agent/cursor-agent", &selected)?;

        let canonical = fs::canonicalize(&selected)?;
        let canonical_root = fs::canonicalize(&root)?;
        assert_eq!(canonical, canonical_root.join("cursor-agent"));
        assert_eq!(cursor_install_root(&canonical)?, canonical_root);
        assert_ne!(
            cursor_install_root(&canonical)?,
            prefix.join("share/share/cursor-agent")
        );

        // Exercise bind itself: the corrected layout reaches the unchanged hash guard.
        fs::write(root.join("index.js"), "altered vendor entry\n")?;
        let error = CursorManagedInstall::bind(&selected)
            .expect_err("fixture vendor bytes must never receive a successful install binding");
        assert!(
            format!("{error:#}").contains("Cursor entry digest mismatch"),
            "{error:#}"
        );

        let direct_prefix = temp.path().join("direct-package");
        fs::create_dir_all(direct_prefix.join("bin"))?;
        let direct = direct_prefix.join("bin/cursor-agent");
        fs::write(&direct, "fixture direct launcher must never execute\n")?;
        let direct = fs::canonicalize(direct)?;
        assert_eq!(
            cursor_install_root(&direct)?,
            direct_prefix.join("share/cursor-agent")
        );
        Ok(())
    }

    #[test]
    fn install_binding_refuses_mismatched_layout_and_launcher_basename() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let prefix = temp.path().join("package");
        let root = prefix.join("share/cursor-agent");
        fs::create_dir_all(&root)?;
        fs::write(
            root.join("index.js"),
            "surrounding sources must not be searched\n",
        )?;

        for relative in [
            "share/not-cursor/cursor-agent",
            "lib/cursor-agent/cursor-agent",
            "share/cursor-agent/nested/cursor-agent",
            "share/cursor-agent/not-cursor-agent",
        ] {
            let target = prefix.join(relative);
            fs::create_dir_all(target.parent().context("fixture target parent")?)?;
            fs::write(&target, "fixture mismatched launcher must never execute\n")?;
            let selected = temp.path().join("cursor-agent");
            std::os::unix::fs::symlink(&target, &selected)?;
            let error = CursorManagedInstall::bind(&selected)
                .expect_err("a different launcher basename or package layout must refuse");
            let message = format!("{error:#}");
            assert!(
                message.contains("expected cursor-agent basename")
                    || message.contains("unsupported managed launcher layout"),
                "{relative}: {message}"
            );
            assert!(!message.contains("Cursor entry"), "{relative}: {message}");
            fs::remove_file(&selected)?;
        }
        Ok(())
    }

    #[test]
    fn offline_check_failure_diagnostic_keeps_untrusted_output_private() {
        use crate::process_runner::CapturedBytes;

        let secret = b"synthetic-private-token=never-emit; /private/path; \x1b[31m\n\xff\0";
        let cases: [(&[u8], &str); 7] = [
            (b"observed_opaque_message_category=SealedExec", "Unknown"),
            (
                b"source-bound main helper invocation changed; loaded main helper identity did not match its package",
                "MainHelperIdentity",
            ),
            (b"could not open pinned helper descriptor", "Descriptor"),
            (b"could not open pinned executable source", "PinnedSource"),
            (b"could not execute the sealed executable", "SealedExec"),
            (
                b"could not create sealed executable descriptor; could not execute the sealed executable; could not execute the sealed executable",
                "SealedExec",
            ),
            (
                b"could not open pinned helper descriptor; could not execute the sealed executable",
                "Multiple",
            ),
        ];
        for (tokens, expected_category) in cases {
            for tokens_on_stdout in [false, true] {
                let mut stdout_bytes = secret.to_vec();
                let mut stderr_bytes = secret.to_vec();
                if tokens_on_stdout {
                    stdout_bytes.extend_from_slice(tokens);
                } else {
                    stderr_bytes.extend_from_slice(tokens);
                }
                let stdout = CapturedBytes::from_bytes_with_truncation_for_test(stdout_bytes, true);
                let stderr = CapturedBytes::from_bytes_for_test(stderr_bytes);
                let rendered = offline_check_failure_diagnostic(&stdout, &stderr);
                assert_eq!(
                    rendered,
                    format!(
                        "managed Cursor offline check captured-output diagnostic: retained_stdout_bytes={}, retained_stderr_bytes={}, observed_opaque_message_category={expected_category}, observed_exact_public_refusal=Unknown",
                        stdout.as_bytes().len(),
                        stderr.as_bytes().len(),
                    )
                );
                // Same lengths and fixed tokens, different private bytes: identical disclosure.
                let mut alternate_stdout = vec![b'x'; secret.len()];
                let mut alternate_stderr = vec![b'y'; secret.len()];
                if tokens_on_stdout {
                    alternate_stdout.extend_from_slice(tokens);
                } else {
                    alternate_stderr.extend_from_slice(tokens);
                }
                assert_eq!(
                    rendered,
                    offline_check_failure_diagnostic(
                        &CapturedBytes::from_bytes_for_test(alternate_stdout),
                        &CapturedBytes::from_bytes_for_test(alternate_stderr),
                    )
                );
            }
        }
        let stdout =
            CapturedBytes::from_bytes_for_test(b"could not open pinned executable source".to_vec());
        let stderr = CapturedBytes::from_bytes_for_test(
            b"pinned executable metadata did not match its binding".to_vec(),
        );
        assert!(offline_check_failure_diagnostic(&stdout, &stderr).ends_with(
            "observed_opaque_message_category=PinnedSource, observed_exact_public_refusal=Unknown"
        ));

        // Exercise the disclosure boundary with complete public messages and hostile framing.
        // No output bytes or arbitrary suffix can become part of the rendered diagnostic.
        let check_exact = |stdout_bytes: Vec<u8>,
                           stdout_truncated: bool,
                           stderr_bytes: Vec<u8>,
                           stderr_truncated: bool,
                           expected: &str| {
            let stdout =
                CapturedBytes::from_bytes_with_truncation_for_test(stdout_bytes, stdout_truncated);
            let stderr =
                CapturedBytes::from_bytes_with_truncation_for_test(stderr_bytes, stderr_truncated);
            let rendered = offline_check_failure_diagnostic(&stdout, &stderr);
            assert_eq!(
                rendered,
                format!(
                    "managed Cursor offline check captured-output diagnostic: retained_stdout_bytes={}, retained_stderr_bytes={}, observed_opaque_message_category=Unknown, observed_exact_public_refusal={expected}",
                    stdout.as_bytes().len(),
                    stderr.as_bytes().len(),
                )
            );
            if expected == "Unknown" {
                assert_eq!(
                    rendered,
                    offline_check_failure_diagnostic(
                        &CapturedBytes::from_bytes_for_test(vec![b'x'; stdout.as_bytes().len()]),
                        &CapturedBytes::from_bytes_for_test(vec![b'y'; stderr.as_bytes().len()]),
                    )
                );
            }
        };
        check_exact(Vec::new(), false, Vec::new(), false, "Unknown");
        let refusals: [(&[u8], &str); 2] = [
            (
                b"Error: main helper manifest bytes did not match its declaration\n",
                "ManifestDigestRefusal",
            ),
            (
                b"Error: fixed helper path was not owner-controlled and immutable\n",
                "ProtectedPathRefusal",
            ),
        ];
        for (refusal, expected) in refusals {
            check_exact(Vec::new(), false, refusal.to_vec(), false, expected);
            check_exact(secret.to_vec(), false, refusal.to_vec(), false, "Unknown");
            check_exact(refusal.to_vec(), false, Vec::new(), false, "Unknown");
            check_exact(Vec::new(), true, refusal.to_vec(), false, "Unknown");
            check_exact(Vec::new(), false, refusal.to_vec(), true, "Unknown");
            for framed in [
                [secret.as_slice(), refusal].concat(),
                [refusal, secret.as_slice()].concat(),
                [secret.as_slice(), refusal, secret.as_slice()].concat(),
                [refusal, b"extra line\n".as_slice()].concat(),
                [refusal, b"\xff".as_slice()].concat(),
                [refusal, refusal].concat(),
                [refusals[0].0, refusals[1].0].concat(),
                vec![b'z'; refusal.len()],
            ] {
                check_exact(Vec::new(), false, framed, false, "Unknown");
            }
        }

        // Exercise the actual helper's pure role/message producer and the strict consumer.
        // These synthetic path inputs are never opened or executed, and never appear in output.
        use crate::pinned_exec::ProtectedHelperComponentRole::*;
        let components = [
            (FilesystemRoot, "FilesystemRoot", "/"),
            (NixRoot, "NixRoot", "/nix"),
            (
                PackageRoot,
                "PackageRoot",
                "/nix/store/synthetic-private-package",
            ),
            (
                PackageBin,
                "PackageBin",
                "/nix/store/synthetic-private-package/bin",
            ),
            (
                PackageExecutable,
                "PackageExecutable",
                "/nix/store/synthetic-private-package/bin/maco",
            ),
            (
                PackageShare,
                "PackageShare",
                "/nix/store/synthetic-private-package/share",
            ),
            (
                PackageMetadataDirectory,
                "PackageMetadataDirectory",
                "/nix/store/synthetic-private-package/share/maco",
            ),
        ];
        for (component, label, path) in components {
            for symlink in [false, true] {
                for owner_mismatch in [false, true] {
                    for writable in [false, true] {
                        let message =
                            crate::pinned_exec::protected_helper_component_refusal_message_for_test(
                                Path::new(path),
                                symlink,
                                owner_mismatch,
                                writable,
                            );
                        assert_eq!(message, format!(
                            "fixed helper path was not owner-controlled and immutable; component={label}; symlink={}; owner_mismatch={}; writable={}",
                            u8::from(symlink), u8::from(owner_mismatch), u8::from(writable),
                        ));
                        let refusal = format!("Error: {message}\n").into_bytes();
                        if !symlink && !owner_mismatch && !writable {
                            check_exact(Vec::new(), false, refusal, false, "Unknown");
                            continue;
                        }
                        let expected = format!(
                            "{:?}",
                            OfflineCheckObservedExactRefusal::ProtectedComponentRefusal {
                                component,
                                symlink,
                                owner_mismatch,
                                writable,
                            }
                        );
                        check_exact(Vec::new(), false, refusal.clone(), false, &expected);
                        check_exact(secret.to_vec(), false, refusal.clone(), false, "Unknown");
                        check_exact(refusal.clone(), false, Vec::new(), false, "Unknown");
                        check_exact(Vec::new(), true, refusal.clone(), false, "Unknown");
                        check_exact(Vec::new(), false, refusal.clone(), true, "Unknown");
                        for framed in [
                            [secret.as_slice(), refusal.as_slice()].concat(),
                            [refusal.as_slice(), secret.as_slice()].concat(),
                            [secret.as_slice(), refusal.as_slice(), secret.as_slice()].concat(),
                            [refusal.as_slice(), b"extra line\n"].concat(),
                            [refusal.as_slice(), b"\xff"].concat(),
                            [refusal.as_slice(), refusal.as_slice()].concat(),
                            [refusal.as_slice(), refusals[1].0].concat(),
                            vec![b'z'; refusal.len()],
                        ] {
                            check_exact(Vec::new(), false, framed, false, "Unknown");
                        }
                    }
                }
            }
        }
        for path in [
            "/nix/store",
            "/nix/store-other/synthetic-private-package/bin/maco",
            "/nix/store/synthetic-private-package/nested/bin/maco",
            "/nix/store/synthetic-private-package/./bin/maco",
            "/synthetic-private-path",
            "relative-private-path",
        ] {
            let message = crate::pinned_exec::protected_helper_component_refusal_message_for_test(
                Path::new(path),
                false,
                true,
                false,
            );
            assert_eq!(
                message,
                "fixed helper path was not owner-controlled and immutable"
            );
            check_exact(
                Vec::new(),
                false,
                format!("Error: {message}\n").into_bytes(),
                false,
                "ProtectedPathRefusal",
            );
        }
        for invalid in [
            b"Error: fixed helper path was not owner-controlled and immutable; component=PrivateRole; symlink=0; owner_mismatch=1; writable=0\n".as_slice(),
            b"Error: fixed helper path was not owner-controlled and immutable; component=NixRoot; symlink=2; owner_mismatch=0; writable=0\n".as_slice(),
            b"Error: fixed helper path was not owner-controlled and immutable; component=NixRoot; symlink=0; owner_mismatch=1; writable=0; private=suffix\n".as_slice(),
            b"Error: fixed helper path was not owner-controlled and immutable; component=NixRoot; symlink=0; owner_mismatch=1; writable=0".as_slice(),
        ] {
            check_exact(Vec::new(), false, invalid.to_vec(), false, "Unknown");
        }
    }

    fn test_budget() -> OperationBudget {
        OperationBudget {
            cancellation: ProcessCancellation::new(),
            deadline: Instant::now() + Duration::from_secs(30),
        }
    }

    #[test]
    fn assignment_authority_admits_exact_write_read_and_parent_owned_check() -> Result<()> {
        let temp = tempfile::tempdir()?;
        git2::Repository::init(temp.path())?;
        fs::write(temp.path().join("assigned.txt"), "before\n")?;
        let mut authority = CursorManagedAssignmentAuthority::new(
            temp.path(),
            vec![PathBuf::from("assigned.txt")],
        )?;
        // This check requires the same genuine package as the installed gate.
        // Missing qualification input is a failure, never a skip or stub.
        authority.bind_main_helper_git(
            SourceBoundMainHelper::capture_qualification_environment()?,
            &test_budget(),
        )?;
        let mut state = SharedState {
            authority: Some(authority),
            ..SharedState::default()
        };
        let authorize = authorize_resource_action(
            &json!({
                "kind": "filesystemWrite",
                "arguments": {"path": "assigned.txt", "text": "after\n"}
            }),
            &mut state,
        )?;
        let action_id = authorize
            .get("actionId")
            .and_then(Value::as_str)
            .context("write action id")?;
        let written = execute_resource_action(
            &json!({
                "kind": "filesystemWrite",
                "actionId": action_id,
                "arguments": {"path": "assigned.txt", "text": "after\n"},
                "cancelled": false
            }),
            &mut state,
            &test_budget(),
        )?;
        assert_eq!(written.pointer("/result/fileSize"), Some(&Value::from(6)));
        assert_eq!(
            fs::read_to_string(temp.path().join("assigned.txt"))?,
            "after\n"
        );

        let check = authorize_resource_action(
            &json!({
                "kind": "offlineCheck",
                "arguments": {
                    "check": "assignedPathsChangedOnlyUtf8",
                    "workingDirectory": temp.path()
                }
            }),
            &mut state,
        )?;
        let check_id = check
            .get("actionId")
            .and_then(Value::as_str)
            .context("check action id")?;
        let checked = execute_resource_action(
            &json!({
                "kind": "offlineCheck",
                "actionId": check_id,
                "arguments": {
                    "check": "assignedPathsChangedOnlyUtf8",
                    "workingDirectory": temp.path()
                },
                "cancelled": false
            }),
            &mut state,
            &test_budget(),
        )?;
        assert_eq!(
            checked.pointer("/result/command"),
            Some(&Value::from(
                "maco-offline-check assigned-paths-changed-only-utf8"
            ))
        );
        assert_eq!(state.evidence.filesystem_writes, 1);
        assert_eq!(state.evidence.offline_checks, 1);
        assert!(state.pending_actions.is_empty());
        Ok(())
    }

    #[test]
    fn assignment_authority_refuses_outside_and_unacknowledged_actions() -> Result<()> {
        let temp = tempfile::tempdir()?;
        git2::Repository::init(temp.path())?;
        let authority = CursorManagedAssignmentAuthority::new(
            temp.path(),
            vec![PathBuf::from("assigned.txt")],
        )?;
        let mut state = SharedState {
            authority: Some(authority),
            ..SharedState::default()
        };
        assert!(authorize_resource_action(
            &json!({
                "kind": "filesystemWrite",
                "arguments": {"path": "outside.txt", "text": "denied"}
            }),
            &mut state,
        )
        .is_err());
        assert!(execute_resource_action(
            &json!({
                "kind": "filesystemWrite",
                "actionId": "cursor-action-missing",
                "arguments": {"path": "assigned.txt", "text": "denied"},
                "cancelled": false
            }),
            &mut state,
            &test_budget(),
        )
        .is_err());
        let cancelled = authorize_resource_action(
            &json!({
                "kind": "filesystemWrite",
                "arguments": {"path": "assigned.txt", "text": "denied"}
            }),
            &mut state,
        )?;
        let cancelled_id = cancelled
            .get("actionId")
            .and_then(Value::as_str)
            .context("cancelled action id")?;
        execute_resource_action(
            &json!({
                "kind": "filesystemWrite",
                "actionId": cancelled_id,
                "arguments": {"path": "assigned.txt", "text": "denied"},
                "cancelled": true
            }),
            &mut state,
            &test_budget(),
        )?;
        let expired = authorize_resource_action(
            &json!({
                "kind": "filesystemWrite",
                "arguments": {"path": "assigned.txt", "text": "expired"}
            }),
            &mut state,
        )?;
        let expired_id = expired
            .get("actionId")
            .and_then(Value::as_str)
            .context("expired action id")?;
        assert!(execute_resource_action(
            &json!({
                "kind": "filesystemWrite",
                "actionId": expired_id,
                "arguments": {"path": "assigned.txt", "text": "expired"},
                "cancelled": false
            }),
            &mut state,
            &OperationBudget {
                cancellation: ProcessCancellation::new(),
                deadline: Instant::now(),
            },
        )
        .is_err());
        assert!(!temp.path().join("outside.txt").exists());
        assert!(!temp.path().join("assigned.txt").exists());
        assert!(state.pending_actions.is_empty());
        Ok(())
    }

    #[test]
    fn assignment_authority_refuses_symlink_ancestor_hardlink_and_fifo() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let outside = tempfile::tempdir()?;
        fs::write(outside.path().join("target.txt"), "outside\n")?;
        std::os::unix::fs::symlink(outside.path(), temp.path().join("linked"))?;
        let workspace_alias = outside.path().join("workspace-alias");
        std::os::unix::fs::symlink(temp.path(), &workspace_alias)?;
        fs::write(temp.path().join("hard.txt"), "held\n")?;
        fs::hard_link(
            temp.path().join("hard.txt"),
            outside.path().join("alias.txt"),
        )?;
        let fifo = temp.path().join("fifo.txt");
        let fifo_c = CString::new(fifo.as_os_str().as_bytes())?;
        // SAFETY: fifo_c is a valid NUL-terminated path.
        if unsafe { libc::mkfifo(fifo_c.as_ptr(), 0o600) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let authority = CursorManagedAssignmentAuthority::new(
            temp.path(),
            vec![
                PathBuf::from("linked/target.txt"),
                PathBuf::from("hard.txt"),
                PathBuf::from("fifo.txt"),
            ],
        )?;
        assert!(authority
            .write(&json!({"path": "linked/target.txt", "text": "denied"}))
            .is_err());
        assert!(authority
            .write(&json!({"path": "hard.txt", "text": "denied"}))
            .is_err());
        assert!(authority.read(&json!({"path": "fifo.txt"})).is_err());
        assert!(authority
            .write(&json!({"path": "fifo.txt", "text": "denied"}))
            .is_err());
        assert!(authority
            .offline_check(
                &json!({
                    "check": "assignedPathsChangedOnlyUtf8",
                    "workingDirectory": workspace_alias
                }),
                &test_budget()
            )
            .is_err());
        assert_eq!(
            fs::read_to_string(outside.path().join("target.txt"))?,
            "outside\n"
        );
        assert_eq!(fs::read_to_string(temp.path().join("hard.txt"))?, "held\n");
        Ok(())
    }

    #[test]
    fn usage_requires_exact_nested_shape_four_buckets_and_attempt_coverage() -> Result<()> {
        let mut state = SharedState::default();
        admit_rpc_attempt("cursor-rpc-1", &mut state)?;
        capture_raw_event(
            "cursor-rpc-1",
            &json!({
                "attemptId": "cursor-rpc-1",
                "raw": {"message": {
                    "case": "interactionUpdate",
                    "value": {"message": {"case": "turnEnded", "value": {
                        "inputTokens": {"$macoInt": "7"},
                        "outputTokens": {"$macoInt": "3"},
                        "cacheReadTokens": {"$macoInt": "2"},
                        "cacheWriteTokens": {"$macoInt": "1"}
                    }}}
                }}
            }),
            &mut state,
        )?;
        complete_rpc_attempt(
            "cursor-rpc-1",
            &json!({"attemptId": "cursor-rpc-1", "outcome": "eof"}),
            &mut state,
        )?;
        assert_eq!(state.evidence.input_tokens, Some(7));
        assert_eq!(state.evidence.output_tokens, Some(3));
        assert_eq!(state.evidence.cache_read_tokens, Some(2));
        assert_eq!(state.evidence.cache_write_tokens, Some(1));
        assert_eq!(state.evidence.usage_attempts_covered, 1);
        assert_eq!(state.evidence.usage_is_incomplete, Some(false));

        admit_rpc_attempt("cursor-rpc-2", &mut state)?;
        capture_raw_event(
            "cursor-rpc-2",
            &json!({"attemptId": "cursor-rpc-2", "raw": {"message": {
                "case": "interactionUpdate",
                "value": {"message": {"case": "turnEnded", "value": {
                    "inputTokens": 1, "outputTokens": 1
                }}}
            }}}),
            &mut state,
        )?;
        complete_rpc_attempt(
            "cursor-rpc-2",
            &json!({"attemptId": "cursor-rpc-2", "outcome": "eof"}),
            &mut state,
        )?;
        assert_eq!(state.evidence.usage_attempts_incomplete, 1);
        assert_eq!(state.evidence.usage_is_incomplete, Some(true));
        assert_eq!(state.evidence.input_tokens, Some(8));
        assert_eq!(state.evidence.output_tokens, Some(4));
        assert_eq!(state.evidence.cache_read_tokens, Some(2));
        assert_eq!(state.evidence.cache_write_tokens, Some(1));
        assert!(state.evidence.usd.is_none());
        assert!(admit_rpc_attempt("cursor-rpc-1", &mut state).is_err());

        let mut divergent = SharedState::default();
        admit_rpc_attempt("cursor-rpc-1", &mut divergent)?;
        for input in [7, 8] {
            capture_raw_event(
                "cursor-rpc-1",
                &json!({"attemptId": "cursor-rpc-1", "raw": {"message": {
                    "case": "interactionUpdate",
                    "value": {"message": {"case": "turnEnded", "value": {
                        "inputTokens": input,
                        "outputTokens": 3,
                        "cacheReadTokens": 2,
                        "cacheWriteTokens": 1
                    }}}
                }}}),
                &mut divergent,
            )?;
        }
        complete_rpc_attempt(
            "cursor-rpc-1",
            &json!({"attemptId": "cursor-rpc-1", "outcome": "eof"}),
            &mut divergent,
        )?;
        assert_eq!(divergent.evidence.input_tokens, Some(8));
        assert_eq!(divergent.evidence.output_tokens, Some(3));
        assert_eq!(divergent.evidence.cache_read_tokens, Some(2));
        assert_eq!(divergent.evidence.cache_write_tokens, Some(1));
        assert_eq!(divergent.evidence.usage_attempts_covered, 0);
        assert_eq!(divergent.evidence.usage_attempts_incomplete, 1);
        assert_eq!(divergent.evidence.usage_is_incomplete, Some(true));
        assert!(divergent.evidence.usd.is_none());
        Ok(())
    }

    #[test]
    fn peer_identity_rejects_sibling_cgroup_and_reused_pid() {
        assert_eq!(
            expected_cgroup_record(Path::new(
                "/sys/fs/cgroup/user.slice/app.slice/maco.service"
            ))
            .unwrap(),
            "/user.slice/app.slice/maco.service"
        );
        assert!(expected_cgroup_record(Path::new("/user.slice/app.slice/maco.service")).is_err());
        let expected = PeerIdentity {
            pid: 41,
            start_time: "boot:100".to_string(),
            cgroup_path: "/user.slice/app.slice/maco.service".to_string(),
        };
        assert!(peer_identity_matches(
            41,
            "boot:100",
            "/user.slice/app.slice/maco.service",
            &expected,
        ));
        assert!(!peer_identity_matches(
            42,
            "boot:100",
            "/user.slice/app.slice/maco.service",
            &expected,
        ));
        assert!(!peer_identity_matches(
            41,
            "boot:100",
            "/user.slice/app.slice/maco.service-sibling",
            &expected,
        ));
        assert!(!peer_identity_matches(
            41,
            "boot:101",
            "/user.slice/app.slice/maco.service",
            &expected,
        ));
    }

    #[test]
    fn parent_finish_joins_cleanup_owner_and_removes_socket_before_return() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let socket_path = temp.path().join("parent.sock");
        fs::write(&socket_path, b"fixture")?;
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let joined = Arc::new(AtomicBool::new(false));
        let thread_joined = Arc::clone(&joined);
        let (finished_tx, finished_rx) = mpsc::channel();
        let thread = thread::spawn(move || {
            while !thread_stop.load(Ordering::Acquire) {
                thread::sleep(Duration::from_millis(1));
            }
            thread_joined.store(true, Ordering::Release);
            let _ = finished_tx.send(());
        });
        let parent = CursorManagedParent {
            socket_path: socket_path.clone(),
            stop,
            state: Arc::new(Mutex::new(SharedState::default())),
            thread: Some(thread),
            finished: Some(finished_rx),
            budget: OperationBudget {
                cancellation: ProcessCancellation::new(),
                deadline: Instant::now() + Duration::from_secs(1),
            },
            active_stream: Arc::new(Mutex::new(None)),
        };
        parent.finish()?;
        assert!(joined.load(Ordering::Acquire));
        assert!(!socket_path.exists());
        Ok(())
    }

    #[test]
    fn disconnected_parent_completion_joins_owner_and_removes_socket_before_return() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let socket_path = temp.path().join("parent.sock");
        fs::write(&socket_path, b"fixture")?;
        let joined = Arc::new(AtomicBool::new(false));
        let thread_joined = Arc::clone(&joined);
        let (finished_tx, finished_rx) = mpsc::channel::<()>();
        let thread = thread::spawn(move || {
            drop(finished_tx);
            thread_joined.store(true, Ordering::Release);
        });
        let parent = CursorManagedParent {
            socket_path: socket_path.clone(),
            stop: Arc::new(AtomicBool::new(false)),
            state: Arc::new(Mutex::new(SharedState::default())),
            thread: Some(thread),
            finished: Some(finished_rx),
            budget: OperationBudget {
                cancellation: ProcessCancellation::new(),
                deadline: Instant::now() + Duration::from_secs(1),
            },
            active_stream: Arc::new(Mutex::new(None)),
        };
        parent.finish()?;
        assert!(joined.load(Ordering::Acquire));
        assert!(!socket_path.exists());
        Ok(())
    }

    #[test]
    fn timed_out_parent_cleanup_aborts_before_assignment_custody_can_return() -> Result<()> {
        const CHILD: &str = "MACO_CURSOR_STUCK_PARENT_TEST_CHILD";
        const RELEASE_MARKER: &str = "MACO_CURSOR_STUCK_PARENT_RELEASE_MARKER";
        if std::env::var_os(CHILD).is_some() {
            let temp = tempfile::tempdir()?;
            let (_release_tx, release_rx) = mpsc::channel::<()>();
            let (finished_tx, finished_rx) = mpsc::channel();
            let thread = thread::spawn(move || {
                let _ = release_rx.recv();
                let _ = finished_tx.send(());
            });
            let parent = CursorManagedParent {
                socket_path: temp.path().join("parent.sock"),
                stop: Arc::new(AtomicBool::new(false)),
                state: Arc::new(Mutex::new(SharedState::default())),
                thread: Some(thread),
                finished: Some(finished_rx),
                budget: OperationBudget {
                    cancellation: ProcessCancellation::new(),
                    deadline: Instant::now(),
                },
                active_stream: Arc::new(Mutex::new(None)),
            };
            let _ = parent.finish();
            fs::write(
                std::env::var_os(RELEASE_MARKER)
                    .context("stuck-parent release marker was not supplied")?,
                b"ordinary report and lease release became reachable",
            )?;
            bail!("stuck managed Cursor parent returned instead of aborting");
        }

        let temp = tempfile::tempdir()?;
        let release_marker = temp.path().join("released");
        let output = std::process::Command::new(std::env::current_exe()?)
            .arg("--exact")
            .arg("runtime_adapter::cursor_managed_parent::tests::timed_out_parent_cleanup_aborts_before_assignment_custody_can_return")
            .arg("--nocapture")
            .env(CHILD, "1")
            .env(RELEASE_MARKER, &release_marker)
            .output()?;
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr)
            .contains("aborting rather than releasing assignment custody"));
        assert!(!release_marker.exists());
        Ok(())
    }
}
