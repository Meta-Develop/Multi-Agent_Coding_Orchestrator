use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    ffi::{OsStr, OsString},
    fmt,
    fs::{self, File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    num::NonZeroUsize,
    path::{Path, PathBuf},
    process::{Child, ChildStderr, ChildStdin, ChildStdout, Command, ExitStatus, Stdio},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc::{self, Receiver, SyncSender, TryRecvError, TrySendError},
        Arc,
    },
    thread,
    time::{Duration, Instant},
};
use thiserror::Error;

use crate::{
    agent_lifecycle::{AgentLaunchMetadata, AgentRegistry, MACO_RUN_ID_ENV, MACO_TASK_ID_ENV},
    external_agent::EnvironmentFailure,
    pinned_exec::{
        self, PinnedDirectExecutable, HIDDEN_PINNED_EXEC_ARGUMENT, PINNED_EXEC_DESCRIPTOR_NAME,
    },
};

const PIPE_READ_CHUNK_SIZE: usize = 8 * 1024;
const PIPE_CHANNEL_CAPACITY: usize = 8;
const MAX_PIPE_EVENTS_PER_POLL: usize = PIPE_CHANNEL_CAPACITY * 2;
const DEFAULT_MAX_STDIN_BYTES: usize = 8 * 1024 * 1024;
const DEFAULT_MAX_TEE_BYTES: usize = 8 * 1024 * 1024;
const MAX_REQUIRED_STREAM_BYTES: usize = 64 * 1024 * 1024;
const MAX_PROCESS_ARGUMENTS: usize = 2048;
const MAX_PROCESS_ARGUMENT_BYTES: usize = 64 * 1024;
const MAX_PROCESS_ARGUMENT_TOTAL_BYTES: usize = 2 * 1024 * 1024;
const MAX_PROCESS_ENVIRONMENT_ENTRIES: usize = 256;
const MAX_PROCESS_ENVIRONMENT_KEY_BYTES: usize = 256;
const MAX_PROCESS_ENVIRONMENT_VALUE_BYTES: usize = 1024 * 1024;
const MAX_PROCESS_ENVIRONMENT_TOTAL_BYTES: usize = 4 * 1024 * 1024;
const MAX_PROCESS_LABEL_BYTES: usize = 4096;
const MAX_SHELL_COMMAND_BYTES: usize = 1024 * 1024;
const MAX_SANDBOX_PATHS_PER_CLASS: usize = 128;
const MAX_SANDBOX_TOTAL_PATHS: usize = 512;
const MAX_SANDBOX_PATH_BYTES: usize = 4096;
const MAX_SANDBOX_MOUNT_CHECKS: usize = 768;
#[cfg(target_os = "linux")]
const MAX_PRIVATE_RUNTIME_FILE_BYTES: usize = 1024 * 1024;
#[cfg(target_os = "linux")]
const MAX_PRIVATE_RUNTIME_FILES: usize = 32;
#[cfg(target_os = "linux")]
const MAX_SANDBOX_ENTRY_SCAN: usize = 200_000;
#[cfg(target_os = "linux")]
const MAX_SANDBOX_MOUNTINFO_BYTES: usize = 4 * 1024 * 1024;
#[cfg(target_os = "linux")]
const MAX_SANDBOX_MOUNTINFO_ENTRIES: usize = 65_536;
#[cfg(target_os = "linux")]
const MAX_SANDBOX_MOUNTINFO_LINE_BYTES: usize = 64 * 1024;
const POLL_INTERVAL: Duration = Duration::from_millis(10);
const THREAD_JOIN_GRACE: Duration = Duration::from_millis(500);
const IO_CANCEL_POLL_INTERVAL: Duration = Duration::from_millis(1);
#[cfg(unix)]
const TERMINATE_GRACE: Duration = Duration::from_millis(100);
const EXIT_AND_DRAIN_GRACE: Duration = Duration::from_millis(500);
#[cfg(target_os = "linux")]
const SYSTEMD_OPERATION_GRACE: Duration = Duration::from_secs(3);
#[cfg(target_os = "linux")]
const SYSTEMD_SLOT_WAIT: Duration = Duration::from_secs(30);
// Keep both supervise admission and strict containment deterministic in the unit-test binary.
// Slot zero remains reserved, so three child lanes produce four total systemd unit slots.
#[cfg(test)]
const TEST_HOST_PROCESS_PARALLELISM: usize = 3;
// These safety probes assert containment evidence rather than command latency. Allow the complete
// bounded slot wait plus setup without changing any production deadline.
#[cfg(all(target_os = "linux", test))]
const CONTENTION_RESILIENT_PROCESS_TEST_TIMEOUT: Duration = Duration::from_secs(40);
#[cfg(target_os = "linux")]
const EXPEDITED_SYSTEMD_SLOT_THRESHOLD: Duration = Duration::from_secs(1);
#[cfg(target_os = "linux")]
const RESERVED_EXPEDITED_SYSTEMD_SLOTS: usize = 1;
#[cfg(target_os = "linux")]
const SYSTEMD_RUNTIME_OVERHEAD: Duration = Duration::from_secs(30);
#[cfg(target_os = "linux")]
const SYSTEMD_ORPHAN_SAFETY_FUSE: Duration = Duration::from_secs(24 * 60 * 60);

/// Cgroup-aware process capacity shared by supervise admission and strict containment.
///
/// Production uses `available_parallelism`, which reflects the runtime's effective CPU
/// quota/affinity where the standard library can observe it. A failed production measurement
/// degrades to one usable lane instead of removing the containment bound. Unit tests pin the
/// shared capacity so both supervise admission and strict containment have deterministic width.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct HostProcessCapacity {
    parallelism: NonZeroUsize,
}

impl HostProcessCapacity {
    #[cfg(not(test))]
    pub(crate) fn measured() -> Self {
        Self::from_measurement(thread::available_parallelism())
    }

    #[cfg(test)]
    pub(crate) fn measured() -> Self {
        let parallelism = match NonZeroUsize::new(TEST_HOST_PROCESS_PARALLELISM) {
            Some(parallelism) => parallelism,
            None => NonZeroUsize::MIN,
        };
        Self { parallelism }
    }

    fn from_measurement(measurement: io::Result<NonZeroUsize>) -> Self {
        let parallelism = match measurement {
            Ok(parallelism) => parallelism,
            Err(_) => NonZeroUsize::MIN,
        };
        Self { parallelism }
    }

    #[cfg(test)]
    pub(crate) const fn from_parallelism(parallelism: NonZeroUsize) -> Self {
        Self { parallelism }
    }

    pub(crate) const fn supervisor_children(self) -> usize {
        self.parallelism.get()
    }

    #[cfg(target_os = "linux")]
    const fn systemd_unit_slots(self) -> usize {
        // Slot zero is reserved for expedited operations. Adding that control slot leaves the
        // complete measured capacity available to ordinary contained children.
        self.parallelism
            .get()
            .saturating_add(RESERVED_EXPEDITED_SYSTEMD_SLOTS)
    }
}

/// A run-scoped cancellation signal for independently contained child processes.
///
/// Clones observe the same state. Cancellation is cooperative at setup boundaries and in the
/// process poll loop; once a child has started, its own containment backend remains responsible
/// for terminating and proving its process tree empty.
#[derive(Debug, Clone, Default)]
pub struct ProcessCancellation {
    requested: Arc<AtomicBool>,
}

impl ProcessCancellation {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn cancel(&self) {
        self.requested.store(true, Ordering::Release);
    }

    pub fn is_cancelled(&self) -> bool {
        self.requested.load(Ordering::Acquire)
    }
}
#[cfg(target_os = "linux")]
const SYSTEMD_SANDBOX_SHOW_PROPERTIES: &[&str] = &[
    "ProtectSystem",
    "ProtectHome",
    "NoNewPrivileges",
    "RestrictSUIDSGID",
    "LockPersonality",
    "PrivateTmp",
    "PrivateDevices",
    "PrivateNetwork",
    "PrivateIPC",
    "ProtectKernelTunables",
    "ProtectKernelModules",
    "ProtectKernelLogs",
    "ProtectClock",
    "ProtectControlGroups",
    "ProtectProc",
    "ProcSubset",
    "SystemCallArchitectures",
    "SystemCallFilter",
    "SystemCallErrorNumber",
    "CapabilityBoundingSet",
    "AmbientCapabilities",
    "RestrictRealtime",
    "RestrictNamespaces",
    "KeyringMode",
    "UMask",
    "RestrictAddressFamilies",
    "MemoryMax",
    "MemorySwapMax",
    "TasksMax",
    "CPUQuotaPerSecUSec",
    "LimitNOFILE",
    "LimitCORE",
    "LimitFSIZE",
    "OOMPolicy",
    "ReadOnlyPaths",
    "ReadWritePaths",
    "BindReadOnlyPaths",
    "BindPaths",
    "InaccessiblePaths",
    "TemporaryFileSystem",
];
#[cfg(target_os = "linux")]
const SYSTEMD_GUARDIAN_SCRIPT: &str = r#"
environment_file=$1
shift
ready=$1
shift
waiting=$1
shift
environment_fifo=$1
shift
start_fifo=$1
shift
target_pid_file=$1
shift
owner_fifo=$1
shift
fifo_waiting=$1
shift
sleep_program=$1
shift
sandbox_report=$1
shift
stat_program=$1
shift
findmnt_program=$1
shift
env_program=$1
shift
target_environment_mode=$1
shift
sandbox_check_count=$1
shift

child_running() {
    child_stat=
    [ -r "/proc/$1/stat" ] || return 1
    { IFS= read -r child_stat < "/proc/$1/stat"; } 2>/dev/null || return 1
    child_fields=${child_stat##*) }
    set -- $child_fields
    [ "$#" -ge 1 ] || return 1
    [ "$1" != Z ] && [ "$1" != X ]
}

fail_guardian() {
    printf 'maco containment guardian: %s\n' "$1" >&2
    exit 125
}

case "$target_environment_mode" in
    source|descriptor) ;;
    *) fail_guardian "invalid target environment mode" ;;
esac

guardian=$$
umask 077
: > "$fifo_waiting" || fail_guardian "could not publish FIFO-wait marker"
fifo_wait_count=0
while [ ! -p "$environment_fifo" ] || [ ! -p "$start_fifo" ] || [ ! -p "$owner_fifo" ]; do
    fifo_wait_count=$((fifo_wait_count + 1))
    [ "$fifo_wait_count" -le 300 ] || fail_guardian "runner did not publish gate FIFOs"
    "$sleep_program" 0.01 || fail_guardian "FIFO wait sleep failed"
done
exec 3<"$owner_fifo" || fail_guardian "could not open owner-liveness FIFO"
(
    IFS= read -r _ <&3
    kill -KILL "$guardian"
) &
: > "$sandbox_report" || fail_guardian "could not create sandbox report"
[ -c /dev/null ] || fail_guardian "private /dev/null was unavailable"
cap_inh=missing
cap_prm=missing
cap_eff=missing
cap_amb=missing
no_new_privs=missing
seccomp=missing
while IFS= read -r status_line; do
    case "$status_line" in
        CapInh:*0000000000000000) cap_inh=0000000000000000 ;;
        CapPrm:*0000000000000000) cap_prm=0000000000000000 ;;
        CapEff:*0000000000000000) cap_eff=0000000000000000 ;;
        CapAmb:*0000000000000000) cap_amb=0000000000000000 ;;
        NoNewPrivs:*1) no_new_privs=1 ;;
        Seccomp:*2) seccomp=2 ;;
    esac
done < /proc/self/status
[ "$cap_inh" = 0000000000000000 ] || fail_guardian "inheritable capabilities remained enabled"
[ "$cap_prm" = 0000000000000000 ] || fail_guardian "permitted capabilities remained enabled"
[ "$cap_eff" = 0000000000000000 ] || fail_guardian "effective capabilities remained enabled"
[ "$cap_amb" = 0000000000000000 ] || fail_guardian "ambient capabilities remained enabled"
[ "$no_new_privs" = 1 ] || fail_guardian "NoNewPrivileges was not active"
[ "$seccomp" = 2 ] || fail_guardian "seccomp filter mode was not active"
printf 'security %s %s %s %s %s %s\n' "$cap_inh" "$cap_prm" "$cap_eff" "$cap_amb" "$no_new_privs" "$seccomp" >> "$sandbox_report" || fail_guardian "could not write security report"
while [ "$sandbox_check_count" -gt 0 ]; do
    sandbox_mode=$1
    sandbox_path=$2
    shift 2
    if [ "$sandbox_mode" = isolated-root ]; then
        isolated_root=$(
            "$findmnt_program" --raw --noheadings --output SOURCE,FSTYPE,VFS-OPTIONS --mountpoint "$sandbox_path"
        ) || fail_guardian "could not inspect isolated root mount"
        isolated_source=${isolated_root%% *}
        isolated_rest=${isolated_root#* }
        isolated_fstype=${isolated_rest%% *}
        isolated_options=${isolated_rest#* }
        [ "$isolated_source" != "$isolated_root" ] || fail_guardian "isolated root mount report was malformed"
        [ "$isolated_fstype" != "$isolated_rest" ] || fail_guardian "isolated root mount report was malformed"
        [ "$isolated_fstype" = tmpfs ] || fail_guardian "isolated root was not backed by tmpfs"
        isolated_read_only=false
        for isolated_option_line in $isolated_options; do
            case ",$isolated_option_line," in
                *,ro,*) isolated_read_only=true ;;
            esac
        done
        [ "$isolated_read_only" = true ] || fail_guardian "isolated root was not read-only"
        printf 'isolated-root %s %s %s\n' "$isolated_source" "$isolated_fstype" "$isolated_options" >> "$sandbox_report" || fail_guardian "could not write isolated-root report"
        sandbox_check_count=$((sandbox_check_count - 1))
        continue
    fi
    if [ "$sandbox_mode" = inaccessible-required ] || [ "$sandbox_mode" = inaccessible-optional ]; then
        if "$stat_program" -L -c '%d %i' -- "$sandbox_path" >/dev/null 2>&1; then
            inaccessible_source=$("$findmnt_program" --raw --noheadings --output SOURCE --mountpoint "$sandbox_path") || fail_guardian "could not inspect inaccessible-path source: $sandbox_path"
            inaccessible_options=$("$findmnt_program" --raw --noheadings --output VFS-OPTIONS --mountpoint "$sandbox_path") || fail_guardian "could not inspect inaccessible-path mount options: $sandbox_path"
            inaccessible_mode=$("$stat_program" -L -c '%a' -- "$sandbox_path") || fail_guardian "could not inspect inaccessible-path mode: $sandbox_path"
            case "$inaccessible_source" in
                *'[/systemd/inaccessible/'*']') ;;
                *) fail_guardian "inaccessible path remained on a non-systemd mount: $sandbox_path" ;;
            esac
            [ "$inaccessible_mode" = 0 ] || fail_guardian "inaccessible path placeholder was not mode 000: $sandbox_path"
            inaccessible_read_only=false
            for inaccessible_option_line in $inaccessible_options; do
                case ",$inaccessible_option_line," in
                    *,ro,*) inaccessible_read_only=true ;;
                esac
            done
            [ "$inaccessible_read_only" = true ] || fail_guardian "inaccessible path placeholder was not read-only: $sandbox_path"
            printf 'inaccessible\n' >> "$sandbox_report" || fail_guardian "could not write inaccessible-path report"
        else
            [ "$sandbox_mode" = inaccessible-optional ] || fail_guardian "required inaccessible path was not mounted: $sandbox_path"
            printf 'inaccessible-missing\n' >> "$sandbox_report" || fail_guardian "could not write optional inaccessible-path report"
        fi
        sandbox_check_count=$((sandbox_check_count - 1))
        continue
    fi
    sandbox_identity=$("$stat_program" -L -c '%d %i' -- "$sandbox_path") || fail_guardian "could not stat sandbox path: $sandbox_path"
    sandbox_options=$("$findmnt_program" --raw --noheadings --output VFS-OPTIONS --target "$sandbox_path") || fail_guardian "could not inspect sandbox mount: $sandbox_path"
    printf 'mounted %s %s\n' "$sandbox_identity" "$sandbox_options" >> "$sandbox_report" || fail_guardian "could not write mount report"
    sandbox_check_count=$((sandbox_check_count - 1))
done
: > "$waiting" || exit 125
IFS= read -r environment_token < "$environment_fifo" || exit 125
[ "$environment_token" = environment ] || exit 125

target_launcher() {
    if [ "$target_environment_mode" = descriptor ]; then
        : > "$2" || exit 125
        IFS= read -r start_token < "$3" || exit 125
        [ "$start_token" = start ] || exit 125
        shift 3
        exec "$env_program" -i "$@" || exit 125
    fi
    set -a
    . "$1" || exit 125
    set +a
    : > "$2" || exit 125
    IFS= read -r start_token < "$3" || exit 125
    [ "$start_token" = start ] || exit 125
    shift 3
    exec "$@"
}
exec 4<&0 || exit 125
target_launcher "$environment_file" "$ready" "$start_fifo" "$@" <&4 &
target=$!
printf '%s\n' "$target" > "$target_pid_file" || fail_guardian "could not publish target PID"
exec 4<&-
while child_running "$target"; do
    "$sleep_program" 0.01 || exit 125
done
wait "$target"
exit $?
"#;
static NEXT_TEE_BACKUP_ID: AtomicU64 = AtomicU64::new(1);
#[cfg(target_os = "linux")]
static NEXT_SYSTEMD_UNIT_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shell {
    UnixSh,
    WindowsCmd,
}

impl Shell {
    pub const fn for_current_platform() -> Self {
        #[cfg(target_os = "windows")]
        {
            Self::WindowsCmd
        }

        #[cfg(not(target_os = "windows"))]
        {
            Self::UnixSh
        }
    }

    fn command(self, command_text: &str) -> Command {
        match self {
            Self::UnixSh => {
                let mut command = Command::new("sh");
                command.arg("-c").arg(command_text);
                command
            }
            Self::WindowsCmd => {
                let mut command = Command::new("cmd");
                command.arg("/C").arg(command_text);
                command
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProcessCommand {
    Shell {
        shell: Shell,
        command: String,
    },
    Direct {
        program: PathBuf,
        args: Vec<OsString>,
    },
}

impl ProcessCommand {
    fn build(&self) -> Command {
        match self {
            Self::Shell { shell, command } => shell.command(command),
            Self::Direct { program, args } => {
                let mut command = Command::new(program);
                command.args(args);
                command
            }
        }
    }

    fn display(&self) -> String {
        match self {
            Self::Shell { shell, command } => match shell {
                Shell::UnixSh => format!("sh -c {command}"),
                Shell::WindowsCmd => format!("cmd /C {command}"),
            },
            Self::Direct { program, args } => {
                let mut parts = Vec::with_capacity(args.len() + 1);
                parts.push(program.display().to_string());
                parts.extend(
                    args.iter()
                        .map(|argument| argument.to_string_lossy().into_owned()),
                );
                parts.join(" ")
            }
        }
    }

    fn lifecycle_argv(&self) -> Vec<String> {
        match self {
            Self::Shell { shell, command } => match shell {
                Shell::UnixSh => {
                    vec!["sh".to_string(), "-c".to_string(), command.clone()]
                }
                Shell::WindowsCmd => {
                    vec!["cmd".to_string(), "/C".to_string(), command.clone()]
                }
            },
            Self::Direct { program, args } => {
                let mut argv = Vec::with_capacity(args.len().saturating_add(1));
                argv.push(program.to_string_lossy().into_owned());
                argv.extend(
                    args.iter()
                        .map(|argument| argument.to_string_lossy().into_owned()),
                );
                argv
            }
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum EnvironmentMode {
    #[default]
    Inherit,
    InheritAndSet(BTreeMap<String, String>),
    ClearAndSet(BTreeMap<String, String>),
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum StdinMode {
    #[default]
    Inherit,
    Null,
    Bytes(Vec<u8>),
    /// Reserve a bounded pipe for [`run_process_interactive`].
    ///
    /// Ordinary batch execution rejects this mode so a caller cannot accidentally leave an
    /// unowned stdin pipe open. The interactive runner keeps the raw handle private and exposes
    /// only a borrowed, deadline-aware line session to its crate-internal handler.
    Interactive,
}

/// Selects the ownership guarantee that must be established before a command executes.
///
/// A required run fails before releasing the requested command when the host cannot provide the
/// backend. Linux requires a trusted user-systemd service manager on cgroup v2; Windows uses
/// suspended creation followed by Job Object assignment. Other Unix platforms currently require
/// the caller to opt into the weaker compatibility policy explicitly. The Linux service also has
/// an orphan-only runtime fuse: the requested timeout plus 30 seconds, or 24 hours when no command
/// timeout is requested. This finite fuse is a last-resort cleanup boundary, not the command
/// timeout reported by [`ProcessOutput::timed_out`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ContainmentPolicy {
    /// Require a backend that places the child before execution and proves the complete subtree
    /// empty before success. Unsupported hosts fail before the requested command is spawned.
    #[default]
    Required,
    /// Explicit compatibility mode for trusted commands. Unix process groups do not contain
    /// descendants that deliberately call `setsid` or move to another process group.
    TrustedBestEffort,
}

/// Identifies the operating-system ownership mechanism used for one run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContainmentBackend {
    SystemdUserService,
    WindowsJobObject,
    UnixProcessGroup,
    DirectChild,
}

/// Records whether the selected backend proved that no owned process remained at return.
///
/// Safety-sensitive callers must accept only [`ProcessTreeEvidence::VerifiedEmpty`]. A successful
/// exit status does not upgrade best-effort or failed verification evidence. This is deliberately
/// separate from [`SideEffectConfinementEvidence`]: an empty cgroup or Job Object does not prove
/// that the command avoided filesystem, socket, or network side effects while it was running.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(tag = "status", content = "backend", rename_all = "snake_case")]
pub enum ProcessTreeEvidence {
    VerifiedEmpty(ContainmentBackend),
    TrustedBestEffort(ContainmentBackend),
    Unverified(ContainmentBackend),
}

impl ProcessTreeEvidence {
    pub const fn is_verified_empty(self) -> bool {
        matches!(self, Self::VerifiedEmpty(_))
    }
}

/// Backwards-compatible name for callers that have not migrated their diagnostics yet.
pub type ContainmentEvidence = ProcessTreeEvidence;

/// Names the side-effect policy that was requested for a process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SideEffectConfinementProfileKind {
    StrictOfflineWorkspace,
    TrustedFixedNetwork,
    ExternalCodex,
    TrustedCompatibility,
}

/// Records whether the requested filesystem, socket, network, and resource policy was enforced.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(tag = "status", content = "profile", rename_all = "snake_case")]
pub enum SideEffectConfinementEvidence {
    Verified(SideEffectConfinementProfileKind),
    TrustedBestEffort(SideEffectConfinementProfileKind),
    Unverified(SideEffectConfinementProfileKind),
}

impl SideEffectConfinementEvidence {
    pub const fn is_verified(self) -> bool {
        matches!(self, Self::Verified(_))
    }

    pub const fn publishable(self) -> bool {
        self.is_verified()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkspaceAccess {
    ReadOnly,
    ReadWrite,
}

/// Resource ceilings applied by the Linux systemd confinement backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcessResourceLimits {
    pub memory_max_bytes: u64,
    pub tasks_max: u32,
    pub cpu_quota_percent: u32,
    pub open_files_max: u32,
    pub file_size_max_bytes: u64,
}

impl Default for ProcessResourceLimits {
    fn default() -> Self {
        Self {
            memory_max_bytes: 4 * 1024 * 1024 * 1024,
            tasks_max: 256,
            cpu_quota_percent: 400,
            open_files_max: 8 * 1024,
            file_size_max_bytes: 2 * 1024 * 1024 * 1024,
        }
    }
}

#[cfg(target_os = "linux")]
#[derive(Clone)]
struct ExternalCodexWritableFileCapability {
    path: PathBuf,
    held_file: Arc<File>,
    identity: ExternalCodexWritableFileIdentity,
}

#[cfg(target_os = "linux")]
impl ExternalCodexWritableFileCapability {
    fn new(path: PathBuf, held_file: Arc<File>) -> std::io::Result<Self> {
        let identity = external_codex_writable_file_identity(&held_file.metadata()?)?;
        Ok(Self {
            path,
            held_file,
            identity,
        })
    }

    fn with_resolved_path(&self, path: PathBuf) -> Self {
        Self {
            path,
            held_file: Arc::clone(&self.held_file),
            identity: self.identity,
        }
    }

    fn verify_path(&self) -> std::io::Result<()> {
        let held_identity = external_codex_writable_file_identity(&self.held_file.metadata()?)?;
        let observed_identity =
            external_codex_writable_file_identity(&fs::symlink_metadata(&self.path)?)?;
        if held_identity != self.identity || observed_identity != self.identity {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "ExternalCodex writable file capability identity changed: {}",
                    self.path.display()
                ),
            ));
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
impl fmt::Debug for ExternalCodexWritableFileCapability {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExternalCodexWritableFileCapability")
            .field("path", &self.path)
            .field("identity", &self.identity)
            .finish_non_exhaustive()
    }
}

#[cfg(target_os = "linux")]
impl PartialEq for ExternalCodexWritableFileCapability {
    fn eq(&self, other: &Self) -> bool {
        self.path == other.path && self.identity == other.identity
    }
}

#[cfg(target_os = "linux")]
impl Eq for ExternalCodexWritableFileCapability {}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ExternalCodexWritableFileIdentity {
    device: u64,
    inode: u64,
    owner: u32,
    mode: u32,
    links: u64,
}

#[cfg(target_os = "linux")]
fn external_codex_writable_file_identity(
    metadata: &fs::Metadata,
) -> std::io::Result<ExternalCodexWritableFileIdentity> {
    use std::os::unix::fs::MetadataExt;

    if !metadata.file_type().is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "ExternalCodex writable file capability is not a regular file",
        ));
    }
    Ok(ExternalCodexWritableFileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        owner: metadata.uid(),
        mode: metadata.mode(),
        links: metadata.nlink(),
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct WorkspaceSandboxConfig {
    workspace_root: PathBuf,
    workspace_access: WorkspaceAccess,
    visible_read_only_roots: Vec<PathBuf>,
    visible_read_only_files: Vec<PathBuf>,
    visible_read_write_roots: Vec<PathBuf>,
    visible_read_write_files: Vec<PathBuf>,
    #[cfg(target_os = "linux")]
    external_codex_writable_file_capabilities: Vec<ExternalCodexWritableFileCapability>,
    writable_artifact_roots: Vec<PathBuf>,
    hidden_roots: Vec<PathBuf>,
    isolated_host_view: bool,
    resource_limits: ProcessResourceLimits,
}

impl WorkspaceSandboxConfig {
    fn new(workspace_root: impl Into<PathBuf>, workspace_access: WorkspaceAccess) -> Self {
        Self {
            workspace_root: workspace_root.into(),
            workspace_access,
            visible_read_only_roots: Vec::new(),
            visible_read_only_files: Vec::new(),
            visible_read_write_roots: Vec::new(),
            visible_read_write_files: Vec::new(),
            #[cfg(target_os = "linux")]
            external_codex_writable_file_capabilities: Vec::new(),
            writable_artifact_roots: Vec::new(),
            hidden_roots: Vec::new(),
            isolated_host_view: false,
            resource_limits: ProcessResourceLimits::default(),
        }
    }

    fn with_writable_artifact_root(mut self, root: impl Into<PathBuf>) -> Self {
        self.writable_artifact_roots.push(root.into());
        self
    }

    fn with_visible_read_only_root(mut self, root: impl Into<PathBuf>) -> Self {
        self.visible_read_only_roots.push(root.into());
        self
    }

    fn with_visible_read_only_file(mut self, file: impl Into<PathBuf>) -> Self {
        self.visible_read_only_files.push(file.into());
        self
    }

    fn with_visible_read_write_root(mut self, root: impl Into<PathBuf>) -> Self {
        self.visible_read_write_roots.push(root.into());
        self
    }

    fn with_visible_read_write_file(mut self, file: impl Into<PathBuf>) -> Self {
        self.visible_read_write_files.push(file.into());
        self
    }

    #[cfg(target_os = "linux")]
    fn with_external_codex_writable_file_capability(
        mut self,
        file: impl Into<PathBuf>,
        held_file: Arc<File>,
    ) -> std::io::Result<Self> {
        let path = file.into();
        let capability = ExternalCodexWritableFileCapability::new(path.clone(), held_file)?;
        self.visible_read_write_files.push(path);
        self.external_codex_writable_file_capabilities
            .push(capability);
        Ok(self)
    }

    fn with_hidden_root(mut self, root: impl Into<PathBuf>) -> Self {
        self.hidden_roots.push(root.into());
        self
    }

    fn with_isolated_host_view(mut self) -> Self {
        self.isolated_host_view = true;
        self
    }

    fn with_resource_limits(mut self, limits: ProcessResourceLimits) -> Self {
        self.resource_limits = limits;
        self
    }
}

/// Linux workspace profile for commands that must not use IPv4 or IPv6.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StrictOfflineWorkspaceProfile {
    config: WorkspaceSandboxConfig,
}

impl StrictOfflineWorkspaceProfile {
    pub fn read_write(workspace_root: impl Into<PathBuf>) -> Self {
        Self {
            config: WorkspaceSandboxConfig::new(workspace_root, WorkspaceAccess::ReadWrite),
        }
    }

    pub fn read_only(workspace_root: impl Into<PathBuf>) -> Self {
        Self {
            config: WorkspaceSandboxConfig::new(workspace_root, WorkspaceAccess::ReadOnly),
        }
    }

    pub fn with_writable_artifact_root(mut self, root: impl Into<PathBuf>) -> Self {
        self.config = self.config.with_writable_artifact_root(root);
        self
    }

    pub fn with_visible_read_only_root(mut self, root: impl Into<PathBuf>) -> Self {
        self.config = self.config.with_visible_read_only_root(root);
        self
    }

    pub fn with_hidden_root(mut self, root: impl Into<PathBuf>) -> Self {
        self.config = self.config.with_hidden_root(root);
        self
    }

    pub(crate) fn with_isolated_host_view(mut self) -> Self {
        self.config = self.config.with_isolated_host_view();
        self
    }

    pub fn with_resource_limits(mut self, limits: ProcessResourceLimits) -> Self {
        self.config = self.config.with_resource_limits(limits);
        self
    }

    #[cfg(test)]
    pub(crate) fn visible_read_only_roots(&self) -> &[PathBuf] {
        &self.config.visible_read_only_roots
    }

    #[cfg(test)]
    pub(crate) fn hidden_roots(&self) -> &[PathBuf] {
        &self.config.hidden_roots
    }

    #[cfg(test)]
    pub(crate) const fn isolated_host_view(&self) -> bool {
        self.config.isolated_host_view
    }
}

/// Linux profile for a fixed trusted command that needs parent-process network access.
///
/// This is an opaque capability: external callers can name it but cannot construct one.
///
/// ```compile_fail
/// use multi_agent_coding_orchestrator::process_runner::TrustedFixedNetworkProfile;
/// let _profile = TrustedFixedNetworkProfile::read_write(".");
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedFixedNetworkProfile {
    config: WorkspaceSandboxConfig,
}

impl TrustedFixedNetworkProfile {
    pub(crate) fn read_write(workspace_root: impl Into<PathBuf>) -> Self {
        Self {
            config: WorkspaceSandboxConfig::new(workspace_root, WorkspaceAccess::ReadWrite),
        }
    }

    pub(crate) fn with_visible_read_only_root(mut self, root: impl Into<PathBuf>) -> Self {
        self.config = self.config.with_visible_read_only_root(root);
        self
    }

    pub(crate) fn with_visible_read_only_file(mut self, file: impl Into<PathBuf>) -> Self {
        self.config = self.config.with_visible_read_only_file(file);
        self
    }

    pub(crate) fn with_hidden_root(mut self, root: impl Into<PathBuf>) -> Self {
        self.config = self.config.with_hidden_root(root);
        self
    }

    pub(crate) fn with_resource_limits(mut self, limits: ProcessResourceLimits) -> Self {
        self.config = self.config.with_resource_limits(limits);
        self
    }

    #[cfg(test)]
    pub(crate) fn visible_read_only_roots(&self) -> &[PathBuf] {
        &self.config.visible_read_only_roots
    }

    #[cfg(test)]
    pub(crate) fn visible_read_only_files(&self) -> &[PathBuf] {
        &self.config.visible_read_only_files
    }

    #[cfg(test)]
    pub(crate) fn hidden_roots(&self) -> &[PathBuf] {
        &self.config.hidden_roots
    }
}

/// Outer Linux profile for Codex. The parent CLI may reach its provider, while model-generated
/// commands must additionally use the custom Codex permission profile assembled by
/// `external_agent`.
///
/// This is an opaque capability. External callers cannot construct one directly; the crate's
/// validated external-Codex launch path is the only authority that may create it.
///
/// ```compile_fail
/// use multi_agent_coding_orchestrator::process_runner::ExternalCodexProfile;
/// let _profile = ExternalCodexProfile::read_write(".");
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalCodexProfile {
    config: WorkspaceSandboxConfig,
}

impl ExternalCodexProfile {
    pub(crate) fn read_write(workspace_root: impl Into<PathBuf>) -> Self {
        Self {
            config: WorkspaceSandboxConfig::new(workspace_root, WorkspaceAccess::ReadWrite),
        }
    }

    pub(crate) fn read_only(workspace_root: impl Into<PathBuf>) -> Self {
        Self {
            config: WorkspaceSandboxConfig::new(workspace_root, WorkspaceAccess::ReadOnly),
        }
    }

    pub(crate) fn with_writable_artifact_root(mut self, root: impl Into<PathBuf>) -> Self {
        self.config = self.config.with_writable_artifact_root(root);
        self
    }

    pub(crate) fn with_visible_read_only_root(mut self, root: impl Into<PathBuf>) -> Self {
        self.config = self.config.with_visible_read_only_root(root);
        self
    }

    pub(crate) fn with_visible_read_only_file(mut self, file: impl Into<PathBuf>) -> Self {
        self.config = self.config.with_visible_read_only_file(file);
        self
    }

    pub(crate) fn with_visible_read_write_root(mut self, root: impl Into<PathBuf>) -> Self {
        self.config = self.config.with_visible_read_write_root(root);
        self
    }

    pub(crate) fn with_visible_read_write_file(mut self, file: impl Into<PathBuf>) -> Self {
        self.config = self.config.with_visible_read_write_file(file);
        self
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn with_visible_read_write_file_capability(
        mut self,
        file: impl Into<PathBuf>,
        held_file: Arc<File>,
    ) -> std::io::Result<Self> {
        self.config = self
            .config
            .with_external_codex_writable_file_capability(file, held_file)?;
        Ok(self)
    }

    pub(crate) fn with_hidden_root(mut self, root: impl Into<PathBuf>) -> Self {
        self.config = self.config.with_hidden_root(root);
        self
    }

    #[cfg(test)]
    pub(crate) fn writable_artifact_roots(&self) -> &[PathBuf] {
        &self.config.writable_artifact_roots
    }

    #[cfg(test)]
    pub(crate) fn visible_read_only_roots(&self) -> &[PathBuf] {
        &self.config.visible_read_only_roots
    }

    #[cfg(test)]
    pub(crate) fn visible_read_write_roots(&self) -> &[PathBuf] {
        &self.config.visible_read_write_roots
    }

    #[cfg(test)]
    pub(crate) fn visible_read_write_files(&self) -> &[PathBuf] {
        &self.config.visible_read_write_files
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SideEffectConfinementProfile {
    StrictOfflineWorkspace(StrictOfflineWorkspaceProfile),
    TrustedFixedNetwork(TrustedFixedNetworkProfile),
    ExternalCodex(ExternalCodexProfile),
    /// Explicit legacy compatibility. Results are never publishable.
    TrustedCompatibility,
}

impl SideEffectConfinementProfile {
    pub const fn kind(&self) -> SideEffectConfinementProfileKind {
        match self {
            Self::StrictOfflineWorkspace(_) => {
                SideEffectConfinementProfileKind::StrictOfflineWorkspace
            }
            Self::TrustedFixedNetwork(_) => SideEffectConfinementProfileKind::TrustedFixedNetwork,
            Self::ExternalCodex(_) => SideEffectConfinementProfileKind::ExternalCodex,
            Self::TrustedCompatibility => SideEffectConfinementProfileKind::TrustedCompatibility,
        }
    }

    fn workspace_config(&self) -> Option<&WorkspaceSandboxConfig> {
        match self {
            Self::StrictOfflineWorkspace(profile) => Some(&profile.config),
            Self::TrustedFixedNetwork(profile) => Some(&profile.config),
            Self::ExternalCodex(profile) => Some(&profile.config),
            Self::TrustedCompatibility => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamCapture {
    pub max_bytes: usize,
    pub tee_path: Option<PathBuf>,
    pub max_tee_bytes: usize,
}

impl StreamCapture {
    pub const fn bounded(max_bytes: usize) -> Self {
        Self {
            max_bytes,
            tee_path: None,
            max_tee_bytes: DEFAULT_MAX_TEE_BYTES,
        }
    }

    pub fn tee_to(mut self, path: impl Into<PathBuf>) -> Self {
        self.tee_path = Some(path.into());
        self
    }

    pub const fn with_tee_limit(mut self, max_tee_bytes: usize) -> Self {
        self.max_tee_bytes = max_tee_bytes;
        self
    }
}

#[cfg(target_os = "linux")]
#[derive(Clone, PartialEq, Eq)]
struct PrivateRuntimeFile {
    name: String,
    bytes: Vec<u8>,
}

#[cfg(target_os = "linux")]
impl fmt::Debug for PrivateRuntimeFile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateRuntimeFile")
            .field("name", &self.name)
            .field(
                "bytes",
                &format_args!("<redacted:{} bytes>", self.bytes.len()),
            )
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessSpec {
    pub label: String,
    pub command: ProcessCommand,
    pub current_dir: PathBuf,
    pub environment: EnvironmentMode,
    /// Explicit MACO lifecycle identity for a provider-backed agent process. When present, the
    /// shared runner stamps its run/task environment and registers the exact launched PID.
    pub agent_lifecycle: Option<AgentLaunchMetadata>,
    /// Required by default. Use [`ProcessSpec::with_containment`] to make a trusted compatibility
    /// decision explicit at the call site.
    pub containment: ContainmentPolicy,
    /// Filesystem, socket, network, and resource confinement is independent of process-tree
    /// ownership. Strict offline workspace confinement is the default.
    pub side_effects: SideEffectConfinementProfile,
    pub stdin: StdinMode,
    pub max_stdin_bytes: usize,
    /// Replace HOME and TMPDIR with this run's owner-private systemd RuntimeDirectory. This is
    /// available only with the strict Linux backend and avoids unmanaged temporary homes.
    pub private_runtime_home: bool,
    /// Point CODEX_HOME at the same owner-private RuntimeDirectory.
    pub private_runtime_codex_home: bool,
    #[cfg(target_os = "linux")]
    private_runtime_files: Vec<PrivateRuntimeFile>,
    pinned_direct: Option<PinnedDirectCommand>,
    /// Total operation deadline starting at [`run_process`] entry. It covers containment-slot
    /// acquisition, pre-start setup, start-gate release, and command execution. Bounded cleanup may
    /// extend the return past this deadline to prove that no owned process remains. On strict Linux
    /// runs this value also sizes the independent orphan-safety fuse.
    pub timeout: Option<Duration>,
    pub stdout: StreamCapture,
    pub stderr: StreamCapture,
}

#[derive(Clone, PartialEq, Eq)]
struct PinnedDirectCommand {
    executable: PinnedDirectExecutable,
    program: PathBuf,
    arguments: Vec<OsString>,
}

impl fmt::Debug for PinnedDirectCommand {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PinnedDirectCommand")
            .field("executable", &"<redacted capability>")
            .field("program", &"<redacted>")
            .field(
                "arguments",
                &format_args!("<redacted:{} entries>", self.arguments.len()),
            )
            .finish()
    }
}

impl PinnedDirectCommand {
    fn validate_command(&self, command: &ProcessCommand) -> io::Result<()> {
        let ProcessCommand::Direct { program, args } = command else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "pinned executable capability requires a direct command",
            ));
        };
        if program != &self.program
            || args != &self.arguments
            || !self.executable.matches_program(program)?
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "direct command changed after executable identity was pinned",
            ));
        }
        pinned_exec::validated_current_helper_path().map(|_| ())
    }
}

impl ProcessSpec {
    pub fn shell(
        label: impl Into<String>,
        shell: Shell,
        command: impl Into<String>,
        current_dir: impl Into<PathBuf>,
        capture_limit_bytes: usize,
    ) -> Self {
        let current_dir = current_dir.into();
        Self {
            label: label.into(),
            command: ProcessCommand::Shell {
                shell,
                command: command.into(),
            },
            current_dir: current_dir.clone(),
            environment: EnvironmentMode::Inherit,
            agent_lifecycle: None,
            containment: ContainmentPolicy::Required,
            side_effects: SideEffectConfinementProfile::StrictOfflineWorkspace(
                StrictOfflineWorkspaceProfile::read_write(current_dir),
            ),
            stdin: StdinMode::Inherit,
            max_stdin_bytes: DEFAULT_MAX_STDIN_BYTES,
            private_runtime_home: false,
            private_runtime_codex_home: false,
            #[cfg(target_os = "linux")]
            private_runtime_files: Vec::new(),
            pinned_direct: None,
            timeout: None,
            stdout: StreamCapture::bounded(capture_limit_bytes),
            stderr: StreamCapture::bounded(capture_limit_bytes),
        }
    }

    pub fn direct(
        label: impl Into<String>,
        program: impl Into<PathBuf>,
        args: impl IntoIterator<Item = impl Into<OsString>>,
        current_dir: impl Into<PathBuf>,
        capture_limit_bytes: usize,
    ) -> Self {
        let current_dir = current_dir.into();
        Self {
            label: label.into(),
            command: ProcessCommand::Direct {
                program: program.into(),
                args: args.into_iter().map(Into::into).collect(),
            },
            current_dir: current_dir.clone(),
            environment: EnvironmentMode::Inherit,
            agent_lifecycle: None,
            containment: ContainmentPolicy::Required,
            side_effects: SideEffectConfinementProfile::StrictOfflineWorkspace(
                StrictOfflineWorkspaceProfile::read_write(current_dir),
            ),
            stdin: StdinMode::Inherit,
            max_stdin_bytes: DEFAULT_MAX_STDIN_BYTES,
            private_runtime_home: false,
            private_runtime_codex_home: false,
            #[cfg(target_os = "linux")]
            private_runtime_files: Vec::new(),
            pinned_direct: None,
            timeout: None,
            stdout: StreamCapture::bounded(capture_limit_bytes),
            stderr: StreamCapture::bounded(capture_limit_bytes),
        }
    }

    pub fn with_environment(mut self, environment: EnvironmentMode) -> Self {
        self.environment = environment;
        self
    }

    /// Marks this spec as a MACO-managed agent launch.
    ///
    /// Environment stamping is applied both here for inspectable built-spec evidence and again at
    /// [`run_process`] entry so later builder calls cannot accidentally discard the identifiers.
    pub fn with_agent_lifecycle(mut self, metadata: AgentLaunchMetadata) -> Self {
        stamp_agent_lifecycle_environment(&mut self.environment, &metadata);
        self.agent_lifecycle = Some(metadata);
        self
    }

    // This capability is intentionally crate-internal and is consumed only by callers that opt
    // into pathname-identity pinning.
    #[allow(dead_code)]
    pub(crate) fn with_pinned_direct_executable(
        mut self,
        executable: PinnedDirectExecutable,
    ) -> io::Result<Self> {
        let ProcessCommand::Direct { program, args } = &self.command else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "pinned executable capability requires a direct command",
            ));
        };
        if !executable.matches_program(program)? {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "pinned executable capability did not match the direct command",
            ));
        }
        self.pinned_direct = Some(PinnedDirectCommand {
            executable,
            program: program.clone(),
            arguments: args.clone(),
        });
        Ok(self)
    }

    fn command_display(&self) -> String {
        match &self.pinned_direct {
            Some(pinned) => format!(
                "<pinned direct executable; {} arguments redacted>",
                pinned.arguments.len()
            ),
            None => self.command.display(),
        }
    }

    pub fn with_containment(mut self, containment: ContainmentPolicy) -> Self {
        self.containment = containment;
        if containment == ContainmentPolicy::TrustedBestEffort {
            self.side_effects = SideEffectConfinementProfile::TrustedCompatibility;
        }
        self
    }

    pub fn with_side_effect_confinement(
        mut self,
        side_effects: SideEffectConfinementProfile,
    ) -> Self {
        self.side_effects = side_effects;
        self
    }

    pub fn with_stdin(mut self, stdin: StdinMode) -> Self {
        self.stdin = stdin;
        self
    }

    pub const fn with_stdin_limit(mut self, max_stdin_bytes: usize) -> Self {
        self.max_stdin_bytes = max_stdin_bytes;
        self
    }

    pub const fn with_private_runtime_home(mut self, enabled: bool) -> Self {
        self.private_runtime_home = enabled;
        self
    }

    pub const fn with_private_runtime_codex_home(mut self, enabled: bool) -> Self {
        self.private_runtime_codex_home = enabled;
        self
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn with_private_runtime_file(
        mut self,
        name: impl Into<String>,
        bytes: Vec<u8>,
    ) -> Self {
        self.private_runtime_files.push(PrivateRuntimeFile {
            name: name.into(),
            bytes,
        });
        self
    }

    pub fn with_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn with_stdout(mut self, stdout: StreamCapture) -> Self {
        self.stdout = stdout;
        self
    }

    pub fn with_stderr(mut self, stderr: StreamCapture) -> Self {
        self.stderr = stderr;
        self
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CapturedBytes {
    bytes: Vec<u8>,
    truncated: bool,
}

impl CapturedBytes {
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn is_truncated(&self) -> bool {
        self.truncated
    }

    pub fn summarize_chars(&self, max_chars: usize) -> CapturedText {
        let text = String::from_utf8_lossy(&self.bytes);
        let mut chars = text.chars();
        let value = chars.by_ref().take(max_chars).collect::<String>();
        CapturedText {
            text: value,
            truncated: self.truncated || chars.next().is_some(),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CapturedText {
    pub text: String,
    pub truncated: bool,
}

#[derive(Debug)]
pub struct ProcessOutput {
    pub status: Option<ExitStatus>,
    pub duration: Duration,
    pub timed_out: bool,
    pub process_tree: ProcessTreeEvidence,
    pub side_effects: SideEffectConfinementEvidence,
    pub stdout: CapturedBytes,
    pub stderr: CapturedBytes,
    pub process_error: Option<String>,
    pub stdin_error: Option<String>,
}

/// Result of one bounded interaction with a contained process.
///
/// Process ownership and confinement evidence are identical to [`ProcessOutput`]. The protocol
/// result is separate so a malformed or lost protocol cannot erase proof that the owned process
/// tree was cleaned up.
#[derive(Debug)]
pub(crate) struct InteractiveProcessOutput<T> {
    pub(crate) process: ProcessOutput,
    pub(crate) interaction: Result<T, String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum InteractiveProcessRead {
    Line,
    Timeout,
    Eof,
}

#[derive(Debug)]
pub struct ProcessFailureEvidence {
    pub stdout: CapturedBytes,
    pub stderr: CapturedBytes,
    pub process_tree: ProcessTreeEvidence,
    pub side_effects: SideEffectConfinementEvidence,
    pub process_error: Option<String>,
    pub stdin_error: Option<String>,
}

impl fmt::Display for ProcessFailureEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let stdout = self.stdout.summarize_chars(512);
        let stderr = self.stderr.summarize_chars(512);
        write!(
            formatter,
            "stdout={:?}{}; stderr={:?}{}",
            stdout.text,
            if stdout.truncated { " (truncated)" } else { "" },
            stderr.text,
            if stderr.truncated { " (truncated)" } else { "" }
        )?;
        write!(
            formatter,
            "; process_tree={:?}; side_effects={:?}",
            self.process_tree, self.side_effects
        )?;
        if let Some(error) = &self.process_error {
            write!(formatter, "; process cleanup: {error}")?;
        }
        if let Some(error) = &self.stdin_error {
            write!(formatter, "; stdin: {error}")?;
        }
        Ok(())
    }
}

impl ProcessOutput {
    pub fn duration_ms(&self) -> u64 {
        duration_millis(self.duration)
    }

    pub fn safety_evidence_verified(&self) -> bool {
        self.process_tree.is_verified_empty() && self.side_effects.is_verified()
    }

    pub fn safety_sensitive_succeeded(&self) -> bool {
        self.status.is_some_and(|status| status.success())
            && !self.timed_out
            && self.process_error.is_none()
            && self.stdin_error.is_none()
            && self.safety_evidence_verified()
    }
}

#[derive(Debug, Error)]
pub enum ProcessRunError {
    #[error("{label} ({command}) was cancelled during {phase}")]
    Cancelled {
        label: String,
        command: String,
        phase: &'static str,
        evidence: Option<Box<ProcessFailureEvidence>>,
    },
    #[error("failed to open {stream} tee for {label} at {path}: {source}")]
    OpenTee {
        label: String,
        stream: &'static str,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error(
        "stdout and stderr tee paths for {label} refer to the same file: {stdout} and {stderr}"
    )]
    TeeConflict {
        label: String,
        stdout: PathBuf,
        stderr: PathBuf,
    },
    #[error("failed to spawn {label} ({command}) in {current_dir}: {source}")]
    Spawn {
        label: String,
        command: String,
        current_dir: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("required process containment is unavailable for {label} ({command}): {source}")]
    ContainmentUnavailable {
        label: String,
        command: String,
        #[source]
        source: std::io::Error,
    },
    /// The total operation budget expired while the requested command was still behind its start
    /// gate. Any spawned containment wrapper has been rolled back before this error is returned.
    #[error("{label} ({command}) timed out before command start during {phase}: {source}")]
    SetupTimeout {
        label: String,
        command: String,
        phase: &'static str,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to query {label} ({command}) status: {source}; retained evidence: {evidence}")]
    Wait {
        label: String,
        command: String,
        evidence: Box<ProcessFailureEvidence>,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to establish process-tree ownership for {label} ({command}): {source}")]
    ProcessOwnership {
        label: String,
        command: String,
        #[source]
        source: std::io::Error,
    },
    #[error("sandbox environment is unavailable for {label} ({command}): {failure}")]
    EnvironmentFailure {
        label: String,
        command: String,
        failure: Box<EnvironmentFailure>,
        target_process_started: bool,
    },
    #[error("failed to prepare cancellable child I/O for {label} ({command}): {source}")]
    IoSetup {
        label: String,
        command: String,
        #[source]
        source: std::io::Error,
    },
    #[error("stdin for {label} exceeds the configured {limit} byte limit ({actual} bytes)")]
    StdinTooLarge {
        label: String,
        limit: usize,
        actual: usize,
    },
}

pub fn run_process(spec: ProcessSpec) -> Result<ProcessOutput, ProcessRunError> {
    run_process_cancellable(spec, &ProcessCancellation::new())
}

pub fn run_process_cancellable(
    spec: ProcessSpec,
    cancellation: &ProcessCancellation,
) -> Result<ProcessOutput, ProcessRunError> {
    run_process_cancellable_with_interaction(spec, cancellation, None)
}

/// Runs one bounded interactive protocol inside the normal contained process lifecycle.
///
/// The handler is invoked synchronously after the exact same preflight, containment attachment,
/// lifecycle registration, tee validation, and start gate as [`run_process_cancellable`]. It can
/// neither obtain nor retain the child or its stdio handles. Returning from the handler closes
/// stdin and the normal runner loop then reaps the process, verifies the owned tree is empty, and
/// returns the ordinary confinement evidence.
pub(crate) fn run_process_interactive<T, F>(
    mut spec: ProcessSpec,
    cancellation: &ProcessCancellation,
    mut handler: F,
) -> Result<InteractiveProcessOutput<T>, ProcessRunError>
where
    F: FnMut(&mut ContainedProcessSession<'_>) -> Result<T, String>,
{
    spec.stdin = StdinMode::Interactive;
    let mut interaction = None;
    let mut adapter = |session: &mut ContainedProcessSession<'_>| {
        interaction = Some(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| handler(session)))
                .unwrap_or_else(|_| {
                    Err("contained interactive handler panicked; details redacted".to_string())
                }),
        );
    };
    let process = run_process_cancellable_with_interaction(spec, cancellation, Some(&mut adapter))?;
    let interaction = interaction.ok_or_else(|| ProcessRunError::IoSetup {
        label: "interactive process".to_string(),
        command: "<redacted>".to_string(),
        source: std::io::Error::other(
            "contained interactive handler was not invoked after successful setup",
        ),
    })?;
    Ok(InteractiveProcessOutput {
        process,
        interaction,
    })
}

fn run_process_cancellable_with_interaction(
    mut spec: ProcessSpec,
    cancellation: &ProcessCancellation,
    interaction: Option<&mut dyn FnMut(&mut ContainedProcessSession<'_>)>,
) -> Result<ProcessOutput, ProcessRunError> {
    let started = Instant::now();
    if interaction.is_some() != matches!(spec.stdin, StdinMode::Interactive) {
        return Err(ProcessRunError::IoSetup {
            label: spec.label.clone(),
            command: spec.command_display(),
            source: std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "interactive stdin requires the bounded interactive runner",
            ),
        });
    }
    if let Some(metadata) = &spec.agent_lifecycle {
        stamp_agent_lifecycle_environment(&mut spec.environment, metadata);
    }
    let command_display = spec.command_display();
    validate_process_spec_bounds(&spec).map_err(|source| ProcessRunError::Spawn {
        label: spec.label.clone(),
        command: command_display.clone(),
        current_dir: spec.current_dir.clone(),
        source,
    })?;
    if let StdinMode::Bytes(bytes) = &spec.stdin {
        if bytes.len() > spec.max_stdin_bytes {
            return Err(ProcessRunError::StdinTooLarge {
                label: spec.label.clone(),
                limit: spec.max_stdin_bytes,
                actual: bytes.len(),
            });
        }
    }
    ensure_not_cancelled(cancellation, &spec.label, &command_display, "initial setup")?;
    let operation_deadline = spec
        .timeout
        .map(|timeout| {
            started.checked_add(timeout).ok_or_else(|| {
                setup_timeout_error(
                    &spec.label,
                    &command_display,
                    "timeout validation",
                    "requested duration exceeds the platform Instant range",
                )
            })
        })
        .transpose()?;
    preflight_direct_program(&spec.command).map_err(|source| ProcessRunError::Spawn {
        label: spec.label.clone(),
        command: command_display.clone(),
        current_dir: spec.current_dir.clone(),
        source,
    })?;
    ensure_not_cancelled(
        cancellation,
        &spec.label,
        &command_display,
        "executable preflight",
    )?;
    ensure_setup_budget(
        operation_deadline,
        &spec.label,
        &command_display,
        "preflight",
    )?;
    let prepared_tees = prepare_tees(
        &spec.label,
        &spec.stdout,
        &spec.stderr,
        spec.containment == ContainmentPolicy::Required,
        operation_deadline,
        &command_display,
    )?;
    let mut prepared_process_tree = PreparedProcessTree::prepare(
        spec.containment,
        &spec.side_effects,
        &spec.label,
        &command_display,
        operation_deadline,
        cancellation,
    )?;
    let mut command = prepared_process_tree
        .build_command(&spec)
        .map_err(|source| {
            containment_setup_error(spec.label.clone(), command_display.clone(), source)
        })?;
    ensure_setup_budget(
        operation_deadline,
        &spec.label,
        &command_display,
        "containment and I/O setup",
    )?;
    configure_stdin(&mut command, &spec.stdin);
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    ensure_not_cancelled(
        cancellation,
        &spec.label,
        &command_display,
        "child spawn gate",
    )?;

    #[cfg(test)]
    if env::var_os("MACO_TEST_ABORT_BEFORE_CHILD_SPAWN").is_some() {
        std::process::abort();
    }
    #[cfg(test)]
    if env::var_os("MACO_TEST_FAIL_BEFORE_CHILD_SPAWN").is_some() {
        return Err(ProcessRunError::Spawn {
            label: spec.label.clone(),
            command: command_display.clone(),
            current_dir: spec.current_dir.clone(),
            source: std::io::Error::other("synthetic child spawn failure"),
        });
    }
    let mut child = command.spawn().map_err(|source| ProcessRunError::Spawn {
        label: spec.label.clone(),
        command: command_display.clone(),
        current_dir: spec.current_dir.clone(),
        source,
    })?;
    #[cfg(test)]
    if let Some(marker) = env::var_os("MACO_TEST_AFTER_CHILD_SPAWN_MARKER") {
        if let Err(source) = fs::write(marker, b"spawned") {
            let error = ProcessRunError::Spawn {
                label: spec.label.clone(),
                command: command_display.clone(),
                current_dir: spec.current_dir.clone(),
                source,
            };
            let cleanup = terminate_unowned_child(&mut child, &spec.label);
            return Err(append_process_run_error_cleanup(error, cleanup));
        }
        while env::var_os("MACO_TEST_HOLD_AFTER_CHILD_SPAWN").is_some() {
            thread::sleep(POLL_INTERVAL);
        }
    }
    let mut attached_process_tree = match prepared_process_tree.attach(
        &mut child,
        &spec.label,
        &command_display,
        operation_deadline,
        cancellation,
    ) {
        Ok(process_tree) => process_tree,
        Err(error) => {
            let cleanup = terminate_unowned_child(&mut child, &spec.label);
            return Err(append_process_run_error_cleanup(error, cleanup));
        }
    };
    if cancellation.is_cancelled() {
        return Err(cancel_attached_process(
            &mut attached_process_tree,
            &mut child,
            &spec.label,
            &command_display,
            "containment attachment gate",
        ));
    }
    let prepared_io_result = {
        #[cfg(test)]
        if env::var_os("MACO_TEST_FAIL_PRE_RELEASE_IO_SETUP").is_some() {
            Err(std::io::Error::other(
                "synthetic pre-release child I/O setup failure",
            ))
        } else {
            PreparedChildIo::take(&mut child, &spec.stdin)
        }
        #[cfg(not(test))]
        PreparedChildIo::take(&mut child, &spec.stdin)
    };
    let prepared_io = match prepared_io_result {
        Ok(prepared_io) => prepared_io,
        Err(source) => {
            let cleanup = attached_process_tree.cleanup(
                &mut child,
                &spec.label,
                "pre-release I/O setup rollback",
            );
            let cleanup_error = append_error(
                cleanup.error,
                wait_for_child_cleanup(&mut child, &spec.label, "pre-release I/O setup rollback"),
            );
            let source = append_error(Some(source.to_string()), cleanup_error)
                .map(std::io::Error::other)
                .unwrap_or(source);
            return Err(ProcessRunError::IoSetup {
                label: spec.label.clone(),
                command: command_display,
                source,
            });
        }
    };
    if let Err(error) = prepared_tees.validate(&spec.label) {
        let cleanup = attached_process_tree.cleanup(
            &mut child,
            &spec.label,
            "tee transaction validation rollback",
        );
        let cleanup_error = append_error(
            cleanup.error,
            wait_for_child_cleanup(
                &mut child,
                &spec.label,
                "tee transaction validation rollback",
            ),
        );
        return Err(append_process_run_error_cleanup(error, cleanup_error));
    }
    if cancellation.is_cancelled() {
        return Err(cancel_attached_process(
            &mut attached_process_tree,
            &mut child,
            &spec.label,
            &command_display,
            "containment start gate",
        ));
    }
    if let Some(metadata) = &spec.agent_lifecycle {
        let pid = match attached_process_tree.agent_lifecycle_pid(
            &mut child,
            operation_deadline,
            cancellation,
        ) {
            Ok(pid) => pid,
            Err(source) => {
                let cleanup = attached_process_tree.cleanup(
                    &mut child,
                    &spec.label,
                    "agent lifecycle PID capture rollback",
                );
                let cleanup_error = append_error(
                    cleanup.error,
                    wait_for_child_cleanup(
                        &mut child,
                        &spec.label,
                        "agent lifecycle PID capture rollback",
                    ),
                );
                let error = process_ownership_error(spec.label.clone(), command_display, source);
                return Err(append_process_run_error_cleanup(error, cleanup_error));
            }
        };
        let registration = AgentRegistry::open(metadata.repo())
            .and_then(|registry| registry.register(metadata, pid, spec.command.lifecycle_argv()));
        if let Err(error) = registration {
            let cleanup = attached_process_tree.cleanup(
                &mut child,
                &spec.label,
                "agent lifecycle registration rollback",
            );
            let cleanup_error = append_error(
                cleanup.error,
                wait_for_child_cleanup(
                    &mut child,
                    &spec.label,
                    "agent lifecycle registration rollback",
                ),
            );
            let source = append_error(
                Some(format!("failed to register launched agent: {error:#}")),
                cleanup_error,
            )
            .map(std::io::Error::other)
            .unwrap_or_else(|| std::io::Error::other("failed to register launched agent"));
            return Err(ProcessRunError::ProcessOwnership {
                label: spec.label.clone(),
                command: command_display,
                source,
            });
        }
    }
    let mut process_tree = match attached_process_tree.release(
        &mut child,
        &spec.label,
        &command_display,
        operation_deadline,
        cancellation,
    ) {
        Ok(process_tree) => process_tree,
        Err(error) => {
            let cleanup = terminate_unowned_child(&mut child, &spec.label);
            return Err(append_process_run_error_cleanup(error, cleanup));
        }
    };
    let (stdout_tee, stderr_tee) = prepared_tees.commit();
    let (mut input_writer, mut output_drainers) = match interaction {
        Some(handler) => {
            let mut session = prepared_io
                .start_interactive(
                    &spec.label,
                    cancellation,
                    operation_deadline,
                    spec.max_stdin_bytes,
                    spec.stdout.max_bytes,
                    spec.stderr.max_bytes,
                    stdout_tee,
                    stderr_tee,
                )
                .map_err(|source| ProcessRunError::IoSetup {
                    label: spec.label.clone(),
                    command: command_display.clone(),
                    source,
                })?;
            if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| handler(&mut session)))
                .is_err()
            {
                let _ = session.fail_io::<()>(
                    "contained interactive protocol adapter panicked; details redacted",
                );
            }
            session.into_runner_io()
        }
        None => prepared_io.start(
            &spec.label,
            spec.stdin,
            spec.stdout.max_bytes,
            spec.stderr.max_bytes,
            stdout_tee,
            stderr_tee,
        ),
    };
    let mut status = None;
    let mut timed_out = false;
    let mut process_error = None;
    let process_tree_evidence;
    let side_effect_evidence;

    loop {
        let output_backlog = output_drainers.drain_ready();
        input_writer.drain_ready();

        if status.is_none() {
            status = match child.try_wait() {
                Ok(status) => status,
                Err(source) => {
                    let evidence = cleanup_after_wait_error(
                        &mut child,
                        &mut process_tree,
                        &spec.label,
                        output_drainers,
                        input_writer,
                    );
                    return Err(ProcessRunError::Wait {
                        label: spec.label.clone(),
                        command: command_display.clone(),
                        evidence: Box::new(evidence),
                        source,
                    });
                }
            };
        }

        let loop_decision = process_loop_decision(
            status.is_some(),
            cancellation.is_cancelled(),
            operation_deadline,
            Instant::now(),
        );

        if loop_decision == ProcessLoopDecision::Cancel {
            let cleanup =
                process_tree.cleanup(&mut child, false, &spec.label, "cancellation termination");
            process_tree_evidence = cleanup.process_tree;
            side_effect_evidence = cleanup.side_effects;
            process_error = append_error(
                process_error,
                Some(format!(
                    "{} was cancelled by its run supervisor",
                    spec.label
                )),
            );
            process_error = append_error(process_error, cleanup.error);

            let exit_deadline = Instant::now() + EXIT_AND_DRAIN_GRACE;
            status = match wait_for_exit_until(&mut child, exit_deadline) {
                Ok(status) => status,
                Err(source) => {
                    let evidence = cleanup_after_wait_error(
                        &mut child,
                        &mut process_tree,
                        &spec.label,
                        output_drainers,
                        input_writer,
                    );
                    return Err(ProcessRunError::Wait {
                        label: spec.label.clone(),
                        command: command_display.clone(),
                        evidence: Box::new(evidence),
                        source,
                    });
                }
            };
            if status.is_none() {
                process_error = append_error(
                    process_error,
                    Some(format!(
                        "{} was cancelled and did not exit within {} ms after termination",
                        spec.label,
                        EXIT_AND_DRAIN_GRACE.as_millis()
                    )),
                );
                let (reaped_status, reap_error) =
                    kill_and_reap_child(&mut child, &spec.label, "cancellation fallback");
                status = Some(reaped_status);
                process_error = append_error(process_error, reap_error);
            }

            finish_child_io(
                &spec.label,
                "after cancellation termination",
                &mut output_drainers,
                &mut input_writer,
                &mut process_error,
            );
            break;
        }

        if loop_decision == ProcessLoopDecision::Timeout {
            timed_out = true;
            let cleanup = process_tree.cleanup(
                &mut child,
                status.is_some(),
                &spec.label,
                "timeout termination",
            );
            process_tree_evidence = cleanup.process_tree;
            side_effect_evidence = cleanup.side_effects;
            process_error = append_error(process_error, cleanup.error);

            let exit_deadline = Instant::now() + EXIT_AND_DRAIN_GRACE;
            if status.is_none() {
                status = match wait_for_exit_until(&mut child, exit_deadline) {
                    Ok(status) => status,
                    Err(source) => {
                        let evidence = cleanup_after_wait_error(
                            &mut child,
                            &mut process_tree,
                            &spec.label,
                            output_drainers,
                            input_writer,
                        );
                        return Err(ProcessRunError::Wait {
                            label: spec.label.clone(),
                            command: command_display.clone(),
                            evidence: Box::new(evidence),
                            source,
                        });
                    }
                };
                if status.is_none() {
                    process_error = append_error(
                        process_error,
                        Some(format!(
                            "{} timed out and did not exit within {} ms after termination",
                            spec.label,
                            EXIT_AND_DRAIN_GRACE.as_millis()
                        )),
                    );
                    let (reaped_status, reap_error) =
                        kill_and_reap_child(&mut child, &spec.label, "timeout fallback");
                    status = Some(reaped_status);
                    process_error = append_error(process_error, reap_error);
                }
            }

            finish_child_io(
                &spec.label,
                "after timeout termination",
                &mut output_drainers,
                &mut input_writer,
                &mut process_error,
            );
            break;
        }

        if loop_decision == ProcessLoopDecision::Complete {
            let cleanup = process_tree.cleanup(
                &mut child,
                true,
                &spec.label,
                "normal process-tree finalization",
            );
            process_tree_evidence = cleanup.process_tree;
            side_effect_evidence = cleanup.side_effects;
            process_error = append_error(process_error, cleanup.error);
            finish_child_io(
                &spec.label,
                "after normal process exit",
                &mut output_drainers,
                &mut input_writer,
                &mut process_error,
            );
            break;
        }

        if !output_backlog {
            thread::sleep(POLL_INTERVAL);
        }
    }

    output_drainers.drain_ready();
    input_writer.drain_ready();
    let (stdout, stderr, output_error) = output_drainers.into_outputs();
    process_error = append_error(process_error, output_error);
    let (stdin_error, input_cleanup_error) = input_writer.into_result(&spec.label);
    process_error = append_error(process_error, input_cleanup_error);

    Ok(ProcessOutput {
        status,
        duration: started.elapsed(),
        timed_out,
        process_tree: process_tree_evidence,
        side_effects: side_effect_evidence,
        stdout,
        stderr,
        process_error,
        stdin_error,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProcessLoopDecision {
    Cancel,
    Timeout,
    Complete,
    Continue,
}

fn process_loop_decision(
    status_observed: bool,
    cancelled: bool,
    operation_deadline: Option<Instant>,
    observed_at: Instant,
) -> ProcessLoopDecision {
    if !status_observed && cancelled {
        ProcessLoopDecision::Cancel
    } else if operation_deadline.is_some_and(|deadline| observed_at >= deadline) {
        // The deadline governs when completion is observed, not when the child happened to exit.
        // Keep this check ahead of `Complete` so a late first observation remains a timeout.
        ProcessLoopDecision::Timeout
    } else if status_observed {
        ProcessLoopDecision::Complete
    } else {
        ProcessLoopDecision::Continue
    }
}

impl ProcessRunError {
    pub fn cancellation_evidence(&self) -> Option<&ProcessFailureEvidence> {
        match self {
            Self::Cancelled {
                evidence: Some(evidence),
                ..
            } => Some(evidence),
            _ => None,
        }
    }

    pub fn is_cancelled(&self) -> bool {
        matches!(self, Self::Cancelled { .. })
    }
}

fn ensure_not_cancelled(
    cancellation: &ProcessCancellation,
    label: &str,
    command: &str,
    phase: &'static str,
) -> Result<(), ProcessRunError> {
    if cancellation.is_cancelled() {
        return Err(ProcessRunError::Cancelled {
            label: label.to_string(),
            command: command.to_string(),
            phase,
            evidence: None,
        });
    }
    Ok(())
}

fn cancel_attached_process(
    process_tree: &mut AttachedProcessTree,
    child: &mut Child,
    label: &str,
    command: &str,
    phase: &'static str,
) -> ProcessRunError {
    let cleanup = process_tree.cleanup(child, label, "pre-release cancellation rollback");
    let process_error = append_error(
        Some(format!("{label} was cancelled by its run supervisor")),
        append_error(
            cleanup.error,
            wait_for_child_cleanup(child, label, "pre-release cancellation rollback"),
        ),
    );
    ProcessRunError::Cancelled {
        label: label.to_string(),
        command: command.to_string(),
        phase,
        evidence: Some(Box::new(ProcessFailureEvidence {
            stdout: CapturedBytes::default(),
            stderr: CapturedBytes::default(),
            process_tree: cleanup.process_tree,
            side_effects: cleanup.side_effects,
            process_error,
            stdin_error: None,
        })),
    }
}

fn validate_process_spec_bounds(spec: &ProcessSpec) -> std::io::Result<()> {
    if spec.label.is_empty()
        || spec.label.len() > MAX_PROCESS_LABEL_BYTES
        || contains_ascii_control(spec.label.as_bytes())
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "process label is empty or exceeds its safety bound",
        ));
    }
    if let Some(metadata) = &spec.agent_lifecycle {
        metadata
            .validate()
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error.to_string()))?;
    }
    let mut argument_count = 0usize;
    let mut argument_bytes = 0usize;
    match &spec.command {
        ProcessCommand::Shell { command, .. } => {
            if command.len() > MAX_SHELL_COMMAND_BYTES || command.as_bytes().contains(&0) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "shell command exceeds its safety bound",
                ));
            }
        }
        ProcessCommand::Direct { program, args } => {
            validate_bounded_os_str(
                program.as_os_str(),
                MAX_SANDBOX_PATH_BYTES,
                "direct executable path",
            )?;
            argument_count = args.len();
            for argument in args {
                let bytes = validate_bounded_os_str(
                    argument.as_os_str(),
                    MAX_PROCESS_ARGUMENT_BYTES,
                    "direct command argument",
                )?;
                argument_bytes = argument_bytes.checked_add(bytes).ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "direct command argument size overflow",
                    )
                })?;
            }
        }
    }
    if argument_count > MAX_PROCESS_ARGUMENTS || argument_bytes > MAX_PROCESS_ARGUMENT_TOTAL_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "direct command argument vector exceeds its safety bound",
        ));
    }
    if let Some(pinned) = &spec.pinned_direct {
        if spec.containment != ContainmentPolicy::Required {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "pinned executable capability requires strict process containment",
            ));
        }
        if !matches!(spec.environment, EnvironmentMode::ClearAndSet(_)) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "pinned executable capability requires an explicit clear-and-set environment",
            ));
        }
        pinned.validate_command(&spec.command)?;
        let ProcessCommand::Direct { args, .. } = &spec.command else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "pinned executable capability requires a direct command",
            ));
        };
        let EnvironmentMode::ClearAndSet(environment) = &spec.environment else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "pinned executable capability requires an explicit clear-and-set environment",
            ));
        };
        let environment = environment
            .iter()
            .map(|(name, value)| (OsString::from(name), OsString::from(value)))
            .collect::<Vec<_>>();
        pinned.executable.encode_descriptor(args, &environment)?;
    }
    validate_environment_bounds(&spec.environment)?;
    for capture in [&spec.stdout, &spec.stderr] {
        if capture.max_bytes > MAX_REQUIRED_STREAM_BYTES
            || capture.max_tee_bytes > MAX_REQUIRED_STREAM_BYTES
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "process stream capture exceeds its safety bound",
            ));
        }
        if let Some(path) = capture.tee_path.as_ref() {
            validate_bounded_path(path, "process tee path")?;
        }
    }
    if spec.max_stdin_bytes > MAX_REQUIRED_STREAM_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "process stdin limit exceeds its safety bound",
        ));
    }
    validate_bounded_path(&spec.current_dir, "process working directory")?;
    if let Some(config) = spec.side_effects.workspace_config() {
        validate_workspace_config_bounds(config)?;
    }
    Ok(())
}

fn validate_environment_bounds(mode: &EnvironmentMode) -> std::io::Result<()> {
    let environment = match mode {
        EnvironmentMode::Inherit => return Ok(()),
        EnvironmentMode::InheritAndSet(environment) | EnvironmentMode::ClearAndSet(environment) => {
            environment
        }
    };
    if environment.len() > MAX_PROCESS_ENVIRONMENT_ENTRIES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "process environment exceeds its entry limit",
        ));
    }
    let mut total = 0usize;
    for (key, value) in environment {
        if key.is_empty()
            || key.len() > MAX_PROCESS_ENVIRONMENT_KEY_BYTES
            || value.len() > MAX_PROCESS_ENVIRONMENT_VALUE_BYTES
            || contains_ascii_control(key.as_bytes())
            || contains_ascii_control(value.as_bytes())
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "process environment entry is empty, malformed, or oversized",
            ));
        }
        total = total
            .checked_add(key.len())
            .and_then(|total| total.checked_add(value.len()))
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "process environment size overflow",
                )
            })?;
    }
    if total > MAX_PROCESS_ENVIRONMENT_TOTAL_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "process environment exceeds its aggregate size limit",
        ));
    }
    Ok(())
}

fn validate_workspace_config_bounds(config: &WorkspaceSandboxConfig) -> std::io::Result<()> {
    for (label, paths) in [
        ("visible read-only roots", &config.visible_read_only_roots),
        ("visible read-only files", &config.visible_read_only_files),
        ("visible read-write roots", &config.visible_read_write_roots),
        ("visible read-write files", &config.visible_read_write_files),
        ("writable artifact roots", &config.writable_artifact_roots),
        ("hidden roots", &config.hidden_roots),
    ] {
        if paths.len() > MAX_SANDBOX_PATHS_PER_CLASS {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("sandbox {label} exceeds its vector limit"),
            ));
        }
        for path in paths {
            validate_bounded_path(path, label)?;
        }
    }
    #[cfg(target_os = "linux")]
    {
        if config.external_codex_writable_file_capabilities.len() > MAX_SANDBOX_PATHS_PER_CLASS {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "ExternalCodex writable file capabilities exceed their vector limit",
            ));
        }
        let mut capability_paths = BTreeSet::new();
        for capability in &config.external_codex_writable_file_capabilities {
            validate_bounded_path(&capability.path, "ExternalCodex writable file capability")?;
            if !config.visible_read_write_files.contains(&capability.path)
                || !capability_paths.insert(&capability.path)
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "ExternalCodex writable file capability is duplicate or lacks an exact writable file",
                ));
            }
        }
    }
    let total = 1usize
        .checked_add(config.visible_read_only_roots.len())
        .and_then(|total| total.checked_add(config.visible_read_only_files.len()))
        .and_then(|total| total.checked_add(config.visible_read_write_roots.len()))
        .and_then(|total| total.checked_add(config.visible_read_write_files.len()))
        .and_then(|total| total.checked_add(config.writable_artifact_roots.len()))
        .and_then(|total| total.checked_add(config.hidden_roots.len()))
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "sandbox path vector size overflow",
            )
        })?;
    if total > MAX_SANDBOX_TOTAL_PATHS {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "sandbox path vectors exceed their aggregate limit",
        ));
    }
    validate_bounded_path(&config.workspace_root, "workspace root")?;
    validate_resource_limits(config.resource_limits)
}

fn validate_bounded_path(path: &Path, label: &str) -> std::io::Result<()> {
    validate_bounded_os_str(path.as_os_str(), MAX_SANDBOX_PATH_BYTES, label).map(|_| ())
}

fn contains_ascii_control(bytes: &[u8]) -> bool {
    bytes.iter().any(|byte| byte.is_ascii_control())
}

#[cfg(unix)]
fn validate_bounded_os_str(value: &OsStr, max_bytes: usize, label: &str) -> std::io::Result<usize> {
    use std::os::unix::ffi::OsStrExt;

    let bytes = value.as_bytes();
    if bytes.is_empty() || bytes.len() > max_bytes || contains_ascii_control(bytes) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("{label} is empty, malformed, or exceeds its encoded-length bound"),
        ));
    }
    Ok(bytes.len())
}

#[cfg(windows)]
fn validate_bounded_os_str(value: &OsStr, max_bytes: usize, label: &str) -> std::io::Result<usize> {
    use std::os::windows::ffi::OsStrExt;

    let mut encoded_units = 0usize;
    for unit in value.encode_wide() {
        if unit == 0 || unit <= 0x1f || unit == 0x7f {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("{label} contains a control code unit"),
            ));
        }
        encoded_units = encoded_units.checked_add(1).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("{label} encoded-length overflow"),
            )
        })?;
    }
    let encoded_bytes = encoded_units.checked_mul(2).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("{label} encoded-length overflow"),
        )
    })?;
    if encoded_bytes == 0 || encoded_bytes > max_bytes {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("{label} is empty or exceeds its encoded-length bound"),
        ));
    }
    Ok(encoded_bytes)
}

fn validate_resource_limits(limits: ProcessResourceLimits) -> std::io::Result<()> {
    if !(16 * 1024 * 1024..=16 * 1024 * 1024 * 1024).contains(&limits.memory_max_bytes)
        || !(1..=4096).contains(&limits.tasks_max)
        || !(1..=1600).contains(&limits.cpu_quota_percent)
        || !(16..=65_536).contains(&limits.open_files_max)
        || !(1..=16 * 1024 * 1024 * 1024).contains(&limits.file_size_max_bytes)
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "process resource limits are zero or exceed their safety bounds",
        ));
    }
    Ok(())
}

fn preflight_direct_program(command: &ProcessCommand) -> std::io::Result<()> {
    let ProcessCommand::Direct { program, .. } = command else {
        return Ok(());
    };
    if program.is_absolute() || program.components().count() > 1 {
        fs::metadata(program).map(|_| ())?;
    }
    Ok(())
}

/// Reads a regular file without following a final symlink and rejects oversized inputs before
/// they can become unbounded process stdin or prompt context.
pub fn read_bounded_regular_file_nofollow(
    path: &Path,
    max_bytes: usize,
) -> std::io::Result<Vec<u8>> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let mut file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("{} is not a regular file", path.display()),
        ));
    }
    #[cfg(target_os = "windows")]
    {
        use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;
        let (_, _, attributes) = windows_file_identity(&file)?;
        if attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("{} may not be a reparse point", path.display()),
            ));
        }
    }
    if metadata.len() > max_bytes as u64 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::FileTooLarge,
            format!(
                "{} exceeds the configured {max_bytes} byte limit",
                path.display()
            ),
        ));
    }
    let read_limit = max_bytes.saturating_add(1) as u64;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    Read::by_ref(&mut file)
        .take(read_limit)
        .read_to_end(&mut bytes)?;
    if bytes.len() > max_bytes {
        return Err(std::io::Error::new(
            std::io::ErrorKind::FileTooLarge,
            format!(
                "{} grew beyond the configured {max_bytes} byte limit while being read",
                path.display()
            ),
        ));
    }
    Ok(bytes)
}

/// Resolves a repository-relative path while rejecting every symlink component.
pub fn resolve_existing_path_without_symlinks(
    root: &Path,
    relative: &Path,
) -> std::io::Result<PathBuf> {
    if relative.is_absolute() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "path must be relative to its workspace root",
        ));
    }
    let canonical_root = fs::canonicalize(root)?;
    let mut current = canonical_root.clone();
    for component in relative.components() {
        let std::path::Component::Normal(component) = component else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("unsafe relative path component in {}", relative.display()),
            ));
        };
        current.push(component);
        if fs::symlink_metadata(&current)?.file_type().is_symlink() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "symlink path component is not allowed: {}",
                    current.display()
                ),
            ));
        }
    }
    let canonical = fs::canonicalize(&current)?;
    if !canonical.starts_with(&canonical_root) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "{} resolves outside workspace root {}",
                relative.display(),
                canonical_root.display()
            ),
        ));
    }
    Ok(canonical)
}

fn terminate_unowned_child(child: &mut Child, label: &str) -> Option<String> {
    let (_, error) = kill_and_reap_child(child, label, "unowned-child rollback");
    error
}

fn wait_for_child_cleanup(child: &mut Child, label: &str, context: &str) -> Option<String> {
    match wait_for_exit_until(child, Instant::now() + EXIT_AND_DRAIN_GRACE) {
        Ok(Some(_)) => None,
        Ok(None) => {
            let (_, cleanup) = kill_and_reap_child(child, label, context);
            append_error(
                Some(format!(
                    "{label} did not exit within {} ms during {context}",
                    EXIT_AND_DRAIN_GRACE.as_millis()
                )),
                cleanup,
            )
        }
        Err(error) => {
            let (_, cleanup) = kill_and_reap_child(child, label, context);
            append_error(
                Some(format!(
                    "failed to wait for {label} during {context}: {error}"
                )),
                cleanup,
            )
        }
    }
}

fn kill_and_reap_child(
    child: &mut Child,
    label: &str,
    context: &str,
) -> (ExitStatus, Option<String>) {
    let mut error = child
        .kill()
        .err()
        .map(|error| format!("failed to kill {label} during {context}: {error}"));
    for attempt in 1..=2 {
        match wait_for_exit_until(child, Instant::now() + EXIT_AND_DRAIN_GRACE) {
            Ok(Some(status)) => return (status, error),
            Ok(None) => {
                error = append_error(
                    error,
                    Some(format!(
                        "{label} remained live after bounded reap attempt {attempt} during {context}"
                    )),
                );
            }
            Err(wait_error) => {
                error = append_error(
                    error,
                    Some(format!(
                        "failed to wait for {label} on reap attempt {attempt} during {context}: {wait_error}"
                    )),
                );
            }
        }
        error = append_error(
            error,
            child
                .kill()
                .err()
                .map(|kill_error| format!("repeat kill failed for {label}: {kill_error}")),
        );
    }
    fail_closed_stuck_owner(&format!("{label} child during {context}"));
}

fn append_process_run_error_cleanup(
    error: ProcessRunError,
    cleanup: Option<String>,
) -> ProcessRunError {
    let Some(cleanup) = cleanup else {
        return error;
    };
    match error {
        ProcessRunError::OpenTee {
            label,
            stream,
            path,
            source,
        } => ProcessRunError::OpenTee {
            label,
            stream,
            path,
            source: std::io::Error::new(
                source.kind(),
                format!("{source}; cleanup failed: {cleanup}"),
            ),
        },
        ProcessRunError::ProcessOwnership {
            label,
            command,
            source,
        } => ProcessRunError::ProcessOwnership {
            label,
            command,
            source: std::io::Error::other(format!("{source}; cleanup failed: {cleanup}")),
        },
        ProcessRunError::EnvironmentFailure {
            label,
            command,
            mut failure,
            target_process_started,
        } => {
            failure.summary = format!("{}; cleanup failed: {cleanup}", failure.summary);
            ProcessRunError::EnvironmentFailure {
                label,
                command,
                failure,
                target_process_started,
            }
        }
        ProcessRunError::SetupTimeout {
            label,
            command,
            phase,
            source,
        } => ProcessRunError::SetupTimeout {
            label,
            command,
            phase,
            source: std::io::Error::other(format!("{source}; cleanup failed: {cleanup}")),
        },
        other => other,
    }
}

fn setup_timeout_error(
    label: &str,
    command: &str,
    phase: &'static str,
    detail: impl Into<String>,
) -> ProcessRunError {
    ProcessRunError::SetupTimeout {
        label: label.to_string(),
        command: command.to_string(),
        phase,
        source: std::io::Error::new(std::io::ErrorKind::TimedOut, detail.into()),
    }
}

fn containment_setup_error(
    label: String,
    command: String,
    source: std::io::Error,
) -> ProcessRunError {
    if let Some((failure, target_process_started)) = environment_failure_from_source(&source) {
        return ProcessRunError::EnvironmentFailure {
            label,
            command,
            failure: Box::new(failure),
            target_process_started,
        };
    }
    ProcessRunError::ContainmentUnavailable {
        label,
        command,
        source,
    }
}

fn process_ownership_error(
    label: String,
    command: String,
    source: std::io::Error,
) -> ProcessRunError {
    if let Some((failure, target_process_started)) = environment_failure_from_source(&source) {
        return ProcessRunError::EnvironmentFailure {
            label,
            command,
            failure: Box::new(failure),
            target_process_started,
        };
    }
    ProcessRunError::ProcessOwnership {
        label,
        command,
        source,
    }
}

fn environment_failure_from_source(source: &std::io::Error) -> Option<(EnvironmentFailure, bool)> {
    #[cfg(target_os = "linux")]
    {
        return source
            .get_ref()
            .and_then(|source| source.downcast_ref::<EnvironmentFailureSource>())
            .map(|source| (source.failure.clone(), source.target_process_started));
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = source;
        None
    }
}

#[cfg(test)]
pub(crate) fn is_verified_backend_unavailable(error: &ProcessRunError) -> bool {
    match error {
        ProcessRunError::ProcessOwnership { .. } => {
            let message = error.to_string();
            [
                "inaccessible path remained",
                "inaccessible path placeholder",
                "could not inspect inaccessible-path",
            ]
            .iter()
            .any(|diagnostic| message.contains(diagnostic))
        }
        _ => false,
    }
}

fn ensure_setup_budget(
    deadline: Option<Instant>,
    label: &str,
    command: &str,
    phase: &'static str,
) -> Result<(), ProcessRunError> {
    if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
        Err(setup_timeout_error(
            label,
            command,
            phase,
            "the total operation deadline was exhausted before command release",
        ))
    } else {
        Ok(())
    }
}

fn cleanup_after_wait_error(
    child: &mut Child,
    process_tree: &mut ProcessTree,
    label: &str,
    mut output_drainers: OutputDrainers,
    mut input_writer: InputWriter,
) -> ProcessFailureEvidence {
    let cleanup = process_tree.cleanup(child, false, label, "wait-error cleanup");
    let process_tree = cleanup.process_tree;
    let side_effects = cleanup.side_effects;
    let mut process_error = cleanup.error;
    process_error = append_error(
        process_error,
        wait_for_child_cleanup(child, label, "error cleanup"),
    );
    finish_child_io(
        label,
        "during wait-error cleanup",
        &mut output_drainers,
        &mut input_writer,
        &mut process_error,
    );
    let (stdout, stderr, output_error) = output_drainers.into_outputs();
    process_error = append_error(process_error, output_error);
    let (stdin_error, input_cleanup_error) = input_writer.into_result(label);
    process_error = append_error(process_error, input_cleanup_error);
    ProcessFailureEvidence {
        stdout,
        stderr,
        process_tree,
        side_effects,
        process_error,
        stdin_error,
    }
}

fn finish_child_io(
    label: &str,
    context: &str,
    output_drainers: &mut OutputDrainers,
    input_writer: &mut InputWriter,
    process_error: &mut Option<String>,
) {
    #[cfg(test)]
    let clock = TestIoFinalizationClock::default();
    #[cfg(not(test))]
    let clock = RealIoThreadClock;

    let output_deadline = clock.deadline_after(EXIT_AND_DRAIN_GRACE);
    if !output_drainers.finish_with_clock(&clock, &output_deadline) {
        *process_error = append_error(
            process_error.take(),
            Some(format!(
                "{label} output pipes did not close within {} ms {context}",
                EXIT_AND_DRAIN_GRACE.as_millis()
            )),
        );
        *process_error = append_error(
            process_error.take(),
            output_drainers.cancel_incomplete(label),
        );
    }
    let input_deadline = clock.deadline_after(EXIT_AND_DRAIN_GRACE);
    if !input_writer.finish_with_clock(&clock, &input_deadline) {
        *process_error = append_error(
            process_error.take(),
            Some(format!(
                "{label} stdin writer did not finish within {} ms {context}",
                EXIT_AND_DRAIN_GRACE.as_millis()
            )),
        );
        *process_error = append_error(process_error.take(), input_writer.cancel_incomplete(label));
    }
}

fn finish_output_drainers_after_exit(
    output_drainers: &mut OutputDrainers,
    grace: Duration,
) -> bool {
    #[cfg(test)]
    let clock = TestIoFinalizationClock::default();
    #[cfg(not(test))]
    let clock = RealIoThreadClock;

    let deadline = clock.deadline_after(grace);
    output_drainers.finish_with_clock(&clock, &deadline)
}

fn prepare_tees(
    label: &str,
    stdout: &StreamCapture,
    stderr: &StreamCapture,
    reject_existing: bool,
    operation_deadline: Option<Instant>,
    command: &str,
) -> Result<PreparedTees, ProcessRunError> {
    ensure_setup_budget(operation_deadline, label, command, "tee preflight")?;
    let stdout_tee_limit = stdout.max_tee_bytes;
    let stderr_tee_limit = stderr.max_tee_bytes;
    if let (Some(stdout), Some(stderr)) = (&stdout.tee_path, &stderr.tee_path) {
        if stdout == stderr {
            return Err(ProcessRunError::TeeConflict {
                label: label.to_string(),
                stdout: stdout.clone(),
                stderr: stderr.clone(),
            });
        }
    }

    let mut stdout = match stdout.tee_path.as_ref() {
        Some(path) => Some(preflight_tee(label, "stdout", path, reject_existing)?),
        None => None,
    };
    let mut stderr = match stderr.tee_path.as_ref() {
        Some(path) => match preflight_tee(label, "stderr", path, reject_existing) {
            Ok(tee) => Some(tee),
            Err(error) => {
                rollback_created_tee(stdout.take());
                return Err(error);
            }
        },
        None => None,
    };
    ensure_setup_budget(operation_deadline, label, command, "tee preflight")?;

    if let (Some(stdout_tee), Some(stderr_tee)) = (&stdout, &stderr) {
        let same_file = match tee_files_are_same(stdout_tee, stderr_tee) {
            Ok(same_file) => same_file,
            Err(source) => {
                let path = stdout_tee.path.clone();
                rollback_created_tee(stdout.take());
                rollback_created_tee(stderr.take());
                return Err(ProcessRunError::OpenTee {
                    label: label.to_string(),
                    stream: "stdout/stderr",
                    path,
                    source,
                });
            }
        };
        if same_file {
            let stdout_path = stdout_tee.path.clone();
            let stderr_path = stderr_tee.path.clone();
            rollback_created_tee(stdout.take());
            rollback_created_tee(stderr.take());
            return Err(ProcessRunError::TeeConflict {
                label: label.to_string(),
                stdout: stdout_path,
                stderr: stderr_path,
            });
        }
    }

    let stdout = match stdout.take() {
        Some(tee) => {
            let path = tee.path.clone();
            Some(PreparedTee::new(tee, stdout_tee_limit).map_err(|source| {
                ProcessRunError::OpenTee {
                    label: label.to_string(),
                    stream: "stdout",
                    path,
                    source,
                }
            })?)
        }
        None => None,
    };
    let stderr = match stderr.take() {
        Some(tee) => {
            let path = tee.path.clone();
            match PreparedTee::new(tee, stderr_tee_limit) {
                Ok(tee) => Some(tee),
                Err(source) => {
                    let mut transaction = PreparedTees {
                        stdout,
                        stderr: None,
                        finished: false,
                    };
                    let rollback = transaction.rollback().err();
                    return Err(ProcessRunError::OpenTee {
                        label: label.to_string(),
                        stream: "stderr",
                        path,
                        source: combine_tee_rollback_error(source, rollback),
                    });
                }
            }
        }
        None => None,
    };
    let mut transaction = PreparedTees {
        stdout,
        stderr,
        finished: false,
    };
    if let Err((stream, path, source)) = transaction.initialize() {
        let rollback = transaction.rollback().err();
        return Err(ProcessRunError::OpenTee {
            label: label.to_string(),
            stream,
            path,
            source: combine_tee_rollback_error(source, rollback),
        });
    }
    if let Err(error) =
        ensure_setup_budget(operation_deadline, label, command, "tee initialization")
    {
        let rollback = transaction.rollback().err();
        return Err(append_process_run_error_cleanup(
            error,
            rollback.map(|error| error.to_string()),
        ));
    }
    #[cfg(all(test, unix))]
    if let Some(pid_path) = env::var_os("MACO_TEST_TEE_HELPER_PID_FILE") {
        let pids = [&transaction.stdout, &transaction.stderr]
            .into_iter()
            .flatten()
            .filter_map(|tee| tee.writer.as_ref())
            .map(|writer| writer.helper.child.id().to_string())
            .collect::<Vec<_>>()
            .join("\n");
        if let Err(source) = fs::write(&pid_path, pids) {
            let rollback = transaction.rollback().err();
            return Err(ProcessRunError::OpenTee {
                label: label.to_string(),
                stream: "stdout/stderr",
                path: PathBuf::from(pid_path),
                source: combine_tee_rollback_error(source, rollback),
            });
        }
    }
    Ok(transaction)
}

fn combine_tee_rollback_error(
    source: std::io::Error,
    rollback: Option<std::io::Error>,
) -> std::io::Error {
    match rollback {
        Some(rollback) => std::io::Error::new(
            source.kind(),
            format!("{source}; tee transaction rollback failed: {rollback}"),
        ),
        None => source,
    }
}

struct TeePreflight {
    file: File,
    path: PathBuf,
    created: bool,
}

struct CreatedTeeGuard<'a> {
    file: &'a File,
    path: &'a Path,
    armed: bool,
}

impl CreatedTeeGuard<'_> {
    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for CreatedTeeGuard<'_> {
    fn drop(&mut self) {
        if self.armed && tee_path_matches_file(self.path, self.file).unwrap_or(false) {
            let _ = fs::remove_file(self.path);
        }
    }
}

struct PreparedTees {
    stdout: Option<PreparedTee>,
    stderr: Option<PreparedTee>,
    finished: bool,
}

impl PreparedTees {
    fn initialize(&mut self) -> Result<(), (&'static str, PathBuf, std::io::Error)> {
        for (stream, tee) in [
            ("stdout", self.stdout.as_mut()),
            ("stderr", self.stderr.as_mut()),
        ] {
            let Some(tee) = tee else {
                continue;
            };
            if let Err(source) = tee.start_helper(stream) {
                return Err((stream, tee.path.clone(), source));
            }
        }
        for (stream, tee) in [
            ("stdout", self.stdout.as_mut()),
            ("stderr", self.stderr.as_mut()),
        ] {
            let Some(tee) = tee else {
                continue;
            };
            if let Err(source) = tee.truncate(stream) {
                return Err((stream, tee.path.clone(), source));
            }
        }
        Ok(())
    }

    fn validate(&self, label: &str) -> Result<(), ProcessRunError> {
        for (stream, tee) in [
            ("stdout", self.stdout.as_ref()),
            ("stderr", self.stderr.as_ref()),
        ] {
            let Some(tee) = tee else {
                continue;
            };
            match tee.path_matches_file() {
                Ok(true) => {}
                Ok(false) => {
                    return Err(ProcessRunError::OpenTee {
                        label: label.to_string(),
                        stream,
                        path: tee.path.clone(),
                        source: std::io::Error::other(
                            "tee path identity changed before transaction commit",
                        ),
                    });
                }
                Err(source) => {
                    return Err(ProcessRunError::OpenTee {
                        label: label.to_string(),
                        stream,
                        path: tee.path.clone(),
                        source,
                    });
                }
            }
        }
        Ok(())
    }

    fn commit(mut self) -> (Option<TeeWriter>, Option<TeeWriter>) {
        self.finished = true;
        (
            self.stdout.as_mut().and_then(|tee| tee.writer.take()),
            self.stderr.as_mut().and_then(|tee| tee.writer.take()),
        )
    }

    fn rollback(&mut self) -> std::io::Result<()> {
        for tee in [&mut self.stdout, &mut self.stderr].into_iter().flatten() {
            drop(tee.writer.take());
        }
        let mut errors = Vec::new();
        for tee in [&mut self.stdout, &mut self.stderr].into_iter().flatten() {
            if let Err(error) = tee.rollback() {
                errors.push(format!("{}: {error}", tee.path.display()));
            }
        }
        self.finished = true;
        if errors.is_empty() {
            Ok(())
        } else {
            Err(std::io::Error::other(errors.join("; ")))
        }
    }
}

impl Drop for PreparedTees {
    fn drop(&mut self) {
        if !self.finished {
            if let Err(error) = self.rollback() {
                fail_closed_stuck_owner(&format!("tee transaction rollback: {error}"));
            }
        }
    }
}

struct PreparedTee {
    startup_file: Option<File>,
    rollback_file: Option<File>,
    writer: Option<TeeWriter>,
    backup: Option<TeeBackup>,
    path: PathBuf,
    created: bool,
    modified: bool,
    max_bytes: usize,
}

impl PreparedTee {
    fn new(tee: TeePreflight, max_bytes: usize) -> std::io::Result<Self> {
        if tee.file.metadata()?.len() > max_bytes as u64 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::FileTooLarge,
                format!(
                    "existing tee file exceeds the configured {max_bytes} byte transactional limit"
                ),
            ));
        }
        let backup = if tee.created {
            None
        } else {
            Some(TeeBackup::create(&tee.file, &tee.path)?)
        };
        let rollback_file = tee.file.try_clone()?;
        Ok(Self {
            startup_file: Some(tee.file),
            rollback_file: Some(rollback_file),
            writer: None,
            backup,
            path: tee.path,
            created: tee.created,
            modified: false,
            max_bytes,
        })
    }

    fn start_helper(&mut self, stream: &'static str) -> std::io::Result<()> {
        #[cfg(not(test))]
        let _ = stream;
        #[cfg(test)]
        if env::var_os("MACO_TEST_FAIL_TEE_HELPER_STREAM").as_deref() == Some(OsStr::new(stream)) {
            return Err(std::io::Error::other(format!(
                "synthetic {stream} tee helper startup failure"
            )));
        }
        if !self.path_matches_file()? {
            return Err(std::io::Error::other(
                "tee path identity changed before helper startup",
            ));
        }
        let file = self
            .startup_file
            .take()
            .ok_or_else(|| std::io::Error::other("tee helper file was already consumed"))?;
        self.writer = Some(TeeWriter::start(file, self.path.clone(), self.max_bytes)?);
        Ok(())
    }

    fn truncate(&mut self, stream: &'static str) -> std::io::Result<()> {
        #[cfg(not(test))]
        let _ = stream;
        #[cfg(test)]
        if env::var_os("MACO_TEST_FAIL_TEE_TRUNCATE_STREAM").as_deref() == Some(OsStr::new(stream))
        {
            return Err(std::io::Error::other(format!(
                "synthetic {stream} tee truncate failure"
            )));
        }
        if !self.path_matches_file()? {
            return Err(std::io::Error::other(
                "tee path identity changed before transactional truncate",
            ));
        }
        let file = self
            .rollback_file
            .as_mut()
            .ok_or_else(|| std::io::Error::other("tee rollback file was already closed"))?;
        file.set_len(0)?;
        self.modified = true;
        file.seek(SeekFrom::Start(0)).map(|_| ())
    }

    fn path_matches_file(&self) -> std::io::Result<bool> {
        let file = self
            .rollback_file
            .as_ref()
            .ok_or_else(|| std::io::Error::other("tee rollback file was already closed"))?;
        tee_path_matches_file(&self.path, file)
    }

    fn rollback(&mut self) -> std::io::Result<()> {
        let Some(mut file) = self.rollback_file.take() else {
            return Ok(());
        };
        if self.created {
            let matches = tee_path_matches_file(&self.path, &file).unwrap_or(false);
            drop(file);
            if matches {
                match fs::remove_file(&self.path) {
                    Ok(()) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error),
                }
            }
            return Ok(());
        }
        if !self.modified {
            return Ok(());
        }
        let backup = self
            .backup
            .as_ref()
            .ok_or_else(|| std::io::Error::other("existing tee omitted rollback backup"))?;
        backup.restore(&mut file)
    }
}

fn preflight_tee(
    label: &str,
    stream: &'static str,
    path: &Path,
    reject_existing: bool,
) -> Result<TeePreflight, ProcessRunError> {
    let mut create_options = OpenOptions::new();
    create_options.read(true).write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        create_options
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;
        create_options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let create_result = create_options.open(path);
    let (file, created) = match create_result {
        Ok(file) => (file, true),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            if reject_existing {
                return Err(ProcessRunError::OpenTee {
                    label: label.to_string(),
                    stream,
                    path: path.to_path_buf(),
                    source: std::io::Error::new(
                        std::io::ErrorKind::AlreadyExists,
                        "required confinement refuses an existing tee target",
                    ),
                });
            }
            let mut existing_options = OpenOptions::new();
            existing_options.read(true).write(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                existing_options
                    .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK);
            }
            #[cfg(target_os = "windows")]
            {
                use std::os::windows::fs::OpenOptionsExt;
                use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;
                existing_options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
            }
            let file = existing_options
                .open(path)
                .map_err(|source| ProcessRunError::OpenTee {
                    label: label.to_string(),
                    stream,
                    path: path.to_path_buf(),
                    source,
                })?;
            (file, false)
        }
        Err(source) => {
            return Err(ProcessRunError::OpenTee {
                label: label.to_string(),
                stream,
                path: path.to_path_buf(),
                source,
            });
        }
    };
    let mut created_guard = created.then(|| CreatedTeeGuard {
        file: &file,
        path,
        armed: true,
    });

    #[cfg(unix)]
    if created {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|source| ProcessRunError::OpenTee {
                label: label.to_string(),
                stream,
                path: path.to_path_buf(),
                source,
            })?;
    }
    #[cfg(test)]
    if created && env::var_os("MACO_TEST_FAIL_NEW_TEE_PREFLIGHT").is_some() {
        return Err(ProcessRunError::OpenTee {
            label: label.to_string(),
            stream,
            path: path.to_path_buf(),
            source: std::io::Error::other("synthetic new tee preflight failure"),
        });
    }
    let identity_matches =
        tee_path_matches_file(path, &file).map_err(|source| ProcessRunError::OpenTee {
            label: label.to_string(),
            stream,
            path: path.to_path_buf(),
            source,
        })?;
    if !identity_matches {
        return Err(ProcessRunError::OpenTee {
            label: label.to_string(),
            stream,
            path: path.to_path_buf(),
            source: std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "tee target must be a regular file and may not be a symlink",
            ),
        });
    }
    if let Some(guard) = created_guard.as_mut() {
        guard.disarm();
    }
    drop(created_guard);

    Ok(TeePreflight {
        file,
        path: path.to_path_buf(),
        created,
    })
}

fn rollback_created_tee(tee: Option<TeePreflight>) {
    let Some(tee) = tee else {
        return;
    };
    let created = tee.created;
    let path = tee.path.clone();
    let matches = created && tee_path_matches_file(&path, &tee.file).unwrap_or(false);
    drop(tee);
    if matches {
        let _ = fs::remove_file(path);
    }
}

#[cfg(unix)]
fn tee_path_matches_file(path: &Path, file: &File) -> std::io::Result<bool> {
    use std::os::unix::fs::MetadataExt;

    let path_metadata = fs::symlink_metadata(path)?;
    let file_metadata = file.metadata()?;
    Ok(path_metadata.file_type().is_file()
        && file_metadata.file_type().is_file()
        && path_metadata.dev() == file_metadata.dev()
        && path_metadata.ino() == file_metadata.ino())
}

#[cfg(target_os = "windows")]
fn tee_path_matches_file(path: &Path, file: &File) -> std::io::Result<bool> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT,
    };

    let path_file = OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    let path_identity = windows_file_identity(&path_file)?;
    let file_identity = windows_file_identity(file)?;
    Ok(path_identity.2 & FILE_ATTRIBUTE_REPARSE_POINT == 0
        && file_identity.2 & FILE_ATTRIBUTE_REPARSE_POINT == 0
        && path_identity.0 == file_identity.0
        && path_identity.1 == file_identity.1)
}

#[cfg(not(any(unix, target_os = "windows")))]
fn tee_path_matches_file(path: &Path, file: &File) -> std::io::Result<bool> {
    Ok(fs::symlink_metadata(path)?.file_type().is_file() && file.metadata()?.file_type().is_file())
}

#[cfg(unix)]
fn tee_files_are_same(left: &TeePreflight, right: &TeePreflight) -> std::io::Result<bool> {
    use std::os::unix::fs::MetadataExt;
    let left = left.file.metadata()?;
    let right = right.file.metadata()?;
    Ok(left.dev() == right.dev() && left.ino() == right.ino())
}

#[cfg(target_os = "windows")]
fn tee_files_are_same(left: &TeePreflight, right: &TeePreflight) -> std::io::Result<bool> {
    let left = windows_file_identity(&left.file)?;
    let right = windows_file_identity(&right.file)?;
    Ok(left.0 == right.0 && left.1 == right.1)
}

#[cfg(target_os = "windows")]
fn windows_file_identity(file: &File) -> std::io::Result<(u32, u64, u32)> {
    use std::{mem::MaybeUninit, os::windows::io::AsRawHandle};
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
    };

    let mut information = MaybeUninit::<BY_HANDLE_FILE_INFORMATION>::zeroed();
    // SAFETY: `information` points to writable storage and the borrowed file handle remains valid
    // for the duration of this call.
    if unsafe { GetFileInformationByHandle(file.as_raw_handle().cast(), information.as_mut_ptr()) }
        == 0
    {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: a successful call initialized the complete structure.
    let information = unsafe { information.assume_init() };
    let index =
        (u64::from(information.nFileIndexHigh) << 32) | u64::from(information.nFileIndexLow);
    Ok((
        information.dwVolumeSerialNumber,
        index,
        information.dwFileAttributes,
    ))
}

#[cfg(not(any(unix, target_os = "windows")))]
fn tee_files_are_same(left: &TeePreflight, right: &TeePreflight) -> std::io::Result<bool> {
    Ok(left.path.canonicalize()? == right.path.canonicalize()?)
}

struct TeeBackup {
    file: Option<File>,
    path: PathBuf,
}

impl TeeBackup {
    fn create(source_file: &File, source_path: &Path) -> std::io::Result<Self> {
        let mut source = source_file.try_clone()?;
        source.seek(SeekFrom::Start(0))?;
        for _ in 0..32 {
            let id = NEXT_TEE_BACKUP_ID.fetch_add(1, Ordering::Relaxed);
            let directory = source_path.parent().unwrap_or_else(|| Path::new("."));
            let path = directory.join(format!(".maco-tee-backup-{}-{id}.tmp", std::process::id()));
            let mut options = OpenOptions::new();
            options.read(true).write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options
                    .mode(0o600)
                    .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
            }
            match options.open(&path) {
                Ok(mut file) => {
                    let prepared = std::io::copy(&mut source, &mut file)
                        .and_then(|_| file.sync_all())
                        .and_then(|_| source.seek(SeekFrom::Start(0)))
                        .and_then(|_| file.seek(SeekFrom::Start(0)))
                        .map(|_| ());
                    if let Err(error) = prepared {
                        drop(file);
                        let _ = fs::remove_file(&path);
                        return Err(error);
                    }
                    return Ok(Self {
                        file: Some(file),
                        path,
                    });
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error),
            }
        }
        Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "failed to allocate a unique tee rollback file",
        ))
    }

    fn restore(&self, destination: &mut File) -> std::io::Result<()> {
        #[cfg(test)]
        if env::var_os("MACO_TEST_FAIL_TEE_RESTORE").is_some() {
            return Err(std::io::Error::other(
                "synthetic tee backup restore failure",
            ));
        }
        let mut source = self
            .file
            .as_ref()
            .ok_or_else(|| std::io::Error::other("tee rollback file was already closed"))?
            .try_clone()?;
        source.seek(SeekFrom::Start(0))?;
        destination.set_len(0)?;
        destination.seek(SeekFrom::Start(0))?;
        std::io::copy(&mut source, destination)?;
        destination.sync_all()?;
        destination.seek(SeekFrom::Start(0)).map(|_| ())
    }
}

impl Drop for TeeBackup {
    fn drop(&mut self) {
        drop(self.file.take());
        let _ = fs::remove_file(&self.path);
    }
}

struct TeeWriter {
    sink: TeeSink,
    #[cfg(unix)]
    helper: TeeHelper,
    path: PathBuf,
}

impl TeeWriter {
    fn start(file: File, path: PathBuf, max_bytes: usize) -> std::io::Result<Self> {
        #[cfg(unix)]
        {
            let (helper, input) = TeeHelper::start(file, &path)?;
            Ok(Self {
                sink: TeeSink {
                    input,
                    remaining: max_bytes,
                    limit_reported: false,
                },
                helper,
                path,
            })
        }

        #[cfg(not(unix))]
        {
            Ok(Self {
                sink: TeeSink {
                    file,
                    remaining: max_bytes,
                    limit_reported: false,
                },
                path,
            })
        }
    }

    fn split(self) -> (TeeSink, Option<TeeHelperHandle>, PathBuf) {
        #[cfg(unix)]
        {
            let helper = TeeHelperHandle(self.helper);
            (self.sink, Some(helper), self.path)
        }

        #[cfg(not(unix))]
        {
            (self.sink, None, self.path)
        }
    }
}

struct TeeSink {
    #[cfg(unix)]
    input: ChildStdin,
    #[cfg(not(unix))]
    file: File,
    remaining: usize,
    limit_reported: bool,
}

impl TeeSink {
    /// Returns `true` once when bytes were discarded because the configured tee cap was reached.
    fn write_all_cancellable(
        &mut self,
        bytes: &[u8],
        cancel: &AtomicBool,
    ) -> std::io::Result<bool> {
        let accepted = bytes.len().min(self.remaining);
        let bytes_to_write = &bytes[..accepted];
        self.remaining -= accepted;
        let exceeded = accepted < bytes.len() && !self.limit_reported;
        if exceeded {
            self.limit_reported = true;
        }
        #[cfg(unix)]
        {
            let mut written = 0;
            while written < bytes_to_write.len() {
                if cancel.load(Ordering::Acquire) {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Interrupted,
                        "tee write cancelled",
                    ));
                }
                match self.input.write(&bytes_to_write[written..]) {
                    Ok(0) => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::WriteZero,
                            "tee helper input returned a zero-length write",
                        ));
                    }
                    Ok(count) => written += count,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(IO_CANCEL_POLL_INTERVAL);
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(error) => return Err(error),
                }
            }
            Ok(exceeded)
        }

        #[cfg(not(unix))]
        {
            self.file.write_all(bytes_to_write).map(|()| exceeded)
        }
    }
}

struct TeeHelperHandle(#[cfg(unix)] TeeHelper, #[cfg(not(unix))] ());

impl TeeHelperHandle {
    fn finish(self, label: &str, stream: &str) -> Option<String> {
        #[cfg(unix)]
        {
            self.0.finish(label, stream)
        }
        #[cfg(not(unix))]
        {
            let _ = (self, label, stream);
            None
        }
    }
}

#[cfg(unix)]
struct TeeHelper {
    child: Child,
    path: PathBuf,
    reaped: bool,
}

#[cfg(unix)]
impl TeeHelper {
    fn start(file: File, path: &Path) -> std::io::Result<(Self, ChildStdin)> {
        use std::os::unix::process::CommandExt;

        let cat = find_trusted_unix_executable(
            "cat",
            &["/bin/cat", "/usr/bin/cat", "/run/current-system/sw/bin/cat"],
        )
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "tee capture requires a root-owned, non-writable cat helper",
            )
        })?;
        let mut command = Command::new(cat);
        command
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::from(file))
            .stderr(Stdio::null())
            .process_group(0);
        let mut child = command.spawn()?;
        let input = match child.stdin.take() {
            Some(input) => input,
            None => {
                let cleanup = rollback_tee_helper_start(&mut child, path);
                return Err(std::io::Error::other(format!(
                    "failed to open tee helper stdin{cleanup}"
                )));
            }
        };
        if let Err(error) = configure_cancellable_io(&input) {
            drop(input);
            let cleanup = rollback_tee_helper_start(&mut child, path);
            return Err(std::io::Error::new(
                error.kind(),
                format!("failed to configure tee helper stdin: {error}{cleanup}"),
            ));
        }
        Ok((
            Self {
                child,
                path: path.to_path_buf(),
                reaped: false,
            },
            input,
        ))
    }

    fn finish(mut self, label: &str, stream: &str) -> Option<String> {
        let deadline = Instant::now() + EXIT_AND_DRAIN_GRACE;
        let mut error = None;
        let status = match wait_for_exit_until(&mut self.child, deadline) {
            Ok(Some(status)) => Some(status),
            Ok(None) => {
                error = Some(format!(
                    "{label} {stream} tee helper for {} did not finish within {} ms",
                    self.path.display(),
                    EXIT_AND_DRAIN_GRACE.as_millis()
                ));
                error = append_error(
                    error,
                    terminate_unix_process_group(&mut self.child, false, label),
                );
                match wait_for_exit_until(&mut self.child, Instant::now() + EXIT_AND_DRAIN_GRACE) {
                    Ok(Some(status)) => Some(status),
                    Ok(None) => fail_closed_stuck_owner(&format!(
                        "{label} {stream} tee helper for {}",
                        self.path.display()
                    )),
                    Err(wait_error) => {
                        error = append_error(
                            error,
                            Some(format!("failed to reap tee helper: {wait_error}")),
                        );
                        match self.child.try_wait() {
                            Ok(Some(status)) => Some(status),
                            _ => fail_closed_stuck_owner(&format!(
                                "{label} {stream} tee helper for {}",
                                self.path.display()
                            )),
                        }
                    }
                }
            }
            Err(wait_error) => {
                error = Some(format!("failed to wait for tee helper: {wait_error}"));
                let _ = terminate_unix_process_group(&mut self.child, false, label);
                match wait_for_exit_until(&mut self.child, Instant::now() + EXIT_AND_DRAIN_GRACE) {
                    Ok(Some(status)) => Some(status),
                    _ => fail_closed_stuck_owner(&format!(
                        "{label} {stream} tee helper for {}",
                        self.path.display()
                    )),
                }
            }
        };
        self.reaped = true;
        if status.is_some_and(|status| !status.success()) {
            error = append_error(
                error,
                Some(format!(
                    "{label} {stream} tee helper for {} exited unsuccessfully",
                    self.path.display()
                )),
            );
        }
        error
    }
}

#[cfg(unix)]
fn rollback_tee_helper_start(child: &mut Child, path: &Path) -> String {
    let error = terminate_unix_process_group(child, false, "tee helper startup rollback");
    match wait_for_exit_until(child, Instant::now() + EXIT_AND_DRAIN_GRACE) {
        Ok(Some(_)) => error
            .map(|error| format!("; cleanup diagnostic: {error}"))
            .unwrap_or_default(),
        Ok(None) => fail_closed_stuck_owner(&format!(
            "tee helper for {} during startup rollback",
            path.display()
        )),
        Err(wait_error) => match child.try_wait() {
            Ok(Some(_)) => format!("; cleanup wait diagnostic: {wait_error}"),
            _ => fail_closed_stuck_owner(&format!(
                "tee helper for {} during startup rollback",
                path.display()
            )),
        },
    }
}

#[cfg(unix)]
impl Drop for TeeHelper {
    fn drop(&mut self) {
        if self.reaped {
            return;
        }
        if !matches!(self.child.try_wait(), Ok(Some(_))) {
            let _ = terminate_unix_process_group(&mut self.child, false, "tee helper drop");
            if !matches!(
                wait_for_exit_until(&mut self.child, Instant::now() + EXIT_AND_DRAIN_GRACE),
                Ok(Some(_))
            ) {
                fail_closed_stuck_owner(&format!(
                    "tee helper for {} during drop",
                    self.path.display()
                ));
            }
        }
        self.reaped = true;
    }
}

fn fail_closed_stuck_owner(label: &str) -> ! {
    eprintln!(
        "fatal: {label} remained live past its bounded cleanup deadline; aborting rather than detaching owned execution"
    );
    std::process::abort()
}

fn stamp_agent_lifecycle_environment(
    environment: &mut EnvironmentMode,
    metadata: &AgentLaunchMetadata,
) {
    if matches!(environment, EnvironmentMode::Inherit) {
        *environment = EnvironmentMode::InheritAndSet(BTreeMap::new());
    }
    let values = match environment {
        EnvironmentMode::InheritAndSet(values) | EnvironmentMode::ClearAndSet(values) => values,
        EnvironmentMode::Inherit => return,
    };
    values.insert(MACO_RUN_ID_ENV.to_string(), metadata.run_id().to_string());
    values.insert(MACO_TASK_ID_ENV.to_string(), metadata.task_id().to_string());
}

fn configure_environment(command: &mut Command, environment: &EnvironmentMode) {
    match environment {
        EnvironmentMode::Inherit => {}
        EnvironmentMode::InheritAndSet(values) => {
            command.envs(values);
        }
        EnvironmentMode::ClearAndSet(values) => {
            command.env_clear().envs(values);
        }
    }
}

fn configure_stdin(command: &mut Command, stdin: &StdinMode) {
    match stdin {
        StdinMode::Inherit => {
            command.stdin(Stdio::inherit());
        }
        StdinMode::Null => {
            command.stdin(Stdio::null());
        }
        StdinMode::Bytes(_) | StdinMode::Interactive => {
            command.stdin(Stdio::piped());
        }
    }
}

#[cfg(target_os = "windows")]
const WINDOWS_PROCESS_CREATION_FLAGS: u32 = 0x0000_0200 | 0x0000_0004;

struct PreparedProcessTree {
    backend: PreparedContainmentBackend,
    side_effects: SideEffectConfinementEvidence,
}

enum PreparedContainmentBackend {
    #[cfg(target_os = "linux")]
    Systemd(Box<SystemdUnit>),
    #[cfg(target_os = "windows")]
    WindowsJob,
    #[cfg(unix)]
    UnixProcessGroup,
    #[cfg(not(any(unix, target_os = "windows")))]
    DirectChild,
}

impl PreparedProcessTree {
    fn prepare(
        policy: ContainmentPolicy,
        side_effect_profile: &SideEffectConfinementProfile,
        label: &str,
        command: &str,
        operation_deadline: Option<Instant>,
        cancellation: &ProcessCancellation,
    ) -> Result<Self, ProcessRunError> {
        let unavailable = |source| ProcessRunError::ContainmentUnavailable {
            label: label.to_string(),
            command: command.to_string(),
            source,
        };
        if policy == ContainmentPolicy::TrustedBestEffort
            && !matches!(
                side_effect_profile,
                SideEffectConfinementProfile::TrustedCompatibility
            )
        {
            return Err(unavailable(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "TrustedBestEffort process ownership cannot claim a strict side-effect profile",
            )));
        }
        let side_effects = if matches!(
            side_effect_profile,
            SideEffectConfinementProfile::TrustedCompatibility
        ) {
            SideEffectConfinementEvidence::TrustedBestEffort(
                SideEffectConfinementProfileKind::TrustedCompatibility,
            )
        } else {
            SideEffectConfinementEvidence::Unverified(side_effect_profile.kind())
        };
        ensure_not_cancelled(cancellation, label, command, "containment slot acquisition")?;
        match policy {
            ContainmentPolicy::Required => {
                #[cfg(target_os = "linux")]
                {
                    match SystemdUnit::prepare(operation_deadline, cancellation) {
                        Ok(unit) => Ok(Self {
                            backend: PreparedContainmentBackend::Systemd(Box::new(unit)),
                            side_effects,
                        }),
                        Err(_source) if cancellation.is_cancelled() => {
                            Err(ProcessRunError::Cancelled {
                                label: label.to_string(),
                                command: command.to_string(),
                                phase: "containment slot acquisition",
                                evidence: None,
                            })
                        }
                        Err(source)
                            if operation_deadline
                                .is_some_and(|deadline| Instant::now() >= deadline) =>
                        {
                            Err(setup_timeout_error(
                                label,
                                command,
                                "strict containment slot acquisition",
                                source.to_string(),
                            ))
                        }
                        Err(source) => Err(unavailable(source)),
                    }
                }
                #[cfg(target_os = "windows")]
                {
                    if !matches!(
                        side_effect_profile,
                        SideEffectConfinementProfile::TrustedCompatibility
                    ) {
                        return Err(unavailable(std::io::Error::new(
                            std::io::ErrorKind::Unsupported,
                            "verified side-effect confinement is not implemented for Windows; use explicit trusted compatibility only for trusted commands",
                        )));
                    }
                    return Ok(Self {
                        backend: PreparedContainmentBackend::WindowsJob,
                        side_effects,
                    });
                }
                #[cfg(all(unix, not(target_os = "linux")))]
                {
                    return Err(unavailable(std::io::Error::new(
                        std::io::ErrorKind::Unsupported,
                        "no verified subtree-containment backend is implemented on this Unix platform; use TrustedBestEffort only for trusted commands",
                    )));
                }
                #[cfg(not(any(unix, target_os = "windows")))]
                {
                    return Err(unavailable(std::io::Error::new(
                        std::io::ErrorKind::Unsupported,
                        "no verified subtree-containment backend is implemented on this platform",
                    )));
                }
            }
            ContainmentPolicy::TrustedBestEffort => {
                #[cfg(unix)]
                {
                    Ok(Self {
                        backend: PreparedContainmentBackend::UnixProcessGroup,
                        side_effects,
                    })
                }
                #[cfg(target_os = "windows")]
                {
                    Ok(Self {
                        backend: PreparedContainmentBackend::WindowsJob,
                        side_effects,
                    })
                }
                #[cfg(not(any(unix, target_os = "windows")))]
                {
                    Ok(Self {
                        backend: PreparedContainmentBackend::DirectChild,
                        side_effects,
                    })
                }
            }
        }
    }

    fn build_command(&mut self, spec: &ProcessSpec) -> std::io::Result<Command> {
        match &mut self.backend {
            #[cfg(target_os = "linux")]
            PreparedContainmentBackend::Systemd(unit) => unit.build_command(spec),
            #[cfg(target_os = "windows")]
            PreparedContainmentBackend::WindowsJob => {
                if spec.private_runtime_home || spec.private_runtime_codex_home {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Unsupported,
                        "private runtime HOME requires the strict Linux systemd backend",
                    ));
                }
                use std::os::windows::process::CommandExt;
                let mut command = spec.command.build();
                command.creation_flags(WINDOWS_PROCESS_CREATION_FLAGS);
                command.current_dir(&spec.current_dir);
                configure_environment(&mut command, &spec.environment);
                Ok(command)
            }
            #[cfg(unix)]
            PreparedContainmentBackend::UnixProcessGroup => {
                if spec.private_runtime_home || spec.private_runtime_codex_home {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Unsupported,
                        "private runtime HOME requires the strict Linux systemd backend",
                    ));
                }
                use std::os::unix::process::CommandExt;
                let mut command = spec.command.build();
                command.process_group(0);
                command.current_dir(&spec.current_dir);
                configure_environment(&mut command, &spec.environment);
                Ok(command)
            }
            #[cfg(not(any(unix, target_os = "windows")))]
            PreparedContainmentBackend::DirectChild => {
                if spec.private_runtime_home || spec.private_runtime_codex_home {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Unsupported,
                        "private runtime HOME requires the strict Linux systemd backend",
                    ));
                }
                let mut command = spec.command.build();
                command.current_dir(&spec.current_dir);
                configure_environment(&mut command, &spec.environment);
                Ok(command)
            }
        }
    }

    fn attach(
        self,
        child: &mut Child,
        label: &str,
        command: &str,
        operation_deadline: Option<Instant>,
        cancellation: &ProcessCancellation,
    ) -> Result<AttachedProcessTree, ProcessRunError> {
        match self.backend {
            #[cfg(target_os = "linux")]
            PreparedContainmentBackend::Systemd(mut unit) => {
                unit.launcher_spawned = true;
                if let Err(source) = unit.confirm_attached(child, operation_deadline, cancellation)
                {
                    if let Err(error) = unit.rollback_startup(label) {
                        fail_closed_stuck_owner(&format!(
                            "{label} systemd containment startup rollback: {error}"
                        ));
                    }
                    return if cancellation.is_cancelled() {
                        Err(ProcessRunError::Cancelled {
                            label: label.to_string(),
                            command: command.to_string(),
                            phase: "strict containment attachment gate",
                            evidence: Some(Box::new(ProcessFailureEvidence {
                                stdout: CapturedBytes::default(),
                                stderr: CapturedBytes::default(),
                                process_tree: ProcessTreeEvidence::VerifiedEmpty(
                                    ContainmentBackend::SystemdUserService,
                                ),
                                side_effects: self.side_effects,
                                process_error: Some(format!(
                                    "{label} was cancelled by its run supervisor"
                                )),
                                stdin_error: None,
                            })),
                        })
                    } else if environment_failure_from_source(&source).is_some() {
                        Err(process_ownership_error(
                            label.to_string(),
                            command.to_string(),
                            source,
                        ))
                    } else if operation_deadline.is_some_and(|deadline| Instant::now() >= deadline)
                    {
                        Err(setup_timeout_error(
                            label,
                            command,
                            "strict containment start gate",
                            source.to_string(),
                        ))
                    } else {
                        Err(process_ownership_error(
                            label.to_string(),
                            command.to_string(),
                            source,
                        ))
                    };
                }
                let side_effects = unit.side_effect_evidence();
                Ok(AttachedProcessTree {
                    backend: ProcessTreeBackend::Systemd(unit),
                    side_effects,
                })
            }
            #[cfg(target_os = "windows")]
            PreparedContainmentBackend::WindowsJob => {
                let job = WindowsJob::create_and_assign(child).map_err(|source| {
                    ProcessRunError::ProcessOwnership {
                        label: label.to_string(),
                        command: command.to_string(),
                        source,
                    }
                })?;
                Ok(AttachedProcessTree {
                    backend: ProcessTreeBackend::WindowsJob(job),
                    side_effects: self.side_effects,
                })
            }
            #[cfg(unix)]
            PreparedContainmentBackend::UnixProcessGroup => Ok(AttachedProcessTree {
                backend: ProcessTreeBackend::UnixProcessGroup,
                side_effects: self.side_effects,
            }),
            #[cfg(not(any(unix, target_os = "windows")))]
            PreparedContainmentBackend::DirectChild => Ok(AttachedProcessTree {
                backend: ProcessTreeBackend::DirectChild,
                side_effects: self.side_effects,
            }),
        }
    }
}

struct AttachedProcessTree {
    backend: ProcessTreeBackend,
    side_effects: SideEffectConfinementEvidence,
}

impl AttachedProcessTree {
    fn agent_lifecycle_pid(
        &mut self,
        child: &mut Child,
        operation_deadline: Option<Instant>,
        cancellation: &ProcessCancellation,
    ) -> std::io::Result<u32> {
        if cancellation.is_cancelled() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Interrupted,
                "agent lifecycle PID capture was cancelled",
            ));
        }
        match &mut self.backend {
            #[cfg(target_os = "linux")]
            ProcessTreeBackend::Systemd(unit) => {
                unit.target_pid(child, operation_deadline, cancellation)
            }
            #[cfg(unix)]
            ProcessTreeBackend::UnixProcessGroup => Ok(child.id()),
            #[cfg(target_os = "windows")]
            ProcessTreeBackend::WindowsJob(_) => Ok(child.id()),
            #[cfg(not(any(unix, target_os = "windows")))]
            ProcessTreeBackend::DirectChild => Ok(child.id()),
        }
    }

    fn cleanup(&mut self, child: &mut Child, label: &str, context: &str) -> TreeCleanup {
        cleanup_process_tree_backend(
            &mut self.backend,
            self.side_effects,
            child,
            false,
            label,
            context,
        )
    }

    fn release(
        mut self,
        child: &mut Child,
        label: &str,
        command: &str,
        operation_deadline: Option<Instant>,
        cancellation: &ProcessCancellation,
    ) -> Result<ProcessTree, ProcessRunError> {
        if cancellation.is_cancelled() {
            let cleanup = self.cleanup(child, label, "containment start-gate cancellation");
            return Err(ProcessRunError::Cancelled {
                label: label.to_string(),
                command: command.to_string(),
                phase: "containment start gate",
                evidence: Some(Box::new(ProcessFailureEvidence {
                    stdout: CapturedBytes::default(),
                    stderr: CapturedBytes::default(),
                    process_tree: cleanup.process_tree,
                    side_effects: cleanup.side_effects,
                    process_error: append_error(
                        Some(format!("{label} was cancelled by its run supervisor")),
                        cleanup.error,
                    ),
                    stdin_error: None,
                })),
            });
        }
        match &mut self.backend {
            #[cfg(target_os = "linux")]
            ProcessTreeBackend::Systemd(unit) => {
                if let Err(source) =
                    unit.release_start_gate(child, operation_deadline, cancellation)
                {
                    if let Err(error) = unit.rollback_startup(label) {
                        fail_closed_stuck_owner(&format!(
                            "{label} systemd containment start-gate rollback: {error}"
                        ));
                    }
                    return if cancellation.is_cancelled() {
                        Err(ProcessRunError::Cancelled {
                            label: label.to_string(),
                            command: command.to_string(),
                            phase: "strict containment start gate",
                            evidence: Some(Box::new(ProcessFailureEvidence {
                                stdout: CapturedBytes::default(),
                                stderr: CapturedBytes::default(),
                                process_tree: ProcessTreeEvidence::VerifiedEmpty(
                                    ContainmentBackend::SystemdUserService,
                                ),
                                side_effects: self.side_effects,
                                process_error: Some(format!(
                                    "{label} was cancelled by its run supervisor"
                                )),
                                stdin_error: None,
                            })),
                        })
                    } else if environment_failure_from_source(&source).is_some() {
                        Err(process_ownership_error(
                            label.to_string(),
                            command.to_string(),
                            source,
                        ))
                    } else if operation_deadline.is_some_and(|deadline| Instant::now() >= deadline)
                    {
                        Err(setup_timeout_error(
                            label,
                            command,
                            "strict containment start gate",
                            source.to_string(),
                        ))
                    } else {
                        Err(process_ownership_error(
                            label.to_string(),
                            command.to_string(),
                            source,
                        ))
                    };
                }
            }
            #[cfg(target_os = "windows")]
            ProcessTreeBackend::WindowsJob(job) => {
                if operation_deadline.is_some_and(|deadline| Instant::now() >= deadline) {
                    let cleanup = job.cleanup(label, "startup timeout rollback", self.side_effects);
                    if cleanup.error.is_some() || !cleanup.process_tree.is_verified_empty() {
                        fail_closed_stuck_owner(&format!(
                            "{label} Windows Job Object startup-timeout rollback: {}",
                            cleanup.error.unwrap_or_else(|| {
                                "job did not report verified-empty containment".to_string()
                            })
                        ));
                    }
                    return Err(setup_timeout_error(
                        label,
                        command,
                        "Windows Job Object attachment",
                        "the total operation deadline expired before the suspended child was resumed",
                    ));
                }
                if let Err(source) = resume_suspended_child(child) {
                    let cleanup = job.cleanup(label, "startup rollback", self.side_effects);
                    if cleanup.error.is_some() || !cleanup.process_tree.is_verified_empty() {
                        fail_closed_stuck_owner(&format!(
                            "{label} Windows Job Object resume rollback: {}",
                            cleanup.error.unwrap_or_else(|| {
                                "job did not report verified-empty containment".to_string()
                            })
                        ));
                    }
                    return Err(ProcessRunError::ProcessOwnership {
                        label: label.to_string(),
                        command: command.to_string(),
                        source,
                    });
                }
            }
            #[cfg(unix)]
            ProcessTreeBackend::UnixProcessGroup => {}
            #[cfg(not(any(unix, target_os = "windows")))]
            ProcessTreeBackend::DirectChild => {}
        }
        Ok(ProcessTree {
            backend: self.backend,
            side_effects: self.side_effects,
        })
    }
}

struct ProcessTree {
    backend: ProcessTreeBackend,
    side_effects: SideEffectConfinementEvidence,
}

enum ProcessTreeBackend {
    #[cfg(target_os = "linux")]
    Systemd(Box<SystemdUnit>),
    #[cfg(target_os = "windows")]
    WindowsJob(WindowsJob),
    #[cfg(unix)]
    UnixProcessGroup,
    #[cfg(not(any(unix, target_os = "windows")))]
    DirectChild,
}

struct TreeCleanup {
    error: Option<String>,
    process_tree: ProcessTreeEvidence,
    side_effects: SideEffectConfinementEvidence,
}

impl ProcessTree {
    fn cleanup(
        &mut self,
        child: &mut Child,
        child_already_exited: bool,
        label: &str,
        context: &str,
    ) -> TreeCleanup {
        cleanup_process_tree_backend(
            &mut self.backend,
            self.side_effects,
            child,
            child_already_exited,
            label,
            context,
        )
    }
}

fn cleanup_process_tree_backend(
    backend: &mut ProcessTreeBackend,
    side_effects: SideEffectConfinementEvidence,
    child: &mut Child,
    child_already_exited: bool,
    label: &str,
    context: &str,
) -> TreeCleanup {
    match backend {
        #[cfg(target_os = "linux")]
        ProcessTreeBackend::Systemd(unit) => {
            let mut cleanup = unit.cleanup(child, label, context);
            cleanup.side_effects = side_effects;
            cleanup
        }
        #[cfg(target_os = "windows")]
        ProcessTreeBackend::WindowsJob(job) => job.cleanup(label, context, side_effects),
        #[cfg(unix)]
        ProcessTreeBackend::UnixProcessGroup => TreeCleanup {
            error: terminate_unix_process_group(child, child_already_exited, label),
            process_tree: ProcessTreeEvidence::TrustedBestEffort(
                ContainmentBackend::UnixProcessGroup,
            ),
            side_effects,
        },
        #[cfg(not(any(unix, target_os = "windows")))]
        ProcessTreeBackend::DirectChild => TreeCleanup {
            error: if child_already_exited {
                None
            } else {
                child
                    .kill()
                    .err()
                    .map(|error| format!("{label} {context} direct process kill failed: {error}"))
            },
            process_tree: ProcessTreeEvidence::TrustedBestEffort(ContainmentBackend::DirectChild),
            side_effects,
        },
    }
}

#[cfg(target_os = "linux")]
struct ResolvedSystemdSandbox {
    kind: SideEffectConfinementProfileKind,
    workspace_root: PathBuf,
    current_dir: PathBuf,
    workspace_access: WorkspaceAccess,
    visible_read_only_roots: Vec<PathBuf>,
    visible_read_only_files: Vec<PathBuf>,
    visible_read_write_roots: Vec<PathBuf>,
    visible_read_write_files: Vec<PathBuf>,
    external_codex_writable_file_capabilities: Vec<ExternalCodexWritableFileCapability>,
    writable_artifact_roots: Vec<PathBuf>,
    hidden_roots: Vec<PathBuf>,
    isolated_host_view: bool,
    resource_limits: ProcessResourceLimits,
    path_identities: Vec<SandboxPathIdentity>,
    mount_checks: Vec<SandboxMountCheck>,
}

#[cfg(target_os = "linux")]
#[derive(Debug)]
struct EnvironmentFailureSource {
    failure: EnvironmentFailure,
    target_process_started: bool,
}

#[cfg(target_os = "linux")]
impl fmt::Display for EnvironmentFailureSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.failure, formatter)
    }
}

#[cfg(target_os = "linux")]
impl std::error::Error for EnvironmentFailureSource {}

#[cfg(target_os = "linux")]
fn environment_failure_io(
    failure: EnvironmentFailure,
    target_process_started: bool,
) -> std::io::Error {
    std::io::Error::other(EnvironmentFailureSource {
        failure,
        target_process_started,
    })
}

#[cfg(target_os = "linux")]
struct SandboxPathIdentity {
    path: PathBuf,
    device: u64,
    inode: u64,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum SandboxMountAccess {
    ReadOnly,
    ReadWrite,
    PrivateRuntime,
    Inaccessible,
    IsolatedRoot,
}

#[cfg(target_os = "linux")]
struct SandboxMountCheck {
    path: PathBuf,
    device: u64,
    inode: u64,
    access: SandboxMountAccess,
    optional: bool,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, PartialEq, Eq)]
struct SandboxMountInfo {
    mount_id: u64,
    device_major: u64,
    device_minor: u64,
    root: PathBuf,
    mount_point: PathBuf,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, PartialEq, Eq)]
struct SandboxMountRegion {
    visible_path: PathBuf,
    device_major: u64,
    device_minor: u64,
    backing_path: PathBuf,
    access: SandboxMountAccess,
}

#[cfg(target_os = "linux")]
impl ResolvedSystemdSandbox {
    fn validate_program_visibility(&self, program: &Path) -> std::io::Result<()> {
        validate_systemd_program_visibility(program, &self.hidden_roots)
    }

    fn add_isolated_runtime_file(&mut self, file: &Path) -> std::io::Result<()> {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        if !self.isolated_host_view {
            return Ok(());
        }
        validate_systemd_path_syntax(file, "isolated runtime helper")?;
        let canonical = fs::canonicalize(file)?;
        if !canonical.starts_with("/nix/store") {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "isolated reviewer runtime helper is outside /nix/store",
            ));
        }
        let metadata = fs::metadata(file)?;
        if !metadata.is_file()
            || metadata.uid() != 0
            || metadata.permissions().mode() & 0o111 == 0
            || metadata.permissions().mode() & 0o022 != 0
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "isolated reviewer runtime helper is not a trusted executable",
            ));
        }
        if self
            .hidden_roots
            .iter()
            .any(|hidden| file.starts_with(hidden) || hidden.starts_with(file))
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "isolated reviewer runtime helper overlaps an inaccessible root",
            ));
        }
        if self.visible_read_only_files.contains(&file.to_path_buf()) {
            return Ok(());
        }
        self.visible_read_only_files.push(file.to_path_buf());
        self.visible_read_only_files.sort();
        self.path_identities
            .push(capture_sandbox_path_identity(&canonical)?);
        self.mount_checks.push(SandboxMountCheck {
            path: file.to_path_buf(),
            device: metadata.dev(),
            inode: metadata.ino(),
            access: SandboxMountAccess::ReadOnly,
            optional: false,
        });
        if self.visible_read_only_files.len() > MAX_SANDBOX_PATHS_PER_CLASS
            || self.mount_checks.len() > MAX_SANDBOX_MOUNT_CHECKS
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "isolated reviewer runtime helper vector exceeds its safety bound",
            ));
        }
        Ok(())
    }

    fn add_private_runtime_root(&mut self, root: &Path) -> std::io::Result<()> {
        validate_systemd_path_syntax(root, "private unit runtime root")?;
        if !root.is_absolute() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "private unit runtime root must be absolute",
            ));
        }
        if self
            .hidden_roots
            .iter()
            .any(|hidden| root.starts_with(hidden) || hidden.starts_with(root))
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "private unit runtime root overlaps an inaccessible sandbox root",
            ));
        }
        self.mount_checks.push(SandboxMountCheck {
            path: root.to_path_buf(),
            device: 0,
            inode: 0,
            access: SandboxMountAccess::PrivateRuntime,
            optional: false,
        });
        if self.mount_checks.len() > MAX_SANDBOX_MOUNT_CHECKS {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "sandbox mount-check vector exceeds its safety bound",
            ));
        }
        Ok(())
    }

    fn verify_path_identities(&self) -> std::io::Result<()> {
        use std::os::unix::fs::MetadataExt;

        for capability in &self.external_codex_writable_file_capabilities {
            capability.verify_path()?;
        }
        for identity in &self.path_identities {
            let metadata = fs::symlink_metadata(&identity.path)?;
            if metadata.file_type().is_symlink()
                || metadata.dev() != identity.device
                || metadata.ino() != identity.inode
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    format!(
                        "sandbox path identity changed before target release: {}",
                        identity.path.display()
                    ),
                ));
            }
        }
        self.verify_no_special_entries()?;
        Ok(())
    }

    fn verify_no_special_entries(&self) -> std::io::Result<()> {
        self.verify_mount_alias_conflicts()?;
        let mut roots = vec![(
            self.workspace_root.clone(),
            self.workspace_access == WorkspaceAccess::ReadWrite,
        )];
        roots.extend(
            self.visible_read_write_roots
                .iter()
                .cloned()
                .map(|root| (root, true)),
        );
        roots.extend(
            self.writable_artifact_roots
                .iter()
                .cloned()
                .map(|root| (root, true)),
        );
        roots.sort_by(|left, right| left.0.cmp(&right.0));
        roots.dedup_by(|left, right| {
            if left.0 == right.0 {
                left.1 |= right.1;
                true
            } else {
                false
            }
        });
        let mut minimal_roots: Vec<(PathBuf, bool)> = Vec::new();
        for (root, writable) in roots {
            if let Some((_, ancestor_writable)) = minimal_roots
                .iter()
                .find(|(ancestor, _)| root.starts_with(ancestor))
            {
                if *ancestor_writable || !writable {
                    continue;
                }
            }
            minimal_roots.push((root, writable));
        }
        let mut remaining = MAX_SANDBOX_ENTRY_SCAN;
        let mut writable_links: BTreeMap<(u64, u64), (u64, u64, PathBuf)> = BTreeMap::new();
        for (root, writable) in minimal_roots {
            scan_sandbox_tree(&root, writable, &mut remaining, &mut writable_links)?;
        }
        for (_, (expected, observed, path)) in writable_links {
            if observed < expected {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    format!(
                        "writable sandbox file has a hard-link alias outside the writable roots: {} ({observed}/{expected} links observed)",
                        path.display()
                    ),
                ));
            }
        }
        self.verify_narrow_writable_hardlink_scope()?;
        self.verify_protected_read_only_hardlink_scope()
    }

    fn verify_narrow_writable_hardlink_scope(&self) -> std::io::Result<()> {
        use std::os::unix::fs::MetadataExt;

        for file in &self.visible_read_write_files {
            let metadata = fs::symlink_metadata(file)?;
            if metadata.nlink() != 1 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    format!(
                        "writable sandbox exception file must not have hard-link aliases: {}",
                        file.display()
                    ),
                ));
            }
        }

        let mut roots = self.visible_read_write_roots.clone();
        roots.sort();
        roots.dedup();
        let mut minimal_roots: Vec<PathBuf> = Vec::new();
        for root in roots {
            if !minimal_roots
                .iter()
                .any(|ancestor| root.starts_with(ancestor))
            {
                minimal_roots.push(root);
            }
        }
        let mut remaining = MAX_SANDBOX_ENTRY_SCAN;
        for root in minimal_roots {
            let mut writable_links = BTreeMap::new();
            scan_sandbox_tree(&root, true, &mut remaining, &mut writable_links)?;
            for (_, (expected, observed, path)) in writable_links {
                if observed < expected {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        format!(
                            "writable sandbox exception has a hard-link alias outside its exact root: {} ({observed}/{expected} links observed)",
                            path.display()
                        ),
                    ));
                }
            }
        }
        Ok(())
    }

    fn effective_path_access(&self, path: &Path) -> std::io::Result<Option<SandboxMountAccess>> {
        let mut selected: Option<(usize, SandboxMountAccess)> = None;
        let mut consider =
            |boundary: &Path, exact: bool, access: SandboxMountAccess| -> std::io::Result<()> {
                if (exact && path != boundary) || (!exact && !path.starts_with(boundary)) {
                    return Ok(());
                }
                let specificity = boundary.components().count();
                match selected {
                    Some((existing_specificity, existing_access))
                        if existing_specificity == specificity && existing_access != access =>
                    {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::PermissionDenied,
                            format!(
                                "sandbox path has conflicting effective access: {}",
                                path.display()
                            ),
                        ));
                    }
                    Some((existing_specificity, _)) if existing_specificity > specificity => {}
                    _ => selected = Some((specificity, access)),
                }
                Ok(())
            };

        consider(
            &self.workspace_root,
            false,
            match self.workspace_access {
                WorkspaceAccess::ReadOnly => SandboxMountAccess::ReadOnly,
                WorkspaceAccess::ReadWrite => SandboxMountAccess::ReadWrite,
            },
        )?;
        for root in &self.visible_read_only_roots {
            consider(root, false, SandboxMountAccess::ReadOnly)?;
        }
        for file in &self.visible_read_only_files {
            consider(file, true, SandboxMountAccess::ReadOnly)?;
        }
        for root in self
            .visible_read_write_roots
            .iter()
            .chain(&self.writable_artifact_roots)
        {
            consider(root, false, SandboxMountAccess::ReadWrite)?;
        }
        for file in &self.visible_read_write_files {
            consider(file, true, SandboxMountAccess::ReadWrite)?;
        }
        Ok(selected.map(|(_, access)| access))
    }

    fn verify_protected_read_only_hardlink_scope(&self) -> std::io::Result<()> {
        use std::os::unix::fs::MetadataExt;

        let mut protected_roots = self.visible_read_only_roots.clone();
        if self.workspace_access == WorkspaceAccess::ReadOnly {
            protected_roots.push(self.workspace_root.clone());
        }
        minimize_sandbox_roots(&mut protected_roots);

        let mut writable_roots = self.visible_read_write_roots.clone();
        writable_roots.extend(self.writable_artifact_roots.iter().cloned());
        if self.workspace_access == WorkspaceAccess::ReadWrite {
            writable_roots.push(self.workspace_root.clone());
        }
        minimize_sandbox_roots(&mut writable_roots);
        if writable_roots.is_empty() && self.visible_read_write_files.is_empty() {
            return Ok(());
        }

        let mut remaining = MAX_SANDBOX_ENTRY_SCAN;
        let mut protected_inodes: BTreeMap<(u64, u64), PathBuf> = BTreeMap::new();
        for root in protected_roots {
            scan_sandbox_regular_files(&root, false, &mut remaining, |path, metadata| {
                if self.effective_path_access(path)? == Some(SandboxMountAccess::ReadOnly) {
                    protected_inodes
                        .entry((metadata.dev(), metadata.ino()))
                        .or_insert_with(|| path.to_path_buf());
                }
                Ok(())
            })?;
        }
        for file in &self.visible_read_only_files {
            let metadata = fs::symlink_metadata(file)?;
            if self.effective_path_access(file)? == Some(SandboxMountAccess::ReadOnly) {
                protected_inodes
                    .entry((metadata.dev(), metadata.ino()))
                    .or_insert_with(|| file.clone());
            }
        }

        let reject_writable_alias = |path: &Path,
                                     metadata: &fs::Metadata,
                                     protected_inodes: &BTreeMap<(u64, u64), PathBuf>|
         -> std::io::Result<()> {
            if self.effective_path_access(path)? != Some(SandboxMountAccess::ReadWrite) {
                return Ok(());
            }
            if protected_inodes.contains_key(&(metadata.dev(), metadata.ino())) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    format!(
                        "protected read-only sandbox file has a writable hard-link alias: {}",
                        path.display()
                    ),
                ));
            }
            Ok(())
        };
        for root in writable_roots {
            scan_sandbox_regular_files(&root, true, &mut remaining, |path, metadata| {
                reject_writable_alias(path, metadata, &protected_inodes)
            })?;
        }
        for file in &self.visible_read_write_files {
            let metadata = fs::symlink_metadata(file)?;
            reject_writable_alias(file, &metadata, &protected_inodes)?;
        }
        Ok(())
    }

    fn verify_mount_alias_conflicts(&self) -> std::io::Result<()> {
        let mountinfo = read_sandbox_mountinfo()?;
        verify_sandbox_mount_alias_conflicts(self, &mountinfo)
    }
}

#[cfg(target_os = "linux")]
fn minimize_sandbox_roots(roots: &mut Vec<PathBuf>) {
    roots.sort();
    roots.dedup();
    let mut minimal: Vec<PathBuf> = Vec::new();
    for root in roots.drain(..) {
        if !minimal.iter().any(|ancestor| root.starts_with(ancestor)) {
            minimal.push(root);
        }
    }
    *roots = minimal;
}

#[cfg(target_os = "linux")]
fn scan_sandbox_regular_files(
    root: &Path,
    reject_special_entries: bool,
    remaining: &mut usize,
    mut visit: impl FnMut(&Path, &fs::Metadata) -> std::io::Result<()>,
) -> std::io::Result<()> {
    use std::os::unix::fs::MetadataExt;

    let root_device = fs::symlink_metadata(root)?.dev();
    let mut pending = vec![root.to_path_buf()];
    while let Some(path) = pending.pop() {
        if *remaining == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "sandbox protected-file scan exceeded the fail-closed {MAX_SANDBOX_ENTRY_SCAN} entry limit"
                ),
            ));
        }
        *remaining -= 1;
        let metadata = fs::symlink_metadata(&path).map_err(|error| {
            std::io::Error::new(
                error.kind(),
                format!(
                    "failed to inspect sandbox entry {}: {error}",
                    path.display()
                ),
            )
        })?;
        if metadata.dev() != root_device {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "sandbox tree crosses a filesystem or mount boundary: {}",
                    path.display()
                ),
            ));
        }
        let file_type = metadata.file_type();
        if file_type.is_symlink() {
            continue;
        }
        if file_type.is_dir() {
            for entry in fs::read_dir(&path).map_err(|error| {
                std::io::Error::new(
                    error.kind(),
                    format!(
                        "failed to enumerate sandbox directory {}: {error}",
                        path.display()
                    ),
                )
            })? {
                pending.push(entry?.path());
            }
        } else if file_type.is_file() {
            visit(&path, &metadata)?;
        } else if reject_special_entries {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "sandbox contains a socket, FIFO, or device node: {}",
                    path.display()
                ),
            ));
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn scan_sandbox_tree(
    root: &Path,
    writable: bool,
    remaining: &mut usize,
    writable_links: &mut BTreeMap<(u64, u64), (u64, u64, PathBuf)>,
) -> std::io::Result<()> {
    use std::os::unix::fs::MetadataExt;

    let root_device = fs::symlink_metadata(root)?.dev();
    let mut pending = vec![root.to_path_buf()];
    while let Some(path) = pending.pop() {
        if *remaining == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "sandbox tree scan exceeded the fail-closed {MAX_SANDBOX_ENTRY_SCAN} entry limit"
                ),
            ));
        }
        *remaining -= 1;
        let metadata = fs::symlink_metadata(&path).map_err(|error| {
            std::io::Error::new(
                error.kind(),
                format!(
                    "failed to inspect sandbox entry {}: {error}",
                    path.display()
                ),
            )
        })?;
        let file_type = metadata.file_type();
        if metadata.dev() != root_device {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "sandbox tree crosses a filesystem or mount boundary: {}",
                    path.display()
                ),
            ));
        }
        if file_type.is_symlink() {
            let target = fs::metadata(&path).map_err(|error| {
                std::io::Error::new(
                    error.kind(),
                    format!(
                        "sandbox symlink must resolve to a regular file or directory {}: {error}",
                        path.display()
                    ),
                )
            })?;
            if !target.is_file() && !target.is_dir() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    format!(
                        "sandbox symlink resolves to a special file: {}",
                        path.display()
                    ),
                ));
            }
            if target.dev() != root_device {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    format!(
                        "sandbox symlink crosses a filesystem boundary: {}",
                        path.display()
                    ),
                ));
            }
            continue;
        }
        if file_type.is_dir() {
            for entry in fs::read_dir(&path).map_err(|error| {
                std::io::Error::new(
                    error.kind(),
                    format!(
                        "failed to enumerate sandbox directory {}: {error}",
                        path.display()
                    ),
                )
            })? {
                pending.push(entry?.path());
            }
            continue;
        }
        if !file_type.is_file() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "sandbox contains a socket, FIFO, or device node: {}",
                    path.display()
                ),
            ));
        }
        if writable && metadata.nlink() > 1 {
            let entry = writable_links
                .entry((metadata.dev(), metadata.ino()))
                .or_insert_with(|| (metadata.nlink(), 0, path.clone()));
            entry.0 = entry.0.max(metadata.nlink());
            entry.1 = entry.1.saturating_add(1);
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn read_sandbox_mountinfo() -> std::io::Result<Vec<SandboxMountInfo>> {
    let file = File::open("/proc/self/mountinfo")?;
    let mut bytes = Vec::new();
    file.take((MAX_SANDBOX_MOUNTINFO_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_SANDBOX_MOUNTINFO_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("mountinfo exceeds the fail-closed {MAX_SANDBOX_MOUNTINFO_BYTES} byte limit"),
        ));
    }
    parse_sandbox_mountinfo(&bytes)
}

#[cfg(target_os = "linux")]
fn parse_sandbox_mountinfo(bytes: &[u8]) -> std::io::Result<Vec<SandboxMountInfo>> {
    let mut entries = Vec::new();
    for line in bytes.split(|byte| *byte == b'\n') {
        if line.is_empty() {
            continue;
        }
        if line.len() > MAX_SANDBOX_MOUNTINFO_LINE_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "mountinfo line exceeds the fail-closed {MAX_SANDBOX_MOUNTINFO_LINE_BYTES} byte limit"
                ),
            ));
        }
        if entries.len() >= MAX_SANDBOX_MOUNTINFO_ENTRIES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "mountinfo exceeds the fail-closed {MAX_SANDBOX_MOUNTINFO_ENTRIES} entry limit"
                ),
            ));
        }
        let fields = line
            .split(|byte| byte.is_ascii_whitespace())
            .filter(|field| !field.is_empty())
            .collect::<Vec<_>>();
        let separator = fields
            .iter()
            .position(|field| *field == b"-")
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "mountinfo entry omitted the filesystem separator",
                )
            })?;
        if separator < 6 || separator + 3 >= fields.len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "mountinfo entry has an invalid field count",
            ));
        }
        let mount_id = parse_mountinfo_u64(fields[0], "mount id")?;
        let _parent_mount_id = parse_mountinfo_u64(fields[1], "parent mount id")?;
        let device = std::str::from_utf8(fields[2]).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "mountinfo device identity is not ASCII",
            )
        })?;
        let (device_major, device_minor) = device.split_once(':').ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "mountinfo device identity omitted ':'",
            )
        })?;
        let device_major = device_major.parse::<u64>().map_err(|error| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("invalid mountinfo device major: {error}"),
            )
        })?;
        let device_minor = device_minor.parse::<u64>().map_err(|error| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("invalid mountinfo device minor: {error}"),
            )
        })?;
        let root = decode_mountinfo_path(fields[3], "mount root")?;
        let mount_point = decode_mountinfo_path(fields[4], "mount point")?;
        entries.push(SandboxMountInfo {
            mount_id,
            device_major,
            device_minor,
            root,
            mount_point,
        });
    }
    let mut mount_ids = BTreeSet::new();
    if entries
        .iter()
        .any(|entry| !mount_ids.insert(entry.mount_id))
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "mountinfo contains duplicate mount ids",
        ));
    }
    if entries.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "mountinfo contained no entries",
        ));
    }
    Ok(entries)
}

#[cfg(target_os = "linux")]
fn parse_mountinfo_u64(field: &[u8], label: &str) -> std::io::Result<u64> {
    let text = std::str::from_utf8(field).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("mountinfo {label} is not ASCII"),
        )
    })?;
    text.parse::<u64>().map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("invalid mountinfo {label}: {error}"),
        )
    })
}

#[cfg(target_os = "linux")]
fn decode_mountinfo_path(field: &[u8], label: &str) -> std::io::Result<PathBuf> {
    use std::os::unix::ffi::OsStringExt;

    let mut decoded = Vec::with_capacity(field.len());
    let mut index = 0;
    while index < field.len() {
        if field[index] != b'\\' {
            decoded.push(field[index]);
            index += 1;
            continue;
        }
        if index + 3 >= field.len()
            || !field[index + 1..=index + 3]
                .iter()
                .all(|byte| matches!(*byte, b'0'..=b'7'))
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("mountinfo {label} contains an invalid escape"),
            ));
        }
        let value = (field[index + 1] - b'0') * 64
            + (field[index + 2] - b'0') * 8
            + (field[index + 3] - b'0');
        if !matches!(value, b' ' | b'\t' | b'\n' | b'\\') {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("mountinfo {label} contains an unsupported escape"),
            ));
        }
        decoded.push(value);
        index += 4;
    }
    let path = PathBuf::from(OsString::from_vec(decoded));
    if !path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                std::path::Component::CurDir | std::path::Component::ParentDir
            )
        })
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("mountinfo {label} is not a normalized absolute path"),
        ));
    }
    Ok(path)
}

#[cfg(target_os = "linux")]
fn sandbox_mount_backing_region(
    path: &Path,
    mountinfo: &[SandboxMountInfo],
) -> std::io::Result<(u64, u64, PathBuf)> {
    let max_specificity = mountinfo
        .iter()
        .filter(|entry| path.starts_with(&entry.mount_point))
        .map(|entry| entry.mount_point.components().count())
        .max()
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "mountinfo did not contain an authoritative mount for sandbox path {}",
                    path.display()
                ),
            )
        })?;
    let mut identities = mountinfo
        .iter()
        .filter(|entry| {
            entry.mount_point.components().count() == max_specificity
                && path.starts_with(&entry.mount_point)
        })
        .map(|entry| {
            let relative = path.strip_prefix(&entry.mount_point).map_err(|error| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("failed to derive mount-relative sandbox path: {error}"),
                )
            })?;
            Ok((
                entry.device_major,
                entry.device_minor,
                entry.root.join(relative),
                entry.mount_id,
            ))
        })
        .collect::<std::io::Result<Vec<_>>>()?;
    identities.sort();
    identities.dedup_by(|left, right| left.0 == right.0 && left.1 == right.1 && left.2 == right.2);
    if identities.len() != 1 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "mountinfo contains ambiguous authoritative mounts for sandbox path {}",
                path.display()
            ),
        ));
    }
    let (major, minor, backing, _) = identities.remove(0);
    Ok((major, minor, backing))
}

#[cfg(target_os = "linux")]
fn verify_sandbox_mount_alias_conflicts(
    sandbox: &ResolvedSystemdSandbox,
    mountinfo: &[SandboxMountInfo],
) -> std::io::Result<()> {
    let mut boundaries = vec![(
        sandbox.workspace_root.clone(),
        match sandbox.workspace_access {
            WorkspaceAccess::ReadOnly => SandboxMountAccess::ReadOnly,
            WorkspaceAccess::ReadWrite => SandboxMountAccess::ReadWrite,
        },
    )];
    boundaries.extend(
        sandbox
            .visible_read_only_roots
            .iter()
            .chain(&sandbox.visible_read_only_files)
            .cloned()
            .map(|path| (path, SandboxMountAccess::ReadOnly)),
    );
    boundaries.extend(
        sandbox
            .visible_read_write_roots
            .iter()
            .chain(&sandbox.visible_read_write_files)
            .chain(&sandbox.writable_artifact_roots)
            .cloned()
            .map(|path| (path, SandboxMountAccess::ReadWrite)),
    );
    for entry in mountinfo {
        if sandbox.effective_path_access(&entry.mount_point)?.is_some() {
            boundaries.push((
                entry.mount_point.clone(),
                sandbox
                    .effective_path_access(&entry.mount_point)?
                    .ok_or_else(|| std::io::Error::other("sandbox mount access disappeared"))?,
            ));
        }
    }
    boundaries.sort();
    boundaries.dedup();
    if boundaries.len() > MAX_SANDBOX_MOUNT_CHECKS {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "sandbox mount-region vector exceeds its safety bound",
        ));
    }

    let mut regions = boundaries
        .into_iter()
        .map(|(visible_path, access)| {
            let (device_major, device_minor, backing_path) =
                sandbox_mount_backing_region(&visible_path, mountinfo)?;
            Ok(SandboxMountRegion {
                visible_path,
                device_major,
                device_minor,
                backing_path,
                access,
            })
        })
        .collect::<std::io::Result<Vec<_>>>()?;
    regions.sort_by(|left, right| {
        left.visible_path
            .cmp(&right.visible_path)
            .then(left.access.cmp(&right.access))
            .then(left.device_major.cmp(&right.device_major))
            .then(left.device_minor.cmp(&right.device_minor))
            .then(left.backing_path.cmp(&right.backing_path))
    });
    regions.dedup();

    for (index, left) in regions.iter().enumerate() {
        for right in regions.iter().skip(index + 1) {
            if left.access == right.access {
                continue;
            }
            if sandbox_mount_regions_conflict(left, right) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    format!(
                        "sandbox read-only and writable paths have a mount identity conflict: {} and {}",
                        left.visible_path.display(),
                        right.visible_path.display()
                    ),
                ));
            }
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn sandbox_mount_regions_conflict(left: &SandboxMountRegion, right: &SandboxMountRegion) -> bool {
    if left.visible_path == right.visible_path {
        return true;
    }
    if let Ok(relative) = left.visible_path.strip_prefix(&right.visible_path) {
        return left.device_major != right.device_major
            || left.device_minor != right.device_minor
            || left.backing_path != right.backing_path.join(relative);
    }
    if let Ok(relative) = right.visible_path.strip_prefix(&left.visible_path) {
        return left.device_major != right.device_major
            || left.device_minor != right.device_minor
            || right.backing_path != left.backing_path.join(relative);
    }
    left.device_major == right.device_major
        && left.device_minor == right.device_minor
        && (left.backing_path.starts_with(&right.backing_path)
            || right.backing_path.starts_with(&left.backing_path))
}

#[cfg(target_os = "linux")]
fn hidden_systemd_program_root(program: &Path, hidden_roots: &[PathBuf]) -> Option<PathBuf> {
    [Path::new("/tmp"), Path::new("/var/tmp")]
        .into_iter()
        .chain(hidden_roots.iter().map(PathBuf::as_path))
        .find(|root| program.starts_with(root))
        .map(Path::to_path_buf)
}

#[cfg(target_os = "linux")]
fn validate_systemd_program_visibility(
    program: &Path,
    hidden_roots: &[PathBuf],
) -> std::io::Result<()> {
    let Some(hidden_root) = hidden_systemd_program_root(program, hidden_roots) else {
        return Ok(());
    };
    let cause = if hidden_root == Path::new("/tmp") || hidden_root == Path::new("/var/tmp") {
        "PrivateTmp=yes replaces that root inside the transient unit"
    } else {
        "sandbox.hidden_roots makes that root inaccessible inside the transient unit"
    };
    Err(environment_failure_io(
        EnvironmentFailure::sandbox_unavailable(format!(
            "the sandbox cannot start program {} because {cause}: {}; place the executable outside the hidden root before retrying",
            program.display(),
            hidden_root.display(),
        )),
        false,
    ))
}

#[cfg(target_os = "linux")]
fn normalized_absolute_program_invocation(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::from("/");
    for component in path.components() {
        match component {
            std::path::Component::RootDir | std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                if normalized != Path::new("/") {
                    normalized.pop();
                }
            }
            std::path::Component::Normal(component) => normalized.push(component),
            std::path::Component::Prefix(_) => {}
        }
    }
    normalized
}

#[cfg(target_os = "linux")]
fn resolved_direct_program_paths(
    spec: &ProcessSpec,
    current_dir: &Path,
) -> std::io::Result<Vec<PathBuf>> {
    let ProcessCommand::Direct { program, .. } = &spec.command else {
        return Ok(Vec::new());
    };
    let candidate = if program.is_absolute() {
        program.clone()
    } else if program.components().count() > 1 {
        current_dir.join(program)
    } else {
        // The guardian's eventual exec applies the target environment's PATH semantics. Avoid a
        // partial local reimplementation here; status 226 remains typed defense in depth for a
        // bare name whose selected executable cannot be established before launch.
        return Ok(Vec::new());
    };
    let invocation = normalized_absolute_program_invocation(&candidate);
    let mut paths = vec![invocation];
    match fs::canonicalize(&candidate) {
        Ok(canonical) if !paths.contains(&canonical) => paths.push(canonical),
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(std::io::Error::new(
                error.kind(),
                format!(
                    "failed to resolve sandbox program path {}: {error}",
                    candidate.display()
                ),
            ));
        }
    }
    Ok(paths)
}

#[cfg(target_os = "linux")]
fn resolve_systemd_sandbox(spec: &ProcessSpec) -> std::io::Result<Option<ResolvedSystemdSandbox>> {
    let Some(config) = spec.side_effects.workspace_config() else {
        return Ok(None);
    };
    let workspace_root = canonical_sandbox_directory(&config.workspace_root, "workspace root")?;
    if workspace_root == Path::new("/") {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "strict workspace confinement refuses '/' as the workspace root",
        ));
    }
    let current_dir = canonical_sandbox_directory(&spec.current_dir, "working directory")?;
    if !current_dir.starts_with(&workspace_root) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "working directory {} resolves outside strict workspace root {}",
                current_dir.display(),
                workspace_root.display()
            ),
        ));
    }

    let mut visible_read_only_roots = config
        .visible_read_only_roots
        .iter()
        .map(|root| canonical_sandbox_directory(root, "visible read-only root"))
        .collect::<std::io::Result<Vec<_>>>()?;
    visible_read_only_roots.sort();
    visible_read_only_roots.dedup();
    if visible_read_only_roots
        .iter()
        .any(|root| root == Path::new("/"))
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "strict workspace confinement refuses '/' as a visible read-only root",
        ));
    }
    let mut visible_read_only_files = config
        .visible_read_only_files
        .iter()
        .map(|file| canonical_sandbox_file(file, "visible read-only file"))
        .collect::<std::io::Result<Vec<_>>>()?;
    visible_read_only_files.sort();
    visible_read_only_files.dedup();
    let mut writable_artifact_roots = config
        .writable_artifact_roots
        .iter()
        .map(|root| canonical_sandbox_directory(root, "writable artifact root"))
        .collect::<std::io::Result<Vec<_>>>()?;
    writable_artifact_roots.sort();
    writable_artifact_roots.dedup();
    if writable_artifact_roots
        .iter()
        .any(|root| root == Path::new("/"))
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "strict workspace confinement refuses '/' as a writable artifact root",
        ));
    }
    let mut visible_read_write_roots = config
        .visible_read_write_roots
        .iter()
        .map(|root| canonical_sandbox_directory(root, "visible read-write root"))
        .collect::<std::io::Result<Vec<_>>>()?;
    visible_read_write_roots.sort();
    visible_read_write_roots.dedup();
    if visible_read_write_roots
        .iter()
        .any(|root| root == Path::new("/"))
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "strict workspace confinement refuses '/' as a visible read-write root",
        ));
    }
    let mut visible_read_write_files = config
        .visible_read_write_files
        .iter()
        .map(|file| canonical_sandbox_file(file, "visible read-write file"))
        .collect::<std::io::Result<Vec<_>>>()?;
    visible_read_write_files.sort();
    visible_read_write_files.dedup();
    let mut external_codex_writable_file_capabilities = Vec::new();
    let mut capability_paths = BTreeSet::new();
    for capability in &config.external_codex_writable_file_capabilities {
        let canonical_path =
            canonical_sandbox_file(&capability.path, "ExternalCodex writable file capability")?;
        if !visible_read_write_files.contains(&canonical_path)
            || !capability_paths.insert(canonical_path.clone())
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "ExternalCodex writable file capability is duplicate or lacks an exact writable file",
            ));
        }
        let resolved_capability = capability.with_resolved_path(canonical_path);
        resolved_capability.verify_path()?;
        external_codex_writable_file_capabilities.push(resolved_capability);
    }

    let mut hidden_roots = config
        .hidden_roots
        .iter()
        .map(|root| canonical_sandbox_directory(root, "hidden root"))
        .collect::<std::io::Result<Vec<_>>>()?;
    hidden_roots.sort();
    hidden_roots.dedup();
    let mut minimal_hidden_roots: Vec<PathBuf> = Vec::new();
    for root in hidden_roots {
        if minimal_hidden_roots
            .iter()
            .any(|ancestor| root.starts_with(ancestor))
        {
            continue;
        }
        minimal_hidden_roots.push(root);
    }
    let hidden_roots = minimal_hidden_roots;
    if hidden_roots.iter().any(|root| root == Path::new("/")) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "strict workspace confinement refuses '/' as a hidden root",
        ));
    }
    if config.isolated_host_view {
        let nix_store = canonical_sandbox_directory(Path::new("/nix/store"), "Nix store root")?;
        if !visible_read_only_roots.contains(&nix_store) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "isolated host view requires an explicit read-only /nix/store binding",
            ));
        }
        for hidden in &hidden_roots {
            for visible in std::iter::once(&workspace_root)
                .chain(std::iter::once(&current_dir))
                .chain(visible_read_only_roots.iter())
                .chain(visible_read_only_files.iter())
                .chain(visible_read_write_roots.iter())
                .chain(visible_read_write_files.iter())
                .chain(writable_artifact_roots.iter())
            {
                if visible.starts_with(hidden) || hidden.starts_with(visible) {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        "isolated host view refuses overlapping visible and inaccessible roots",
                    ));
                }
            }
        }
    }
    let mut identity_paths = vec![workspace_root.clone(), current_dir.clone()];
    identity_paths.extend(visible_read_only_roots.iter().cloned());
    identity_paths.extend(visible_read_only_files.iter().cloned());
    identity_paths.extend(visible_read_write_roots.iter().cloned());
    identity_paths.extend(visible_read_write_files.iter().cloned());
    identity_paths.extend(writable_artifact_roots.iter().cloned());
    identity_paths.extend(hidden_roots.iter().cloned());
    identity_paths.sort();
    identity_paths.dedup();
    let path_identities = identity_paths
        .iter()
        .map(|path| capture_sandbox_path_identity(path))
        .collect::<std::io::Result<Vec<_>>>()?;
    let mount_checks = build_sandbox_mount_checks(SandboxMountPaths {
        workspace_root: &workspace_root,
        workspace_access: config.workspace_access,
        visible_read_only_roots: &visible_read_only_roots,
        visible_read_only_files: &visible_read_only_files,
        visible_read_write_roots: &visible_read_write_roots,
        visible_read_write_files: &visible_read_write_files,
        writable_artifact_roots: &writable_artifact_roots,
        hidden_roots: &hidden_roots,
        isolated_host_view: config.isolated_host_view,
    })?;
    if mount_checks.len() > MAX_SANDBOX_MOUNT_CHECKS {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "sandbox mount-check vector exceeds its safety bound",
        ));
    }

    let sandbox = ResolvedSystemdSandbox {
        kind: spec.side_effects.kind(),
        workspace_root,
        current_dir,
        workspace_access: config.workspace_access,
        visible_read_only_roots,
        visible_read_only_files,
        visible_read_write_roots,
        visible_read_write_files,
        external_codex_writable_file_capabilities,
        writable_artifact_roots,
        hidden_roots,
        isolated_host_view: config.isolated_host_view,
        resource_limits: config.resource_limits,
        path_identities,
        mount_checks,
    };
    for program in resolved_direct_program_paths(spec, &sandbox.current_dir)? {
        sandbox.validate_program_visibility(&program)?;
    }
    sandbox.verify_no_special_entries()?;
    Ok(Some(sandbox))
}

#[cfg(target_os = "linux")]
fn canonical_sandbox_directory(path: &Path, label: &str) -> std::io::Result<PathBuf> {
    validate_systemd_path_syntax(path, label)?;
    reject_symlink_ancestors(path, label)?;
    let canonical = fs::canonicalize(path).map_err(|error| {
        std::io::Error::new(
            error.kind(),
            format!("failed to canonicalize {label} {}: {error}", path.display()),
        )
    })?;
    if !canonical.is_dir() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("{label} {} is not a directory", canonical.display()),
        ));
    }
    validate_systemd_path_syntax(&canonical, label)?;
    Ok(canonical)
}

#[cfg(target_os = "linux")]
fn canonical_sandbox_file(path: &Path, label: &str) -> std::io::Result<PathBuf> {
    validate_systemd_path_syntax(path, label)?;
    reject_symlink_ancestors(path, label)?;
    let canonical = fs::canonicalize(path).map_err(|error| {
        std::io::Error::new(
            error.kind(),
            format!("failed to canonicalize {label} {}: {error}", path.display()),
        )
    })?;
    if !canonical.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("{label} {} is not a regular file", canonical.display()),
        ));
    }
    validate_systemd_path_syntax(&canonical, label)?;
    Ok(canonical)
}

#[cfg(target_os = "linux")]
fn validate_systemd_path_syntax(path: &Path, label: &str) -> std::io::Result<()> {
    use std::os::unix::ffi::OsStrExt;

    if path.as_os_str().as_bytes().iter().any(|byte| {
        byte.is_ascii_whitespace() || byte.is_ascii_control() || matches!(*byte, b':' | b'\\')
    }) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "{label} contains whitespace or systemd path-list syntax that cannot be verified exactly: {}",
                path.display()
            ),
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn reject_symlink_ancestors(path: &Path, label: &str) -> std::io::Result<()> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        env::current_dir()?.join(path)
    };
    let mut current = PathBuf::new();
    for component in absolute.components() {
        match component {
            std::path::Component::Prefix(_) => current.push(component.as_os_str()),
            std::path::Component::RootDir => current.push(component.as_os_str()),
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("{label} may not contain '..': {}", path.display()),
                ));
            }
            std::path::Component::Normal(component) => {
                current.push(component);
                let metadata = fs::symlink_metadata(&current).map_err(|error| {
                    std::io::Error::new(
                        error.kind(),
                        format!(
                            "failed to inspect {label} ancestor {}: {error}",
                            current.display()
                        ),
                    )
                })?;
                if metadata.file_type().is_symlink() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!(
                            "{label} may not traverse a symlink ancestor: {}",
                            current.display()
                        ),
                    ));
                }
            }
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn capture_sandbox_path_identity(path: &Path) -> std::io::Result<SandboxPathIdentity> {
    use std::os::unix::fs::MetadataExt;

    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("sandbox path may not be a symlink: {}", path.display()),
        ));
    }
    Ok(SandboxPathIdentity {
        path: path.to_path_buf(),
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

#[cfg(target_os = "linux")]
struct SandboxMountPaths<'a> {
    workspace_root: &'a Path,
    workspace_access: WorkspaceAccess,
    visible_read_only_roots: &'a [PathBuf],
    visible_read_only_files: &'a [PathBuf],
    visible_read_write_roots: &'a [PathBuf],
    visible_read_write_files: &'a [PathBuf],
    writable_artifact_roots: &'a [PathBuf],
    hidden_roots: &'a [PathBuf],
    isolated_host_view: bool,
}

#[cfg(target_os = "linux")]
fn build_sandbox_mount_checks(
    paths: SandboxMountPaths<'_>,
) -> std::io::Result<Vec<SandboxMountCheck>> {
    use std::os::unix::fs::MetadataExt;

    let mut requested = BTreeMap::new();
    // ProtectSystem=strict is the foundation that keeps same-filesystem symlink targets outside
    // explicitly writable binds read-only. Verify the unit's actual root mount rather than
    // trusting only the configured property.
    requested.insert(
        PathBuf::from("/"),
        if paths.isolated_host_view {
            SandboxMountAccess::IsolatedRoot
        } else {
            SandboxMountAccess::ReadOnly
        },
    );
    let workspace_mount_access = match paths.workspace_access {
        WorkspaceAccess::ReadOnly => SandboxMountAccess::ReadOnly,
        WorkspaceAccess::ReadWrite => SandboxMountAccess::ReadWrite,
    };
    requested.insert(paths.workspace_root.to_path_buf(), workspace_mount_access);
    for path in paths
        .visible_read_only_roots
        .iter()
        .chain(paths.visible_read_only_files)
    {
        if requested
            .insert(path.clone(), SandboxMountAccess::ReadOnly)
            .is_some_and(|existing| existing != SandboxMountAccess::ReadOnly)
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "sandbox path was requested both read-only and read-write: {}",
                    path.display()
                ),
            ));
        }
    }
    for path in paths
        .visible_read_write_roots
        .iter()
        .chain(paths.visible_read_write_files)
        .chain(paths.writable_artifact_roots)
    {
        if requested
            .insert(path.clone(), SandboxMountAccess::ReadWrite)
            .is_some_and(|existing| existing != SandboxMountAccess::ReadWrite)
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "sandbox path was requested both read-only and read-write: {}",
                    path.display()
                ),
            ));
        }
    }
    let mut checks = requested
        .into_iter()
        .map(|(path, access)| {
            let (device, inode) = if access == SandboxMountAccess::IsolatedRoot {
                (0, 0)
            } else {
                let metadata = fs::symlink_metadata(&path)?;
                if metadata.file_type().is_symlink() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!("sandbox mount check path is a symlink: {}", path.display()),
                    ));
                }
                (metadata.dev(), metadata.ino())
            };
            Ok(SandboxMountCheck {
                path,
                device,
                inode,
                access,
                optional: false,
            })
        })
        .collect::<std::io::Result<Vec<_>>>()?;
    let mut inaccessible = known_sensitive_socket_paths()
        .into_iter()
        .map(|path| (path, true))
        .collect::<BTreeMap<_, _>>();
    for path in paths.hidden_roots {
        inaccessible.insert(path.clone(), false);
    }
    for (path, optional) in inaccessible {
        checks.push(SandboxMountCheck {
            path,
            device: 0,
            inode: 0,
            access: SandboxMountAccess::Inaccessible,
            optional,
        });
    }
    Ok(checks)
}

#[cfg(target_os = "linux")]
fn apply_systemd_sandbox_properties(command: &mut Command, sandbox: &ResolvedSystemdSandbox) {
    command.args([
        "--property=ProtectSystem=strict",
        "--property=ProtectHome=tmpfs",
        "--property=NoNewPrivileges=yes",
        "--property=RestrictSUIDSGID=yes",
        "--property=LockPersonality=yes",
        "--property=PrivateTmp=yes",
        "--property=PrivateDevices=yes",
        "--property=PrivateIPC=yes",
        "--property=ProtectKernelTunables=yes",
        "--property=ProtectKernelModules=yes",
        "--property=ProtectKernelLogs=yes",
        "--property=ProtectClock=yes",
        "--property=ProtectControlGroups=yes",
        "--property=ProtectProc=invisible",
        "--property=ProcSubset=pid",
        "--property=SystemCallArchitectures=native",
        "--property=SystemCallErrorNumber=EPERM",
        "--property=RestrictRealtime=yes",
        "--property=KeyringMode=private",
        "--property=UMask=0077",
        "--property=MemorySwapMax=0",
        "--property=LimitCORE=0",
        "--property=OOMPolicy=kill",
    ]);
    command.arg("--property=RestrictNamespaces=yes");
    if sandbox.isolated_host_view {
        command.arg("--property=TemporaryFileSystem=/:ro");
    }
    if sandbox.kind == SideEffectConfinementProfileKind::StrictOfflineWorkspace {
        command.args([
            "--property=PrivateNetwork=yes",
            "--property=RestrictAddressFamilies=AF_UNIX",
            "--property=SystemCallFilter=~@clock @debug @module @mount @obsolete @raw-io @reboot @swap bpf fanotify_init fanotify_mark ipc mq_getsetattr mq_notify mq_open mq_timedreceive mq_timedreceive_time64 mq_timedsend mq_timedsend_time64 mq_unlink msgctl msgget msgrcv msgsnd open_by_handle_at process_madvise process_vm_readv process_vm_writev quotactl quotactl_fd semctl semget semop semtimedop semtimedop_time64 shmat shmctl shmdt shmget link linkat mknod mknodat socket socketpair socketcall",
        ]);
    } else {
        command.args([
            "--property=PrivateNetwork=no",
            "--property=RestrictAddressFamilies=AF_INET AF_INET6",
            "--property=SystemCallFilter=~@clock @debug @module @mount @obsolete @raw-io @reboot @swap bpf fanotify_init fanotify_mark ipc mq_getsetattr mq_notify mq_open mq_timedreceive mq_timedreceive_time64 mq_timedsend mq_timedsend_time64 mq_unlink msgctl msgget msgrcv msgsnd open_by_handle_at process_madvise process_vm_readv process_vm_writev quotactl quotactl_fd semctl semget semop semtimedop semtimedop_time64 shmat shmctl shmdt shmget link linkat mknod mknodat",
        ]);
    }

    let limits = sandbox.resource_limits;
    command
        .arg(format!("--property=MemoryMax={}", limits.memory_max_bytes))
        .arg(format!("--property=TasksMax={}", limits.tasks_max))
        .arg(format!("--property=CPUQuota={}%", limits.cpu_quota_percent))
        .arg(format!("--property=LimitNOFILE={}", limits.open_files_max))
        .arg(format!(
            "--property=LimitFSIZE={}",
            limits.file_size_max_bytes
        ));

    for root in &sandbox.hidden_roots {
        command.arg(systemd_path_property("InaccessiblePaths=", root, false));
    }
    for path in known_sensitive_socket_paths() {
        command.arg(systemd_path_property("InaccessiblePaths=", &path, true));
    }

    for root in &sandbox.visible_read_only_roots {
        command
            .arg(systemd_path_property("BindReadOnlyPaths=", root, false))
            .arg(systemd_path_property("ReadOnlyPaths=", root, false));
    }
    for file in &sandbox.visible_read_only_files {
        command
            .arg(systemd_path_property("BindReadOnlyPaths=", file, false))
            .arg(systemd_path_property("ReadOnlyPaths=", file, false));
    }
    for root in &sandbox.visible_read_write_roots {
        command
            .arg(systemd_path_property("BindPaths=", root, false))
            .arg(systemd_path_property("ReadWritePaths=", root, false));
    }
    for file in &sandbox.visible_read_write_files {
        command
            .arg(systemd_path_property("BindPaths=", file, false))
            .arg(systemd_path_property("ReadWritePaths=", file, false));
    }

    match sandbox.workspace_access {
        WorkspaceAccess::ReadOnly => {
            command
                .arg(systemd_path_property(
                    "BindReadOnlyPaths=",
                    &sandbox.workspace_root,
                    false,
                ))
                .arg(systemd_path_property(
                    "ReadOnlyPaths=",
                    &sandbox.workspace_root,
                    false,
                ));
        }
        WorkspaceAccess::ReadWrite => {
            command
                .arg(systemd_path_property(
                    "BindPaths=",
                    &sandbox.workspace_root,
                    false,
                ))
                .arg(systemd_path_property(
                    "ReadWritePaths=",
                    &sandbox.workspace_root,
                    false,
                ));
        }
    }
    for root in &sandbox.writable_artifact_roots {
        command
            .arg(systemd_path_property("BindPaths=", root, false))
            .arg(systemd_path_property("ReadWritePaths=", root, false));
    }
}

#[cfg(target_os = "linux")]
fn verify_systemd_sandbox_properties(
    sandbox: &ResolvedSystemdSandbox,
    properties: &BTreeMap<String, String>,
    runtime_dir: &Path,
) -> std::io::Result<()> {
    for (name, expected) in [
        ("ProtectSystem", "strict"),
        ("ProtectHome", "tmpfs"),
        ("NoNewPrivileges", "yes"),
        ("RestrictSUIDSGID", "yes"),
        ("LockPersonality", "yes"),
        ("PrivateTmp", "yes"),
        ("PrivateDevices", "yes"),
        ("PrivateIPC", "yes"),
        ("ProtectKernelTunables", "yes"),
        ("ProtectKernelModules", "yes"),
        ("ProtectKernelLogs", "yes"),
        ("ProtectClock", "yes"),
        ("ProtectControlGroups", "yes"),
        ("ProtectProc", "invisible"),
        ("ProcSubset", "pid"),
        ("SystemCallArchitectures", "native"),
        ("RestrictRealtime", "yes"),
        ("KeyringMode", "private"),
        ("UMask", "0077"),
        ("MemorySwapMax", "0"),
        ("LimitCORE", "0"),
        ("OOMPolicy", "kill"),
    ] {
        require_effective_property(properties, name, |value| value == expected, expected)?;
    }
    verify_system_call_error_number(property_value(properties, "SystemCallErrorNumber")?)?;
    require_effective_property(
        properties,
        "SystemCallFilter",
        |value| !value.trim().is_empty(),
        "a non-empty syscall filter",
    )?;
    verify_effective_system_call_filter(
        sandbox.kind,
        property_value(properties, "SystemCallFilter")?,
    )?;
    require_effective_property(
        properties,
        "RestrictNamespaces",
        |value| value == "yes",
        "yes",
    )?;

    verify_systemd_network_properties(sandbox.kind, properties)?;
    verify_isolated_host_view_property(sandbox, properties)?;

    let limits = sandbox.resource_limits;
    for (name, expected) in [
        ("MemoryMax", limits.memory_max_bytes.to_string()),
        ("TasksMax", limits.tasks_max.to_string()),
        ("LimitNOFILE", limits.open_files_max.to_string()),
        ("LimitFSIZE", limits.file_size_max_bytes.to_string()),
    ] {
        require_effective_property(properties, name, |value| value == expected, &expected)?;
    }
    if sandbox.kind == SideEffectConfinementProfileKind::TrustedFixedNetwork {
        let expected_quota_micros = u64::from(limits.cpu_quota_percent) * 10_000;
        require_effective_property(
            properties,
            "CPUQuotaPerSecUSec",
            |value| parse_systemd_duration_micros(value) == Some(expected_quota_micros),
            &format!("exactly {expected_quota_micros} microseconds per second"),
        )?;
    } else {
        require_effective_property(
            properties,
            "CPUQuotaPerSecUSec",
            |value| !value.is_empty() && value != "infinity",
            "a finite quota",
        )?;
    }

    let inaccessible = property_value(properties, "InaccessiblePaths")?;
    for root in &sandbox.hidden_roots {
        require_property_path("InaccessiblePaths", inaccessible, root)?;
    }
    // Mask known same-user IPC endpoints and the Nix daemon. The complete runtime root cannot be
    // masked because it contains systemd's unit-lifetime guardian directory; AF_UNIX/socket
    // restrictions are independently verified for target isolation.
    // SAFETY: geteuid has no preconditions and does not access Rust memory.
    let uid = unsafe { libc::geteuid() };
    for path in [
        PathBuf::from(format!("/run/user/{uid}/bus")),
        PathBuf::from(format!("/run/user/{uid}/systemd")),
        PathBuf::from("/nix/var/nix/daemon-socket/socket"),
    ] {
        require_property_path("InaccessiblePaths", inaccessible, &path)?;
    }
    require_property_path(
        "BindPaths",
        property_value(properties, "BindPaths")?,
        runtime_dir,
    )?;
    require_property_path(
        "ReadWritePaths",
        property_value(properties, "ReadWritePaths")?,
        runtime_dir,
    )?;

    match sandbox.workspace_access {
        WorkspaceAccess::ReadOnly => {
            require_property_path(
                "BindReadOnlyPaths",
                property_value(properties, "BindReadOnlyPaths")?,
                &sandbox.workspace_root,
            )?;
            require_property_path(
                "ReadOnlyPaths",
                property_value(properties, "ReadOnlyPaths")?,
                &sandbox.workspace_root,
            )?;
        }
        WorkspaceAccess::ReadWrite => {
            require_property_path(
                "BindPaths",
                property_value(properties, "BindPaths")?,
                &sandbox.workspace_root,
            )?;
            require_property_path(
                "ReadWritePaths",
                property_value(properties, "ReadWritePaths")?,
                &sandbox.workspace_root,
            )?;
        }
    }
    for root in &sandbox.visible_read_only_roots {
        require_property_path(
            "BindReadOnlyPaths",
            property_value(properties, "BindReadOnlyPaths")?,
            root,
        )?;
    }
    for file in &sandbox.visible_read_only_files {
        require_property_path(
            "BindReadOnlyPaths",
            property_value(properties, "BindReadOnlyPaths")?,
            file,
        )?;
        require_property_path(
            "ReadOnlyPaths",
            property_value(properties, "ReadOnlyPaths")?,
            file,
        )?;
    }
    for root in &sandbox.visible_read_write_roots {
        require_property_path("BindPaths", property_value(properties, "BindPaths")?, root)?;
        require_property_path(
            "ReadWritePaths",
            property_value(properties, "ReadWritePaths")?,
            root,
        )?;
    }
    for file in &sandbox.visible_read_write_files {
        require_property_path("BindPaths", property_value(properties, "BindPaths")?, file)?;
        require_property_path(
            "ReadWritePaths",
            property_value(properties, "ReadWritePaths")?,
            file,
        )?;
    }
    for root in &sandbox.writable_artifact_roots {
        require_property_path("BindPaths", property_value(properties, "BindPaths")?, root)?;
        require_property_path(
            "ReadWritePaths",
            property_value(properties, "ReadWritePaths")?,
            root,
        )?;
    }
    verify_exact_systemd_path_properties(sandbox, properties, runtime_dir)
}

#[cfg(target_os = "linux")]
fn verify_exact_systemd_path_properties(
    sandbox: &ResolvedSystemdSandbox,
    properties: &BTreeMap<String, String>,
    runtime_dir: &Path,
) -> std::io::Result<()> {
    if !matches!(
        sandbox.kind,
        SideEffectConfinementProfileKind::TrustedFixedNetwork
            | SideEffectConfinementProfileKind::ExternalCodex
    ) && !sandbox.isolated_host_view
    {
        return Ok(());
    }

    let mut inaccessible = sandbox
        .hidden_roots
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    inaccessible.extend(known_sensitive_socket_paths());
    verify_exact_property_paths(
        "InaccessiblePaths",
        property_value(properties, "InaccessiblePaths")?,
        &inaccessible,
    )?;

    let mut read_only = sandbox
        .visible_read_only_roots
        .iter()
        .chain(&sandbox.visible_read_only_files)
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut read_only_bindings = sandbox
        .visible_read_only_roots
        .iter()
        .chain(&sandbox.visible_read_only_files)
        .map(|path| (path.clone(), path.clone()))
        .collect::<BTreeSet<_>>();
    let mut read_write = sandbox
        .visible_read_write_roots
        .iter()
        .chain(&sandbox.visible_read_write_files)
        .chain(&sandbox.writable_artifact_roots)
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut read_write_bindings = sandbox
        .visible_read_write_roots
        .iter()
        .chain(&sandbox.visible_read_write_files)
        .chain(&sandbox.writable_artifact_roots)
        .map(|path| (path.clone(), path.clone()))
        .collect::<BTreeSet<_>>();
    match sandbox.workspace_access {
        WorkspaceAccess::ReadOnly => {
            read_only.insert(sandbox.workspace_root.clone());
            read_only_bindings.insert((
                sandbox.workspace_root.clone(),
                sandbox.workspace_root.clone(),
            ));
        }
        WorkspaceAccess::ReadWrite => {
            read_write.insert(sandbox.workspace_root.clone());
            read_write_bindings.insert((
                sandbox.workspace_root.clone(),
                sandbox.workspace_root.clone(),
            ));
        }
    }
    read_write.insert(runtime_dir.to_path_buf());
    read_write_bindings.insert((runtime_dir.to_path_buf(), runtime_dir.to_path_buf()));
    verify_exact_property_bindings(
        "BindReadOnlyPaths",
        property_value(properties, "BindReadOnlyPaths")?,
        &read_only_bindings,
    )?;
    verify_exact_property_paths(
        "ReadOnlyPaths",
        property_value(properties, "ReadOnlyPaths")?,
        &read_only,
    )?;
    verify_exact_property_bindings(
        "BindPaths",
        property_value(properties, "BindPaths")?,
        &read_write_bindings,
    )?;
    verify_exact_property_paths(
        "ReadWritePaths",
        property_value(properties, "ReadWritePaths")?,
        &read_write,
    )
}

#[cfg(target_os = "linux")]
fn is_exact_isolated_host_view_property(value: &str) -> bool {
    let mut entries = value.split_whitespace();
    entries.next() == Some("/:ro") && entries.next().is_none()
}

#[cfg(target_os = "linux")]
fn verify_isolated_host_view_property(
    sandbox: &ResolvedSystemdSandbox,
    properties: &BTreeMap<String, String>,
) -> std::io::Result<()> {
    let value = property_value(properties, "TemporaryFileSystem")?;
    if !sandbox.isolated_host_view {
        return if value.trim().is_empty() {
            Ok(())
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "effective TemporaryFileSystem unexpectedly changed the ordinary sandbox root",
            ))
        };
    }
    if is_exact_isolated_host_view_property(value) {
        Ok(())
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "effective TemporaryFileSystem did not exactly match the isolated read-only root",
        ))
    }
}

#[cfg(target_os = "linux")]
fn verify_systemd_network_properties(
    kind: SideEffectConfinementProfileKind,
    properties: &BTreeMap<String, String>,
) -> std::io::Result<()> {
    let address_families = property_value(properties, "RestrictAddressFamilies")?;
    let actual_families = address_families.split_whitespace().collect::<BTreeSet<_>>();
    let expected_families = if kind == SideEffectConfinementProfileKind::StrictOfflineWorkspace {
        BTreeSet::from(["AF_UNIX"])
    } else {
        BTreeSet::from(["AF_INET", "AF_INET6"])
    };
    if actual_families != expected_families {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "effective RestrictAddressFamilies does not match {:?}: {address_families:?}",
                kind
            ),
        ));
    }
    if kind == SideEffectConfinementProfileKind::StrictOfflineWorkspace {
        require_effective_property(properties, "PrivateNetwork", |value| value == "yes", "yes")?;
    } else {
        require_effective_property(properties, "PrivateNetwork", |value| value == "no", "no")?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn verify_sandbox_mount_report(path: &Path, checks: &[SandboxMountCheck]) -> std::io::Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let metadata = fs::symlink_metadata(path)?;
    // SAFETY: geteuid has no preconditions and does not access Rust memory.
    let effective_uid = unsafe { libc::geteuid() };
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.uid() != effective_uid
        || metadata.permissions().mode() & 0o777 != 0o600
        || metadata.nlink() != 1
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("unsafe sandbox mount report {}", path.display()),
        ));
    }
    let bytes = read_bounded_regular_file_nofollow(path, 64 * 1024)?;
    let report = std::str::from_utf8(&bytes).map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("sandbox mount report is not UTF-8: {error}"),
        )
    })?;
    let lines = report.lines().collect::<Vec<_>>();
    if lines.len() != checks.len() + 1 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "sandbox mount report has {} entries; expected {}",
                lines.len(),
                checks.len() + 1
            ),
        ));
    }
    let security = lines[0].split_whitespace().collect::<Vec<_>>();
    if security.len() != 7
        || security[0] != "security"
        || security[1..=4]
            .iter()
            .any(|value| *value != "0000000000000000")
        || security[5] != "1"
        || security[6] != "2"
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("unit security state was not capability-free, no-new-privileges, and seccomp-filtered: {:?}", lines[0]),
        ));
    }
    for (line, check) in lines[1..].iter().copied().zip(checks) {
        if check.access == SandboxMountAccess::Inaccessible {
            let accepted =
                line == "inaccessible" || (check.optional && line == "inaccessible-missing");
            if !accepted {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    format!(
                        "sandbox path remained visible inside unit mount namespace: {}",
                        check.path.display()
                    ),
                ));
            }
            continue;
        }
        if check.access == SandboxMountAccess::IsolatedRoot {
            let fields = line.split_whitespace().collect::<Vec<_>>();
            if fields.len() != 4
                || fields[0] != "isolated-root"
                || fields[2] != "tmpfs"
                || !fields[3].split(',').any(|option| option == "ro")
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "sandbox root was not an isolated read-only tmpfs",
                ));
            }
            continue;
        }
        let fields = line.split_whitespace().collect::<Vec<_>>();
        if fields.len() != 4 || fields[0] != "mounted" {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("malformed sandbox mount report line: {line:?}"),
            ));
        }
        let device = fields[1].parse::<u64>().map_err(|error| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("invalid mount report device: {error}"),
            )
        })?;
        let inode = fields[2].parse::<u64>().map_err(|error| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("invalid mount report inode: {error}"),
            )
        })?;
        let (expected_device, expected_inode) =
            if check.access == SandboxMountAccess::PrivateRuntime {
                let runtime = fs::symlink_metadata(&check.path)?;
                if runtime.file_type().is_symlink()
                    || !runtime.is_dir()
                    || runtime.uid() != effective_uid
                    || runtime.permissions().mode() & 0o777 != 0o700
                {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        "private unit runtime mount identity or mode was unsafe",
                    ));
                }
                (runtime.dev(), runtime.ino())
            } else {
                (check.device, check.inode)
            };
        if device != expected_device || inode != expected_inode {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "systemd bound the wrong inode for {}: expected {}:{}, observed {device}:{inode}",
                    check.path.display(),
                    expected_device,
                    expected_inode
                ),
            ));
        }
        let options = fields[3].split(',').collect::<Vec<_>>();
        let expected = match check.access {
            SandboxMountAccess::ReadOnly => "ro",
            SandboxMountAccess::ReadWrite => "rw",
            SandboxMountAccess::PrivateRuntime => "rw",
            SandboxMountAccess::Inaccessible => continue,
            SandboxMountAccess::IsolatedRoot => continue,
        };
        if !options.contains(&expected) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "sandbox mount access for {} was not {expected}: {:?}",
                    check.path.display(),
                    fields[3]
                ),
            ));
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn property_value<'a>(
    properties: &'a BTreeMap<String, String>,
    name: &str,
) -> std::io::Result<&'a str> {
    properties.get(name).map(String::as_str).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("systemd show omitted effective property {name}"),
        )
    })
}

#[cfg(target_os = "linux")]
fn require_effective_property(
    properties: &BTreeMap<String, String>,
    name: &str,
    predicate: impl FnOnce(&str) -> bool,
    expected: &str,
) -> std::io::Result<()> {
    let value = property_value(properties, name)?;
    if predicate(value) {
        Ok(())
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("effective {name}={value:?}; required {expected}"),
        ))
    }
}

#[cfg(target_os = "linux")]
fn parse_systemd_duration_micros(value: &str) -> Option<u64> {
    for (suffix, multiplier) in [
        ("us", 1u64),
        ("ms", 1_000u64),
        ("s", 1_000_000u64),
        ("min", 60_000_000u64),
    ] {
        if let Some(number) = value.strip_suffix(suffix) {
            return number
                .parse::<u64>()
                .ok()
                .and_then(|number| number.checked_mul(multiplier));
        }
    }
    value.parse::<u64>().ok()
}

#[cfg(target_os = "linux")]
fn require_property_path(name: &str, value: &str, path: &Path) -> std::io::Result<()> {
    let path = path.to_str().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("{name} path is not valid UTF-8: {}", path.display()),
        )
    })?;
    let matches = value.split_whitespace().any(|entry| {
        let entry = entry.strip_prefix('-').unwrap_or(entry);
        let source = entry.split(':').next().unwrap_or(entry);
        source == path
    });
    if matches {
        Ok(())
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("effective {name} omitted required path {path}"),
        ))
    }
}

#[cfg(target_os = "linux")]
fn parse_property_bindings(value: &str) -> BTreeSet<(PathBuf, PathBuf)> {
    value
        .split_whitespace()
        .filter_map(|entry| {
            let entry = entry.strip_prefix('-').unwrap_or(entry);
            let mut parts = entry.split(':');
            let source = parts.next()?;
            let destination = parts
                .next()
                .filter(|value| !value.is_empty())
                .unwrap_or(source);
            Some((PathBuf::from(source), PathBuf::from(destination)))
        })
        .collect()
}

#[cfg(target_os = "linux")]
fn verify_exact_property_bindings(
    name: &str,
    value: &str,
    expected: &BTreeSet<(PathBuf, PathBuf)>,
) -> std::io::Result<()> {
    let actual = parse_property_bindings(value);
    if &actual == expected {
        Ok(())
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "effective {name} binding set differed from the exact requested set: expected {expected:?}, observed {actual:?}"
            ),
        ))
    }
}

#[cfg(target_os = "linux")]
fn verify_exact_property_paths(
    name: &str,
    value: &str,
    expected: &BTreeSet<PathBuf>,
) -> std::io::Result<()> {
    let actual = value
        .split_whitespace()
        .map(|entry| {
            let entry = entry.strip_prefix('-').unwrap_or(entry);
            PathBuf::from(entry.split(':').next().unwrap_or(entry))
        })
        .collect::<BTreeSet<_>>();
    if &actual == expected {
        Ok(())
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "effective {name} path set differed from the exact requested set: expected {expected:?}, observed {actual:?}"
            ),
        ))
    }
}

#[cfg(target_os = "linux")]
fn verify_system_call_error_number(value: &str) -> std::io::Result<()> {
    if value == "EPERM" || value == libc::EPERM.to_string() {
        Ok(())
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("effective SystemCallErrorNumber={value:?}; required EPERM"),
        ))
    }
}

#[cfg(target_os = "linux")]
const REQUIRED_DENIED_SYSCALLS: &[&str] = &[
    "bpf",
    "fanotify_init",
    "fanotify_mark",
    "ipc",
    "mq_getsetattr",
    "mq_notify",
    "mq_open",
    "mq_timedreceive",
    "mq_timedreceive_time64",
    "mq_timedsend",
    "mq_timedsend_time64",
    "mq_unlink",
    "msgctl",
    "msgget",
    "msgrcv",
    "msgsnd",
    "open_by_handle_at",
    "process_madvise",
    "process_vm_readv",
    "process_vm_writev",
    "quotactl",
    "quotactl_fd",
    "semctl",
    "semget",
    "semop",
    "semtimedop",
    "semtimedop_time64",
    "shmat",
    "shmctl",
    "shmdt",
    "shmget",
    "link",
    "linkat",
    "mknod",
    "mknodat",
];

#[cfg(target_os = "linux")]
fn required_denied_group_representatives() -> [(&'static str, &'static [&'static str]); 8] {
    let raw_io_representatives: &[&str] = if cfg!(any(target_arch = "x86", target_arch = "x86_64"))
    {
        &["ioperm", "iopl"]
    } else if cfg!(target_arch = "s390x") {
        &[
            "s390_pci_mmio_read",
            "s390_pci_mmio_write",
            "s390_runtime_instr",
        ]
    } else {
        // Linux exposes no architecture-common raw-I/O syscall outside the families above. A
        // systemd version that expands this group on another architecture therefore fails closed;
        // versions retaining the requested group token remain supported.
        &[]
    };
    [
        (
            "@clock",
            &["adjtimex", "clock_adjtime", "clock_settime", "settimeofday"],
        ),
        (
            "@debug",
            &[
                "perf_event_open",
                "ptrace",
                "process_vm_readv",
                "process_vm_writev",
            ],
        ),
        ("@module", &["delete_module", "finit_module", "init_module"]),
        (
            "@mount",
            &[
                "fsconfig",
                "fsmount",
                "fsopen",
                "fspick",
                "mount",
                "mount_setattr",
                "move_mount",
                "pivot_root",
                "umount2",
            ],
        ),
        ("@obsolete", &["_sysctl", "sysfs"]),
        ("@raw-io", raw_io_representatives),
        ("@reboot", &["kexec_load", "reboot"]),
        ("@swap", &["swapon", "swapoff"]),
    ]
}

#[cfg(target_os = "linux")]
fn verify_effective_system_call_filter(
    kind: SideEffectConfinementProfileKind,
    value: &str,
) -> std::io::Result<()> {
    let tokens = value.split_whitespace().collect::<Vec<_>>();
    let configured_as_deny_list = tokens.first().is_some_and(|token| token.starts_with('~'));
    if !configured_as_deny_list {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "effective SystemCallFilter was not a deny list",
        ));
    }

    // Older systemd releases may retain group names here, while newer releases expose their
    // architecture-specific expansion. Require either the group token or every selected
    // architecture-common member from each requested group.
    for (group, representatives) in required_denied_group_representatives() {
        let retained_group = tokens
            .iter()
            .any(|token| token.trim_start_matches('~') == group);
        let expanded_group = !representatives.is_empty()
            && representatives.iter().all(|representative| {
                tokens
                    .iter()
                    .any(|token| token.trim_start_matches('~') == *representative)
            });
        if !retained_group && !expanded_group {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "effective SystemCallFilter omitted denied group {group} and its complete representative expansion"
                ),
            ));
        }
    }

    for syscall in REQUIRED_DENIED_SYSCALLS {
        if !tokens
            .iter()
            .any(|token| token.trim_start_matches('~') == *syscall)
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!("effective SystemCallFilter omitted denied syscall {syscall}"),
            ));
        }
    }
    if kind == SideEffectConfinementProfileKind::StrictOfflineWorkspace {
        for syscall in ["socket", "socketpair", "socketcall"] {
            if !tokens
                .iter()
                .any(|token| token.trim_start_matches('~') == syscall)
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    format!("effective SystemCallFilter omitted denied syscall {syscall}"),
                ));
            }
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn systemd_path_property(name: &str, path: &Path, optional: bool) -> OsString {
    let mut property = OsString::from("--property=");
    property.push(name);
    if optional {
        property.push("-");
    }
    property.push(path.as_os_str());
    property
}

#[cfg(target_os = "linux")]
fn known_sensitive_socket_paths() -> Vec<PathBuf> {
    // SAFETY: geteuid has no preconditions and does not access Rust memory.
    let uid = unsafe { libc::geteuid() };
    let user_runtime = PathBuf::from(format!("/run/user/{uid}"));
    [
        user_runtime.join("bus"),
        user_runtime.join("systemd"),
        user_runtime.join("gnupg"),
        user_runtime.join("keyring"),
        user_runtime.join("wayland-0"),
        user_runtime.join("pipewire-0"),
        user_runtime.join("pulse"),
        user_runtime.join("ssh-agent"),
        user_runtime.join("docker.sock"),
        user_runtime.join("podman"),
        user_runtime.join("libvirt"),
        PathBuf::from("/run/dbus/system_bus_socket"),
        PathBuf::from("/var/run/dbus/system_bus_socket"),
        PathBuf::from("/run/docker.sock"),
        PathBuf::from("/var/run/docker.sock"),
        PathBuf::from("/run/podman"),
        PathBuf::from("/run/libvirt"),
        PathBuf::from("/var/run/libvirt"),
        PathBuf::from("/run/credentials"),
        PathBuf::from("/run/secrets"),
        PathBuf::from("/run/keys"),
        PathBuf::from("/nix/var/nix/daemon-socket/socket"),
    ]
    .into_iter()
    .collect()
}

#[cfg(target_os = "linux")]
struct SystemdUnit {
    _permit: SystemdUnitPermit,
    systemd_run: PathBuf,
    systemctl: PathBuf,
    env_program: PathBuf,
    shell: PathBuf,
    sleep_program: PathBuf,
    stat_program: PathBuf,
    findmnt_program: PathBuf,
    name: String,
    cgroup_path: PathBuf,
    runtime_dir: PathBuf,
    client_runtime: PathBuf,
    environment_file: PathBuf,
    ready_path: PathBuf,
    waiting_path: PathBuf,
    environment_fifo_path: PathBuf,
    start_fifo_path: PathBuf,
    target_pid_path: PathBuf,
    owner_fifo_path: PathBuf,
    fifo_waiting_path: PathBuf,
    sandbox_report_path: PathBuf,
    owner_channel: Option<File>,
    pending_environment: Option<EnvironmentMode>,
    pending_runtime_files: Vec<PrivateRuntimeFile>,
    runtime_file_paths: Vec<PathBuf>,
    target_program_path: Option<PathBuf>,
    sandbox: Option<ResolvedSystemdSandbox>,
    sandbox_verified: bool,
    environment_published: bool,
    environment_released: bool,
    fifos_prepared: bool,
    launcher_spawned: bool,
    launcher_completed: bool,
    observed_owned: bool,
    cleaned: bool,
}

#[cfg(target_os = "linux")]
struct SystemdUnitPermit {
    file: File,
}

#[cfg(target_os = "linux")]
impl SystemdUnitPermit {
    fn acquire(
        runtime_root: &Path,
        operation_deadline: Option<Instant>,
        cancellation: &ProcessCancellation,
    ) -> std::io::Result<Self> {
        use std::os::unix::{
            fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
            io::AsRawFd,
        };

        // SAFETY: geteuid has no preconditions and does not access Rust memory.
        let effective_uid = unsafe { libc::geteuid() };
        let deadline = bounded_operation_deadline(SYSTEMD_SLOT_WAIT, operation_deadline)?;
        let max_concurrent_units = HostProcessCapacity::measured().systemd_unit_slots();
        loop {
            if cancellation.is_cancelled() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Interrupted,
                    "systemd containment slot acquisition was cancelled",
                ));
            }
            if Instant::now() >= deadline {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "no systemd containment execution slot became available before the bounded setup deadline",
                ));
            }
            let first_slot = if operation_deadline.is_some_and(|deadline| {
                deadline.saturating_duration_since(Instant::now())
                    <= EXPEDITED_SYSTEMD_SLOT_THRESHOLD
            }) {
                0
            } else {
                RESERVED_EXPEDITED_SYSTEMD_SLOTS
            };
            // Slot zero stays available for operations whose total deadline is at most one second;
            // longer and unbounded runs share the remaining slots.
            for slot in first_slot..max_concurrent_units {
                let path = runtime_root.join(format!("maco-process-runner-slot-{slot}.lock"));
                let file = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create(true)
                    .mode(0o600)
                    .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                    .open(&path)?;
                let metadata = file.metadata()?;
                if !metadata.is_file()
                    || metadata.uid() != effective_uid
                    || metadata.permissions().mode() & 0o077 != 0
                {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        format!("unsafe systemd containment slot file {}", path.display()),
                    ));
                }
                // SAFETY: flock operates on this live owned descriptor and does not access memory.
                if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
                    if cancellation.is_cancelled() {
                        drop(file);
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::Interrupted,
                            "systemd containment slot acquisition was cancelled",
                        ));
                    }
                    if Instant::now() >= deadline {
                        drop(file);
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "a systemd containment execution slot became available only after the bounded setup deadline",
                        ));
                    }
                    return Ok(Self { file });
                }
                let error = std::io::Error::last_os_error();
                let code = error.raw_os_error();
                if code != Some(libc::EWOULDBLOCK) && code != Some(libc::EAGAIN) {
                    return Err(error);
                }
            }
            if Instant::now() >= deadline {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!(
                        "no systemd containment execution slot became available within {} seconds",
                        SYSTEMD_SLOT_WAIT.as_secs()
                    ),
                ));
            }
            thread::sleep(POLL_INTERVAL);
        }
    }
}

#[cfg(target_os = "linux")]
impl Drop for SystemdUnitPermit {
    fn drop(&mut self) {
        use std::os::unix::io::AsRawFd;

        // SAFETY: unlocking this live descriptor is advisory cleanup; closing also releases it.
        let _ = unsafe { libc::flock(self.file.as_raw_fd(), libc::LOCK_UN) };
    }
}

#[cfg(target_os = "linux")]
impl SystemdUnit {
    fn prepare(
        operation_deadline: Option<Instant>,
        cancellation: &ProcessCancellation,
    ) -> std::io::Result<Self> {
        #[cfg(test)]
        if env::var_os("MACO_TEST_DISABLE_STRICT_CONTAINMENT").is_some() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "strict containment disabled by isolated regression test",
            ));
        }
        let client_runtime = trusted_linux_runtime_root()?;
        let permit = SystemdUnitPermit::acquire(&client_runtime, operation_deadline, cancellation)?;
        let systemd_run = find_trusted_unix_executable(
            "systemd-run",
            &[
                "/usr/bin/systemd-run",
                "/bin/systemd-run",
                "/run/current-system/sw/bin/systemd-run",
            ],
        )
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "strict containment requires a root-owned, non-writable systemd-run at a trusted system path",
            )
        })?;
        let shell = find_trusted_unix_executable(
            "sh",
            &["/bin/sh", "/usr/bin/sh", "/run/current-system/sw/bin/sh"],
        )
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "strict containment requires a root-owned, non-writable POSIX shell at a trusted system path",
            )
        })?;
        let systemctl = find_trusted_unix_executable(
            "systemctl",
            &[
                "/usr/bin/systemctl",
                "/bin/systemctl",
                "/run/current-system/sw/bin/systemctl",
            ],
        )
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "strict containment requires a root-owned, non-writable systemctl at a trusted system path",
            )
        })?;
        let env_program = find_trusted_unix_executable(
            "env",
            &["/usr/bin/env", "/bin/env", "/run/current-system/sw/bin/env"],
        )
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "strict containment requires a root-owned, non-writable env helper at a trusted system path",
            )
        })?;
        let sleep_program = find_trusted_unix_executable(
            "sleep",
            &[
                "/usr/bin/sleep",
                "/bin/sleep",
                "/run/current-system/sw/bin/sleep",
            ],
        )
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "strict containment requires a root-owned, non-writable sleep helper at a trusted system path",
            )
        })?;
        let stat_program = find_trusted_unix_executable(
            "stat",
            &[
                "/usr/bin/stat",
                "/bin/stat",
                "/run/current-system/sw/bin/stat",
            ],
        )
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "strict containment requires a root-owned, non-writable stat helper at a trusted system path",
            )
        })?;
        let findmnt_program = find_trusted_unix_executable(
            "findmnt",
            &[
                "/usr/bin/findmnt",
                "/bin/findmnt",
                "/run/current-system/sw/bin/findmnt",
            ],
        )
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "strict containment requires a root-owned, non-writable findmnt helper at a trusted system path",
            )
        })?;
        let manager_cgroup = systemd_user_manager_cgroup()?;
        let manager_path = Path::new("/sys/fs/cgroup").join(
            manager_cgroup
                .strip_prefix("/")
                .unwrap_or(manager_cgroup.as_path()),
        );
        if !manager_path.join("cgroup.controllers").is_file()
            || !manager_path.join("cgroup.kill").is_file()
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                format!(
                    "systemd user manager cgroup {} does not expose cgroup v2 kill/verification controls",
                    manager_path.display()
                ),
            ));
        }
        let sequence = NEXT_SYSTEMD_UNIT_ID.fetch_add(1, Ordering::Relaxed);
        let runner_pid = std::process::id();
        let name = format!("maco-process-{runner_pid}-{sequence}.service");
        let cgroup_path = manager_path.join("app.slice").join(&name);
        let runtime_dir = client_runtime
            .clone()
            .join(format!("maco-process-{runner_pid}-{sequence}"));
        let environment_file = runtime_dir.join("environment");
        let ready_path = runtime_dir.join("environment-ready");
        let waiting_path = runtime_dir.join("guardian-waiting");
        let environment_fifo_path = runtime_dir.join("environment-gate");
        let start_fifo_path = runtime_dir.join("start-gate");
        let target_pid_path = runtime_dir.join("target-pid");
        let owner_fifo_path = runtime_dir.join("owner-liveness");
        let fifo_waiting_path = runtime_dir.join("fifo-waiting");
        let sandbox_report_path = runtime_dir.join("sandbox-mount-report");
        Ok(Self {
            _permit: permit,
            systemd_run,
            systemctl,
            env_program,
            shell,
            sleep_program,
            stat_program,
            findmnt_program,
            name,
            cgroup_path,
            runtime_dir,
            client_runtime,
            environment_file,
            ready_path,
            waiting_path,
            environment_fifo_path,
            start_fifo_path,
            target_pid_path,
            owner_fifo_path,
            fifo_waiting_path,
            sandbox_report_path,
            owner_channel: None,
            pending_environment: None,
            pending_runtime_files: Vec::new(),
            runtime_file_paths: Vec::new(),
            target_program_path: None,
            sandbox: None,
            sandbox_verified: false,
            environment_published: false,
            environment_released: false,
            fifos_prepared: false,
            launcher_spawned: false,
            launcher_completed: false,
            observed_owned: false,
            cleaned: false,
        })
    }

    fn build_command(&mut self, spec: &ProcessSpec) -> std::io::Result<Command> {
        let target_environment = if spec.private_runtime_home || spec.private_runtime_codex_home {
            environment_with_private_runtime_home(
                &spec.environment,
                &self.runtime_dir,
                spec.private_runtime_home,
                spec.private_runtime_codex_home,
            )?
        } else {
            spec.environment.clone()
        };
        let mut private_runtime_files = spec.private_runtime_files.clone();
        let pinned_launch = if let Some(pinned) = &spec.pinned_direct {
            pinned.validate_command(&spec.command)?;
            let ProcessCommand::Direct { args, .. } = &spec.command else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "pinned executable capability requires a direct command",
                ));
            };
            let helper = pinned_exec::validated_current_helper_path()?;
            let environment = effective_environment(&target_environment)
                .into_iter()
                .collect::<Vec<_>>();
            let descriptor = pinned.executable.encode_descriptor(args, &environment)?;
            let (bytes, digest) = descriptor.into_parts();
            private_runtime_files.push(PrivateRuntimeFile {
                name: PINNED_EXEC_DESCRIPTOR_NAME.to_string(),
                bytes,
            });
            Some((helper, digest))
        } else {
            None
        };
        validate_private_runtime_files(&private_runtime_files)?;
        self.pending_runtime_files = private_runtime_files;
        self.pending_environment = Some(if pinned_launch.is_some() {
            EnvironmentMode::ClearAndSet(BTreeMap::new())
        } else {
            target_environment
        });
        let mut sandbox = resolve_systemd_sandbox(spec)?;
        let target_current_dir = sandbox
            .as_ref()
            .map_or(spec.current_dir.as_path(), |sandbox| {
                sandbox.current_dir.as_path()
            });
        let target_program_path = match &pinned_launch {
            Some((helper, _)) => helper.clone(),
            None => match &spec.command {
                ProcessCommand::Shell { .. } => self.shell.clone(),
                ProcessCommand::Direct { program, .. } if program.is_absolute() => {
                    normalized_absolute_program_invocation(program)
                }
                ProcessCommand::Direct { program, .. } if program.components().count() > 1 => {
                    normalized_absolute_program_invocation(&target_current_dir.join(program))
                }
                ProcessCommand::Direct { program, .. } => program.clone(),
            },
        };
        if let Some(sandbox) = sandbox.as_mut() {
            if pinned_launch.is_some() || matches!(&spec.command, ProcessCommand::Shell { .. }) {
                sandbox.validate_program_visibility(&target_program_path)?;
            }
            for helper in [
                &self.env_program,
                &self.shell,
                &self.sleep_program,
                &self.stat_program,
                &self.findmnt_program,
            ] {
                sandbox.add_isolated_runtime_file(helper)?;
            }
            if let Some((helper, _)) = &pinned_launch {
                sandbox.add_isolated_runtime_file(helper)?;
            }
            sandbox.add_private_runtime_root(&self.runtime_dir)?;
        }
        self.target_program_path = Some(target_program_path);
        let working_directory = sandbox
            .as_ref()
            .map(|sandbox| sandbox.current_dir.clone())
            .unwrap_or_else(|| spec.current_dir.clone());
        let runtime_name = self
            .runtime_dir
            .file_name()
            .and_then(OsStr::to_str)
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "systemd containment runtime directory name is not valid UTF-8",
                )
            })?;
        let runtime_max = systemd_runtime_max(spec.timeout)?;
        let mut command = Command::new(&self.systemd_run);
        command
            .env_clear()
            .env("XDG_RUNTIME_DIR", &self.client_runtime)
            .args([
                "--user",
                "--quiet",
                "--pipe",
                "--wait",
                "--collect",
                "--service-type=exec",
                "--slice=app.slice",
                "--expand-environment=no",
                "--property=KillMode=control-group",
                "--property=KillSignal=SIGKILL",
                "--property=FinalKillSignal=SIGKILL",
                "--property=ProtectControlGroups=yes",
                "--property=TimeoutStopSec=100ms",
                "--property=RuntimeDirectoryPreserve=no",
                "--property=RuntimeDirectoryMode=0700",
            ])
            .arg(format!("--property=RuntimeDirectory={runtime_name}"))
            .arg(format!(
                "--property=RuntimeMaxSec={}ms",
                runtime_max.as_millis()
            ));
        if let Some(sandbox) = &sandbox {
            apply_systemd_sandbox_properties(&mut command, sandbox);
            command
                .arg(systemd_path_property(
                    "BindPaths=",
                    &self.runtime_dir,
                    false,
                ))
                .arg(systemd_path_property(
                    "ReadWritePaths=",
                    &self.runtime_dir,
                    false,
                ));
        }
        self.sandbox = sandbox;
        command
            .arg("--unit")
            .arg(&self.name)
            .arg("--working-directory")
            .arg(&working_directory)
            .arg("--")
            .arg(&self.env_program)
            .arg("-i")
            .arg(&self.shell)
            .args([
                OsStr::new("-c"),
                OsStr::new(SYSTEMD_GUARDIAN_SCRIPT),
                OsStr::new("maco-containment-guardian"),
            ])
            .arg(&self.environment_file)
            .arg(&self.ready_path)
            .arg(&self.waiting_path)
            .arg(&self.environment_fifo_path)
            .arg(&self.start_fifo_path)
            .arg(&self.target_pid_path)
            .arg(&self.owner_fifo_path)
            .arg(&self.fifo_waiting_path)
            .arg(&self.sleep_program)
            .arg(&self.sandbox_report_path)
            .arg(&self.stat_program)
            .arg(&self.findmnt_program)
            .arg(&self.env_program)
            .arg(if pinned_launch.is_some() {
                "descriptor"
            } else {
                "source"
            })
            .arg(
                self.sandbox
                    .as_ref()
                    .map_or(0, |sandbox| sandbox.mount_checks.len())
                    .to_string(),
            );
        if let Some(sandbox) = &self.sandbox {
            for check in &sandbox.mount_checks {
                command
                    .arg(match check.access {
                        SandboxMountAccess::ReadOnly => "ro",
                        SandboxMountAccess::ReadWrite => "rw",
                        SandboxMountAccess::PrivateRuntime => "rw",
                        SandboxMountAccess::Inaccessible if check.optional => {
                            "inaccessible-optional"
                        }
                        SandboxMountAccess::Inaccessible => "inaccessible-required",
                        SandboxMountAccess::IsolatedRoot => "isolated-root",
                    })
                    .arg(&check.path);
            }
        }
        if let Some((helper, digest)) = pinned_launch {
            command
                .arg(helper)
                .arg(HIDDEN_PINNED_EXEC_ARGUMENT)
                .arg(self.runtime_dir.join(PINNED_EXEC_DESCRIPTOR_NAME))
                .arg(digest);
        } else {
            match &spec.command {
                ProcessCommand::Shell {
                    shell,
                    command: text,
                } => match shell {
                    Shell::UnixSh => {
                        command.arg(&self.shell).arg("-c").arg(text);
                    }
                    Shell::WindowsCmd => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            "Windows cmd shell cannot run through Linux systemd containment",
                        ));
                    }
                },
                ProcessCommand::Direct { program, args } => {
                    command.arg(program).args(args);
                }
            }
        }
        Ok(command)
    }

    fn confirm_attached(
        &mut self,
        child: &mut Child,
        operation_deadline: Option<Instant>,
        cancellation: &ProcessCancellation,
    ) -> std::io::Result<()> {
        let deadline = bounded_operation_deadline(SYSTEMD_OPERATION_GRACE, operation_deadline)?;
        loop {
            if cancellation.is_cancelled() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Interrupted,
                    "systemd containment attachment was cancelled",
                ));
            }
            if Instant::now() >= deadline {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!(
                        "systemd transient unit {} did not reach its start gate before the bounded setup deadline",
                        self.name
                    ),
                ));
            }
            if matches!(cgroup_populated(&self.cgroup_path)?, Some(true)) {
                self.observed_owned = true;
            }
            if !self.fifos_prepared && self.fifo_waiting_path.is_file() {
                prepare_systemd_gate_fifos(
                    &self.runtime_dir,
                    &self.fifo_waiting_path,
                    [
                        &self.environment_fifo_path,
                        &self.start_fifo_path,
                        &self.owner_fifo_path,
                    ],
                )?;
                self.fifos_prepared = true;
            }
            if self.observed_owned && self.owner_channel.is_none() && self.owner_fifo_path.exists()
            {
                match open_systemd_owner_fifo(&self.owner_fifo_path) {
                    Ok(channel) => self.owner_channel = Some(channel),
                    Err(error) if error.raw_os_error() == Some(libc::ENOENT) => {}
                    Err(error) => return Err(error),
                }
            }
            if self.owner_channel.is_some()
                && self.waiting_path.is_file()
                && !self.environment_published
            {
                for private_file in std::mem::take(&mut self.pending_runtime_files) {
                    let path = self.runtime_dir.join(&private_file.name);
                    self.runtime_file_paths.push(path.clone());
                    publish_private_runtime_file(&path, &private_file.bytes)?;
                }
                let environment = self.pending_environment.take().ok_or_else(|| {
                    std::io::Error::other("systemd containment omitted pending environment")
                })?;
                publish_systemd_environment_file(&self.environment_file, &environment)?;
                self.environment_published = true;
                #[cfg(test)]
                if let Some(marker) = env::var_os("MACO_TEST_ENVIRONMENT_PUBLISHED_MARKER") {
                    fs::write(marker, b"published")?;
                    while env::var_os("MACO_TEST_HOLD_AFTER_ENVIRONMENT_PUBLISH").is_some() {
                        thread::sleep(POLL_INTERVAL);
                    }
                }
            }
            if self.environment_published && !self.environment_released {
                match signal_systemd_fifo(&self.environment_fifo_path, b"environment\n") {
                    Ok(()) => self.environment_released = true,
                    Err(error) if error.raw_os_error() == Some(libc::ENXIO) => {}
                    Err(error) => return Err(error),
                }
            }
            if self.environment_released && self.ready_path.is_file() {
                if self.sandbox.is_some() && !self.sandbox_verified {
                    self.verify_effective_sandbox()?;
                    self.sandbox_verified = true;
                }
                #[cfg(test)]
                if env::var_os("MACO_TEST_ABORT_BEFORE_START_RELEASE").is_some() {
                    std::process::abort();
                }
                return Ok(());
            }
            if let Some(status) = child.try_wait()? {
                self.launcher_completed = true;
                let startup_output = collect_exited_child_startup_output(child);
                return Err(systemd_launcher_exit_error(
                    status,
                    &startup_output,
                    self.target_program_path.as_deref(),
                    "before transient-unit ownership was observed",
                ));
            }
            thread::sleep(IO_CANCEL_POLL_INTERVAL);
        }
    }

    fn side_effect_evidence(&self) -> SideEffectConfinementEvidence {
        match &self.sandbox {
            Some(sandbox) if self.sandbox_verified => {
                SideEffectConfinementEvidence::Verified(sandbox.kind)
            }
            Some(sandbox) => SideEffectConfinementEvidence::Unverified(sandbox.kind),
            None => SideEffectConfinementEvidence::TrustedBestEffort(
                SideEffectConfinementProfileKind::TrustedCompatibility,
            ),
        }
    }

    fn verify_effective_sandbox(&self) -> std::io::Result<()> {
        let sandbox = self.sandbox.as_ref().ok_or_else(|| {
            std::io::Error::other("strict sandbox verification omitted requested profile")
        })?;
        sandbox.verify_path_identities()?;
        verify_sandbox_mount_report(&self.sandbox_report_path, &sandbox.mount_checks)?;
        let properties = systemd_show_properties(
            &self.systemctl,
            &self.client_runtime,
            &self.name,
            SYSTEMD_SANDBOX_SHOW_PROPERTIES,
        )?;
        verify_systemd_sandbox_properties(sandbox, &properties, &self.runtime_dir)
    }

    fn release_start_gate(
        &mut self,
        child: &mut Child,
        operation_deadline: Option<Instant>,
        cancellation: &ProcessCancellation,
    ) -> std::io::Result<()> {
        let deadline = bounded_operation_deadline(SYSTEMD_OPERATION_GRACE, operation_deadline)?;
        remove_file_if_present(&self.environment_file).map_err(|error| {
            std::io::Error::new(
                error.kind(),
                format!(
                    "failed to remove consumed private environment file before releasing containment gate: {error}"
                ),
            )
        })?;
        remove_file_if_present(&self.owner_fifo_path).map_err(|error| {
            std::io::Error::new(
                error.kind(),
                format!("failed to unlink confirmed systemd owner-liveness FIFO: {error}"),
            )
        })?;
        loop {
            if cancellation.is_cancelled() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Interrupted,
                    "systemd containment start-gate release was cancelled",
                ));
            }
            match signal_systemd_fifo(&self.start_fifo_path, b"start\n") {
                Ok(()) => return Ok(()),
                Err(error) if error.raw_os_error() == Some(libc::ENXIO) => {}
                Err(error) => return Err(error),
            }
            if let Some(status) = child.try_wait()? {
                self.launcher_completed = true;
                let startup_output = collect_exited_child_startup_output(child);
                return Err(systemd_launcher_exit_error(
                    status,
                    &startup_output,
                    self.target_program_path.as_deref(),
                    "before the execution gate was released",
                ));
            }
            if Instant::now() >= deadline {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!(
                        "systemd transient unit {} did not consume its start gate before the bounded setup deadline",
                        self.name
                    ),
                ));
            }
            thread::sleep(IO_CANCEL_POLL_INTERVAL);
        }
    }

    fn target_pid(
        &mut self,
        child: &mut Child,
        operation_deadline: Option<Instant>,
        cancellation: &ProcessCancellation,
    ) -> std::io::Result<u32> {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

        let deadline = bounded_operation_deadline(SYSTEMD_OPERATION_GRACE, operation_deadline)?;
        loop {
            if cancellation.is_cancelled() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Interrupted,
                    "systemd target PID capture was cancelled",
                ));
            }
            let mut file = match OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
                .open(&self.target_pid_path)
            {
                Ok(file) => file,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    if let Some(status) = child.try_wait()? {
                        self.launcher_completed = true;
                        let startup_output = collect_exited_child_startup_output(child);
                        return Err(systemd_launcher_exit_error(
                            status,
                            &startup_output,
                            self.target_program_path.as_deref(),
                            "before target PID publication",
                        ));
                    }
                    if Instant::now() >= deadline {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "systemd target PID was not published before the setup deadline",
                        ));
                    }
                    thread::sleep(IO_CANCEL_POLL_INTERVAL);
                    continue;
                }
                Err(error) => return Err(error),
            };
            let metadata = file.metadata()?;
            // SAFETY: geteuid has no preconditions and does not access Rust memory.
            let effective_uid = unsafe { libc::geteuid() };
            if !metadata.is_file()
                || metadata.uid() != effective_uid
                || metadata.nlink() != 1
                || metadata.mode() & 0o077 != 0
                || metadata.len() > 32
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "systemd target PID record is not a bounded owner-private regular file",
                ));
            }
            let mut contents = String::new();
            file.read_to_string(&mut contents)?;
            let pid = contents.trim().parse::<u32>().map_err(|error| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("systemd target PID record is invalid: {error}"),
                )
            })?;
            if pid == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "systemd target PID record contains PID 0",
                ));
            }
            let rebound = fs::symlink_metadata(&self.target_pid_path)?;
            if !rebound.is_file()
                || rebound.dev() != metadata.dev()
                || rebound.ino() != metadata.ino()
            {
                return Err(std::io::Error::other(
                    "systemd target PID record changed while it was read",
                ));
            }
            let cgroup_processes = fs::read_to_string(self.cgroup_path.join("cgroup.procs"))?;
            let pid_text = pid.to_string();
            if !cgroup_processes
                .lines()
                .any(|entry| entry.trim() == pid_text)
            {
                return Err(std::io::Error::other(format!(
                    "systemd target PID {pid} is not owned by the prepared containment cgroup"
                )));
            }
            crate::agent_lifecycle::process_start_time(pid)
                .map_err(|error| std::io::Error::other(error.to_string()))?;
            let descriptor_metadata = file.metadata()?;
            if descriptor_metadata.dev() != metadata.dev()
                || descriptor_metadata.ino() != metadata.ino()
            {
                return Err(std::io::Error::other(
                    "systemd target PID descriptor changed unexpectedly",
                ));
            }
            return Ok(pid);
        }
    }

    fn cleanup(&mut self, _child: &mut Child, label: &str, context: &str) -> TreeCleanup {
        if self.cleaned {
            return TreeCleanup {
                error: None,
                process_tree: ProcessTreeEvidence::VerifiedEmpty(
                    ContainmentBackend::SystemdUserService,
                ),
                side_effects: SideEffectConfinementEvidence::Unverified(
                    SideEffectConfinementProfileKind::TrustedCompatibility,
                ),
            };
        }
        let error = self.kill_and_verify(label, context).err().map(|error| {
            format!(
                "{label} {context} could not verify empty systemd containment unit {}: {error}",
                self.name
            )
        });
        if error.is_none() && self.observed_owned {
            self.cleaned = true;
            self.remove_runtime_files();
        }
        TreeCleanup {
            process_tree: if error.is_none() && self.observed_owned {
                ProcessTreeEvidence::VerifiedEmpty(ContainmentBackend::SystemdUserService)
            } else {
                ProcessTreeEvidence::Unverified(ContainmentBackend::SystemdUserService)
            },
            side_effects: SideEffectConfinementEvidence::Unverified(
                SideEffectConfinementProfileKind::TrustedCompatibility,
            ),
            error,
        }
    }

    fn rollback_startup(&mut self, label: &str) -> std::io::Result<()> {
        self.owner_channel.take();
        if !self.launcher_spawned {
            self.cleaned = true;
            self.remove_runtime_files();
            return Ok(());
        }
        if self.observed_owned {
            self.kill_and_verify(label, "startup rollback")?;
            self.cleaned = true;
            self.remove_runtime_files();
            return Ok(());
        }
        if self.launcher_completed && cgroup_populated(&self.cgroup_path)?.is_none() {
            self.cleaned = true;
            self.remove_runtime_files();
            return Ok(());
        }
        let status = run_control_command_bounded(
            &self.systemctl,
            [
                OsStr::new("--user"),
                OsStr::new("--no-block"),
                OsStr::new("stop"),
                self.name.as_ref(),
            ],
            "systemctl startup rollback",
            &self.client_runtime,
        )?;
        if !status.success() {
            return Err(std::io::Error::other(format!(
                "systemctl stop for {} exited with {status}",
                self.name
            )));
        }
        let deadline = Instant::now() + SYSTEMD_OPERATION_GRACE;
        loop {
            match cgroup_populated(&self.cgroup_path)? {
                Some(true) => {
                    self.observed_owned = true;
                    return self.kill_and_verify(label, "startup rollback");
                }
                Some(false) => {
                    self.observed_owned = true;
                }
                None => {
                    self.cleaned = true;
                    self.remove_runtime_files();
                    return Ok(());
                }
            }
            if Instant::now() >= deadline {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "systemd startup rollback did not collect the transient unit",
                ));
            }
            thread::sleep(IO_CANCEL_POLL_INTERVAL);
        }
    }

    fn kill_and_verify(&mut self, _label: &str, _context: &str) -> std::io::Result<()> {
        if !self.observed_owned {
            return Err(std::io::Error::other(
                "systemd transient-unit ownership was never observed",
            ));
        }
        self.owner_channel.take();
        if matches!(cgroup_populated(&self.cgroup_path)?, Some(true)) {
            match OpenOptions::new()
                .write(true)
                .open(self.cgroup_path.join("cgroup.kill"))
                .and_then(|mut kill| kill.write_all(b"1\n"))
            {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
        }
        let deadline = Instant::now() + SYSTEMD_OPERATION_GRACE;
        loop {
            match cgroup_populated(&self.cgroup_path)? {
                None => return Ok(()),
                Some(false) if Instant::now() >= deadline => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        format!(
                            "cgroup became empty but the transient unit was not collected/inactive after {} ms",
                            SYSTEMD_OPERATION_GRACE.as_millis()
                        ),
                    ));
                }
                Some(false) => wait_for_lifecycle_progress(IO_CANCEL_POLL_INTERVAL),
                Some(true) if Instant::now() >= deadline => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        format!(
                            "cgroup remained populated after {} ms",
                            SYSTEMD_OPERATION_GRACE.as_millis()
                        ),
                    ));
                }
                Some(true) => wait_for_lifecycle_progress(IO_CANCEL_POLL_INTERVAL),
            }
        }
    }

    fn remove_runtime_files(&self) {
        for path in &self.runtime_file_paths {
            let _ = fs::remove_file(path);
        }
        let _ = fs::remove_file(&self.sandbox_report_path);
        let _ = fs::remove_file(&self.start_fifo_path);
        let _ = fs::remove_file(&self.target_pid_path);
        let _ = fs::remove_file(&self.owner_fifo_path);
        let _ = fs::remove_file(&self.environment_fifo_path);
        let _ = fs::remove_file(&self.fifo_waiting_path);
        let _ = fs::remove_file(&self.waiting_path);
        let _ = fs::remove_file(&self.ready_path);
        let _ = fs::remove_file(&self.environment_file);
        let _ = fs::remove_dir(&self.runtime_dir);
    }
}

#[cfg(target_os = "linux")]
fn systemd_show_properties(
    systemctl: &Path,
    client_runtime: &Path,
    unit: &str,
    names: &[&str],
) -> std::io::Result<BTreeMap<String, String>> {
    let mut args = vec![
        OsString::from("--user"),
        OsString::from("show"),
        OsString::from("--no-pager"),
    ];
    args.extend(
        names
            .iter()
            .map(|name| OsString::from(format!("--property={name}"))),
    );
    args.push(OsString::from(unit));
    let (status, stdout, stderr) = run_control_command_capture_bounded(
        systemctl,
        &args,
        "systemctl sandbox verification",
        client_runtime,
    )?;
    if !status.success() {
        return Err(std::io::Error::other(format!(
            "systemctl show for {unit} exited with {status}: {}",
            String::from_utf8_lossy(stderr.as_bytes()).trim()
        )));
    }
    if stdout.is_truncated() || stderr.is_truncated() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "systemctl sandbox verification output exceeded its bounded capture",
        ));
    }
    let stdout = std::str::from_utf8(stdout.as_bytes()).map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("systemctl sandbox verification output was not UTF-8: {error}"),
        )
    })?;
    let properties = stdout
        .lines()
        .filter_map(|line| line.split_once('='))
        .map(|(name, value)| (name.to_string(), value.to_string()))
        .collect::<BTreeMap<_, _>>();
    Ok(properties)
}

#[cfg(target_os = "linux")]
fn run_control_command_capture_bounded(
    program: &Path,
    args: &[OsString],
    label: &str,
    client_runtime: &Path,
) -> std::io::Result<(ExitStatus, CapturedBytes, CapturedBytes)> {
    use std::os::unix::process::CommandExt;

    let mut command = Command::new(program);
    command
        .env_clear()
        .env("XDG_RUNTIME_DIR", client_runtime)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    let mut child = command.spawn()?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| std::io::Error::other("systemctl stdout pipe was unavailable"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| std::io::Error::other("systemctl stderr pipe was unavailable"))?;
    configure_cancellable_io(&stdout)?;
    configure_cancellable_io(&stderr)?;
    let mut drainers =
        OutputDrainers::start(stdout, stderr, label, 64 * 1024, 64 * 1024, None, None);
    let deadline = Instant::now() + SYSTEMD_OPERATION_GRACE;
    let status = loop {
        let backlog = drainers.drain_ready();
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline {
            let cleanup = terminate_unix_process_group(&mut child, false, label);
            let status = wait_for_exit_until(&mut child, Instant::now() + SYSTEMD_OPERATION_GRACE)?
                .unwrap_or_else(|| fail_closed_stuck_owner(label));
            let detail = cleanup.unwrap_or_else(|| {
                format!("{label} exceeded its bounded deadline and was terminated with {status}")
            });
            let _ = finish_output_drainers_after_exit(&mut drainers, EXIT_AND_DRAIN_GRACE);
            let _ = drainers.cancel_incomplete(label);
            return Err(std::io::Error::new(std::io::ErrorKind::TimedOut, detail));
        }
        if !backlog {
            thread::sleep(POLL_INTERVAL);
        }
    };
    if !finish_output_drainers_after_exit(&mut drainers, EXIT_AND_DRAIN_GRACE) {
        let cleanup = drainers.cancel_incomplete(label);
        return Err(std::io::Error::other(
            cleanup.unwrap_or_else(|| format!("{label} output pipes did not close")),
        ));
    }
    let (stdout, stderr, output_error) = drainers.into_outputs();
    if let Some(error) = output_error {
        return Err(std::io::Error::other(error));
    }
    Ok((status, stdout, stderr))
}

#[cfg(target_os = "linux")]
fn run_control_command_bounded<'a>(
    program: &Path,
    args: impl IntoIterator<Item = &'a OsStr>,
    label: &str,
    client_runtime: &Path,
) -> std::io::Result<ExitStatus> {
    use std::os::unix::process::CommandExt;

    let mut command = Command::new(program);
    command
        .env_clear()
        .env("XDG_RUNTIME_DIR", client_runtime)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .process_group(0);
    let mut child = command.spawn()?;
    match wait_for_exit_until(&mut child, Instant::now() + SYSTEMD_OPERATION_GRACE)? {
        Some(status) => Ok(status),
        None => {
            let cleanup = terminate_unix_process_group(&mut child, false, label);
            match wait_for_exit_until(&mut child, Instant::now() + SYSTEMD_OPERATION_GRACE)? {
                Some(status) => {
                    if let Some(cleanup) = cleanup {
                        Err(std::io::Error::other(cleanup))
                    } else {
                        Err(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            format!("{label} exceeded its bounded deadline and was terminated with {status}"),
                        ))
                    }
                }
                None => fail_closed_stuck_owner(label),
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn classify_systemd_namespace_failure(
    status: ExitStatus,
    startup_output: &str,
    program: &Path,
) -> Option<EnvironmentFailure> {
    if status.code() != Some(226) {
        return None;
    }
    let namespace_corroborated = startup_output.to_ascii_uppercase().contains("NAMESPACE");
    let corroboration = if namespace_corroborated {
        "startup output also reported NAMESPACE"
    } else {
        "startup output did not repeat NAMESPACE"
    };
    Some(EnvironmentFailure::sandbox_unavailable(format!(
        "systemd reported exit status 226/NAMESPACE while preparing the sandbox for program {}; namespace setup failed before the program executed ({corroboration})",
        program.display(),
    )))
}

#[cfg(target_os = "linux")]
fn systemd_launcher_exit_error(
    status: ExitStatus,
    startup_output: &str,
    program: Option<&Path>,
    phase: &str,
) -> std::io::Error {
    let program = program.unwrap_or_else(|| Path::new("<unknown sandbox program>"));
    if let Some(failure) = classify_systemd_namespace_failure(status, startup_output, program) {
        return environment_failure_io(failure, false);
    }
    std::io::Error::other(format!(
        "systemd-run exited with {status} {phase}{startup_output}"
    ))
}

#[cfg(target_os = "linux")]
fn collect_exited_child_startup_output(child: &mut Child) -> String {
    fn read(stream: Option<impl Read>) -> String {
        let Some(stream) = stream else {
            return String::new();
        };
        let mut bytes = Vec::new();
        let _ = stream
            .take((PIPE_READ_CHUNK_SIZE * 4) as u64)
            .read_to_end(&mut bytes);
        String::from_utf8_lossy(&bytes).trim().to_string()
    }

    let stdout = read(child.stdout.take());
    let stderr = read(child.stderr.take());
    let mut details = Vec::new();
    if !stdout.is_empty() {
        details.push(format!("stdout={stdout:?}"));
    }
    if !stderr.is_empty() {
        details.push(format!("stderr={stderr:?}"));
    }
    if details.is_empty() {
        String::new()
    } else {
        format!("; startup output: {}", details.join("; "))
    }
}

#[cfg(target_os = "linux")]
impl Drop for SystemdUnit {
    fn drop(&mut self) {
        if !self.cleaned && self.launcher_spawned {
            if let Err(error) = self.rollback_startup("process") {
                fail_closed_stuck_owner(&format!(
                    "systemd containment drop rollback for {}: {error}",
                    self.name
                ));
            }
        }
        self.remove_runtime_files();
    }
}

#[cfg(target_os = "linux")]
fn systemd_user_manager_cgroup() -> std::io::Result<PathBuf> {
    let contents = fs::read_to_string("/proc/self/cgroup")?;
    let current = contents
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "strict containment requires a unified cgroup v2 hierarchy",
            )
        })?;
    let mut manager = PathBuf::from("/");
    for component in Path::new(current).components() {
        let std::path::Component::Normal(component) = component else {
            continue;
        };
        manager.push(component);
        let component = component.to_string_lossy();
        if component.starts_with("user@") && component.ends_with(".service") {
            return Ok(manager);
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        format!("current cgroup {current} is not inside a delegated systemd user manager"),
    ))
}

#[cfg(target_os = "linux")]
fn cgroup_populated(path: &Path) -> std::io::Result<Option<bool>> {
    let events = match fs::read_to_string(path.join("cgroup.events")) {
        Ok(events) => events,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    events
        .lines()
        .find_map(|line| line.strip_prefix("populated "))
        .map(|value| match value {
            "0" => Ok(false),
            "1" => Ok(true),
            other => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("unexpected cgroup populated value {other:?}"),
            )),
        })
        .transpose()?
        .map(Some)
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "cgroup.events omitted populated state",
            )
        })
}

#[cfg(unix)]
fn find_trusted_unix_executable(_name: &str, candidates: &[&str]) -> Option<PathBuf> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    candidates.iter().find_map(|candidate| {
        let canonical = fs::canonicalize(candidate).ok()?;
        let metadata = canonical.metadata().ok()?;
        (metadata.is_file()
            && metadata.uid() == 0
            && metadata.permissions().mode() & 0o111 != 0
            && metadata.permissions().mode() & 0o022 == 0)
            .then(|| PathBuf::from(candidate))
    })
}

pub(crate) fn trusted_system_executable(
    name: &str,
    candidates: &[&str],
) -> std::io::Result<PathBuf> {
    #[cfg(unix)]
    {
        find_trusted_unix_executable(name, candidates).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!(
                    "trusted root-owned, non-writable executable {name} was not found at a fixed path"
                ),
            )
        })
    }
    #[cfg(not(unix))]
    {
        let _ = (name, candidates);
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "fixed trusted executable resolution is not implemented on this platform",
        ))
    }
}

#[cfg(target_os = "linux")]
fn environment_with_private_runtime_home(
    mode: &EnvironmentMode,
    runtime_dir: &Path,
    set_home: bool,
    set_codex_home: bool,
) -> std::io::Result<EnvironmentMode> {
    let runtime_dir = runtime_dir.to_str().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "private systemd runtime HOME is not valid UTF-8: {}",
                runtime_dir.display()
            ),
        )
    })?;
    let (clear, mut values) = match mode {
        EnvironmentMode::Inherit => (false, BTreeMap::new()),
        EnvironmentMode::InheritAndSet(values) => (false, values.clone()),
        EnvironmentMode::ClearAndSet(values) => (true, values.clone()),
    };
    if set_home {
        values.insert("HOME".to_string(), runtime_dir.to_string());
        values.insert("TMPDIR".to_string(), runtime_dir.to_string());
    }
    if set_codex_home {
        values.insert("CODEX_HOME".to_string(), runtime_dir.to_string());
    }
    Ok(if clear {
        EnvironmentMode::ClearAndSet(values)
    } else {
        EnvironmentMode::InheritAndSet(values)
    })
}

#[cfg(target_os = "linux")]
fn effective_environment(mode: &EnvironmentMode) -> BTreeMap<OsString, OsString> {
    let mut environment = match mode {
        EnvironmentMode::Inherit | EnvironmentMode::InheritAndSet(_) => env::vars_os().collect(),
        EnvironmentMode::ClearAndSet(_) => BTreeMap::new(),
    };
    match mode {
        EnvironmentMode::Inherit => {}
        EnvironmentMode::InheritAndSet(values) | EnvironmentMode::ClearAndSet(values) => {
            environment.extend(
                values
                    .iter()
                    .map(|(name, value)| (OsString::from(name), OsString::from(value))),
            );
        }
    }
    environment
}

#[cfg(target_os = "linux")]
fn prepare_systemd_gate_fifos<'a>(
    runtime_dir: &Path,
    waiting_marker: &Path,
    fifo_paths: impl IntoIterator<Item = &'a PathBuf>,
) -> std::io::Result<()> {
    use std::os::unix::{ffi::OsStrExt, fs::FileTypeExt, fs::MetadataExt, fs::PermissionsExt};

    let metadata = fs::symlink_metadata(runtime_dir)?;
    // SAFETY: geteuid has no preconditions and does not access Rust memory.
    let effective_uid = unsafe { libc::geteuid() };
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != effective_uid
        || metadata.permissions().mode() & 0o777 != 0o700
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("unsafe systemd runtime directory {}", runtime_dir.display()),
        ));
    }
    let waiting_metadata = fs::symlink_metadata(waiting_marker)?;
    if waiting_marker.parent() != Some(runtime_dir)
        || waiting_metadata.file_type().is_symlink()
        || !waiting_metadata.is_file()
        || waiting_metadata.uid() != effective_uid
        || waiting_metadata.permissions().mode() & 0o777 != 0o600
        || waiting_metadata.nlink() != 1
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "unsafe systemd FIFO-wait marker {}",
                waiting_marker.display()
            ),
        ));
    }

    for path in fifo_paths {
        if path.parent() != Some(runtime_dir) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "systemd gate FIFO escaped its private runtime directory",
            ));
        }
        let fifo = std::ffi::CString::new(path.as_os_str().as_bytes()).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "systemd gate FIFO path contains a NUL byte",
            )
        })?;
        // SAFETY: fifo is a valid NUL-terminated path and the mode contains only permission bits.
        if unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        let metadata = fs::symlink_metadata(path)?;
        if !metadata.file_type().is_fifo()
            || metadata.uid() != effective_uid
            || metadata.permissions().mode() & 0o777 != 0o600
            || metadata.nlink() != 1
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!("unsafe systemd gate FIFO {}", path.display()),
            ));
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn open_systemd_owner_fifo(path: &Path) -> std::io::Result<File> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};

    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;
    // SAFETY: geteuid has no preconditions and does not access Rust memory.
    let effective_uid = unsafe { libc::geteuid() };
    if !metadata.file_type().is_fifo()
        || metadata.uid() != effective_uid
        || metadata.permissions().mode() & 0o777 != 0o600
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("unsafe systemd owner-liveness FIFO {}", path.display()),
        ));
    }
    Ok(file)
}

#[cfg(target_os = "linux")]
fn signal_systemd_fifo(path: &Path, token: &[u8]) -> std::io::Result<()> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};

    let mut gate = OpenOptions::new()
        .write(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let metadata = gate.metadata()?;
    // SAFETY: geteuid has no preconditions and does not access Rust memory.
    let effective_uid = unsafe { libc::geteuid() };
    if !metadata.file_type().is_fifo()
        || metadata.uid() != effective_uid
        || metadata.permissions().mode() & 0o777 != 0o600
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("systemd containment gate {} is not a FIFO", path.display()),
        ));
    }
    gate.write_all(token)
}

#[cfg(target_os = "linux")]
fn remove_file_if_present(path: &Path) -> std::io::Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

#[cfg(target_os = "linux")]
fn systemd_runtime_max(timeout: Option<Duration>) -> std::io::Result<Duration> {
    match timeout {
        Some(timeout) => timeout
            .checked_add(SYSTEMD_RUNTIME_OVERHEAD)
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "process timeout is too large to add the systemd cleanup allowance",
                )
            }),
        None => Ok(SYSTEMD_ORPHAN_SAFETY_FUSE),
    }
}

#[cfg(target_os = "linux")]
fn bounded_operation_deadline(
    platform_grace: Duration,
    operation_deadline: Option<Instant>,
) -> std::io::Result<Instant> {
    let now = Instant::now();
    if operation_deadline.is_some_and(|deadline| now >= deadline) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "the total operation deadline was exhausted during containment setup",
        ));
    }
    let platform_deadline = now.checked_add(platform_grace).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "platform containment grace exceeds the Instant range",
        )
    })?;
    Ok(operation_deadline
        .map(|deadline| deadline.min(platform_deadline))
        .unwrap_or(platform_deadline))
}

#[cfg(target_os = "linux")]
pub(crate) fn trusted_linux_runtime_root() -> std::io::Result<PathBuf> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    // SAFETY: geteuid has no preconditions and does not access Rust memory.
    let effective_uid = unsafe { libc::geteuid() };
    let user_runtime = PathBuf::from(format!("/run/user/{effective_uid}"));
    if user_runtime.metadata().is_ok_and(|metadata| {
        metadata.is_dir()
            && metadata.uid() == effective_uid
            && metadata.permissions().mode() & 0o077 == 0
    }) {
        return Ok(user_runtime);
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::PermissionDenied,
        "strict systemd containment requires an owner-private /run/user/<uid> runtime root",
    ))
}

#[cfg(target_os = "linux")]
fn validate_private_runtime_files(files: &[PrivateRuntimeFile]) -> std::io::Result<()> {
    if files.len() > MAX_PRIVATE_RUNTIME_FILES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "private runtime file vector exceeds its safety bound",
        ));
    }
    let mut names = std::collections::BTreeSet::new();
    for file in files {
        let path = Path::new(&file.name);
        if file.name.is_empty()
            || path.components().count() != 1
            || !matches!(
                path.components().next(),
                Some(std::path::Component::Normal(_))
            )
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "private runtime filename must be one safe component: {:?}",
                    file.name
                ),
            ));
        }
        if file.bytes.len() > MAX_PRIVATE_RUNTIME_FILE_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::FileTooLarge,
                format!(
                    "private runtime file {:?} exceeds the {} byte limit",
                    file.name, MAX_PRIVATE_RUNTIME_FILE_BYTES
                ),
            ));
        }
        if !names.insert(file.name.as_str()) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!("duplicate private runtime filename {:?}", file.name),
            ));
        }
        if matches!(
            file.name.as_str(),
            "environment"
                | "environment-ready"
                | "guardian-waiting"
                | "environment-gate"
                | "start-gate"
                | "target-pid"
                | "owner-liveness"
                | "fifo-waiting"
                | "sandbox-mount-report"
        ) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("private runtime filename is reserved: {:?}", file.name),
            ));
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn publish_private_runtime_file(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)?;
    let metadata = file.metadata()?;
    // SAFETY: geteuid has no preconditions and does not access Rust memory.
    let effective_uid = unsafe { libc::geteuid() };
    if !metadata.is_file()
        || metadata.uid() != effective_uid
        || metadata.permissions().mode() & 0o777 != 0o600
        || metadata.nlink() != 1
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("unsafe private runtime file {}", path.display()),
        ));
    }
    file.write_all(bytes)?;
    file.sync_all()?;
    File::open(path.parent().unwrap_or_else(|| Path::new(".")))?.sync_all()
}

#[cfg(target_os = "linux")]
fn publish_systemd_environment_file(path: &Path, mode: &EnvironmentMode) -> std::io::Result<()> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)?;
    let published = (|| {
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
        let metadata = file.metadata()?;
        // SAFETY: geteuid has no preconditions and does not access Rust memory.
        let effective_uid = unsafe { libc::geteuid() };
        if !metadata.is_file()
            || metadata.uid() != effective_uid
            || metadata.permissions().mode() & 0o777 != 0o600
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!("unsafe systemd environment file {}", path.display()),
            ));
        }
        for (name, value) in effective_environment(mode) {
            let name = name.to_str().ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "strict systemd containment cannot project a non-UTF-8 environment name",
                )
            })?;
            let valid_name = name.bytes().enumerate().all(|(index, byte)| {
                byte == b'_' || byte.is_ascii_alphabetic() || (index > 0 && byte.is_ascii_digit())
            });
            if name.is_empty() || !valid_name {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("invalid environment variable name {name:?}"),
                ));
            }
            let value = value.to_str().ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("strict systemd containment cannot project non-UTF-8 value for {name}"),
                )
            })?;
            let escaped = value.replace('\'', "'\\''");
            writeln!(file, "{name}='{escaped}'")?;
        }
        file.sync_all()?;
        File::open(path.parent().unwrap_or_else(|| Path::new(".")))?.sync_all()
    })();
    if published.is_err() {
        let matches = tee_path_matches_file(path, &file).unwrap_or(false);
        drop(file);
        if matches {
            let _ = fs::remove_file(path);
        }
    }
    published
}

#[cfg(unix)]
fn terminate_unix_process_group(
    child: &mut Child,
    child_already_exited: bool,
    label: &str,
) -> Option<String> {
    terminate_unix_process_group_with_wait(
        child,
        child_already_exited,
        label,
        wait_for_lifecycle_progress,
    )
}

#[cfg(unix)]
fn wait_for_lifecycle_progress(duration: Duration) {
    thread::sleep(duration);
}

#[cfg(unix)]
fn terminate_unix_process_group_with_wait<F>(
    child: &mut Child,
    child_already_exited: bool,
    label: &str,
    mut wait: F,
) -> Option<String>
where
    F: FnMut(Duration),
{
    let pid = child.id();
    match send_unix_process_group_signal(pid, libc::SIGTERM) {
        Ok(GroupSignalResult::Sent) => {
            wait(TERMINATE_GRACE);
            match send_unix_process_group_signal(pid, libc::SIGKILL) {
                Ok(GroupSignalResult::Sent | GroupSignalResult::Missing) => None,
                Err(group_error) => direct_child_kill_after_group_error(
                    child,
                    child_already_exited,
                    label,
                    group_error,
                ),
            }
        }
        Ok(GroupSignalResult::Missing) if child_already_exited => None,
        Ok(GroupSignalResult::Missing) if matches!(child.try_wait(), Ok(Some(_))) => None,
        Ok(GroupSignalResult::Missing) => child.kill().err().map(|error| {
            format!("{label} process group was missing and direct process kill failed: {error}")
        }),
        Err(group_error) => {
            direct_child_kill_after_group_error(child, child_already_exited, label, group_error)
        }
    }
}

#[cfg(unix)]
fn direct_child_kill_after_group_error(
    child: &mut Child,
    child_already_exited: bool,
    label: &str,
    group_error: std::io::Error,
) -> Option<String> {
    if child_already_exited || matches!(child.try_wait(), Ok(Some(_))) {
        return Some(format!(
            "{label} process group termination failed: {group_error}"
        ));
    }
    match child.kill() {
        Ok(()) => Some(format!(
            "{label} process group termination failed: {group_error}; direct child was killed"
        )),
        Err(child_error) => Some(format!(
            "{label} process group termination failed: {group_error}; direct process kill failed: {child_error}"
        )),
    }
}

#[cfg(unix)]
enum GroupSignalResult {
    Sent,
    Missing,
}

#[cfg(unix)]
fn send_unix_process_group_signal(
    pid: u32,
    signal: libc::c_int,
) -> std::io::Result<GroupSignalResult> {
    let pid = libc::pid_t::try_from(pid).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("process id {pid} cannot be represented as a Unix process group"),
        )
    })?;
    // SAFETY: a negative nonzero pid addresses the child-created process group; no Rust memory is
    // accessed and `signal` is a valid libc signal constant supplied by the caller.
    if unsafe { libc::kill(-pid, signal) } == 0 {
        return Ok(GroupSignalResult::Sent);
    }
    let error = std::io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ESRCH) {
        Ok(GroupSignalResult::Missing)
    } else {
        Err(error)
    }
}

#[cfg(target_os = "windows")]
struct WindowsJob {
    handle: WindowsOwnedHandle,
}

#[cfg(target_os = "windows")]
impl WindowsJob {
    fn create_and_assign(child: &Child) -> std::io::Result<Self> {
        use std::{mem::size_of, os::windows::io::AsRawHandle, ptr};
        use windows_sys::Win32::{
            Foundation::HANDLE,
            System::JobObjects::{
                AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
                SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
                JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
            },
        };

        // SAFETY: null security attributes/name request an unnamed job owned by this process.
        let handle = unsafe { CreateJobObjectW(ptr::null(), ptr::null()) };
        if handle.is_null() {
            return Err(std::io::Error::other(format!(
                "CreateJobObjectW failed: {}",
                std::io::Error::last_os_error()
            )));
        }
        let job = Self {
            handle: WindowsOwnedHandle { handle },
        };
        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        // SAFETY: `limits` is initialized for the requested information class and valid for the
        // duration of the call; `job.handle` remains owned by `job`.
        let configured = unsafe {
            SetInformationJobObject(
                job.handle.raw(),
                JobObjectExtendedLimitInformation,
                ptr::from_ref(&limits).cast(),
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        };
        if configured == 0 {
            return Err(std::io::Error::other(format!(
                "SetInformationJobObject(KILL_ON_JOB_CLOSE) failed: {}",
                std::io::Error::last_os_error()
            )));
        }

        let process_handle = child.as_raw_handle() as HANDLE;
        // SAFETY: `process_handle` is borrowed from the live child and `job.handle` is valid.
        if unsafe { AssignProcessToJobObject(job.handle.raw(), process_handle) } == 0 {
            return Err(std::io::Error::other(format!(
                "AssignProcessToJobObject failed: {}",
                std::io::Error::last_os_error()
            )));
        }
        Ok(job)
    }

    fn terminate(&self, label: &str, context: &str) -> Option<String> {
        use windows_sys::Win32::System::JobObjects::TerminateJobObject;

        // SAFETY: the handle is valid while `self` is alive. The exit code is diagnostic only.
        if unsafe { TerminateJobObject(self.handle.raw(), 1) } != 0 {
            None
        } else {
            Some(format!(
                "{label} {context} failed in TerminateJobObject: {}",
                std::io::Error::last_os_error()
            ))
        }
    }

    fn cleanup(
        &self,
        label: &str,
        context: &str,
        side_effects: SideEffectConfinementEvidence,
    ) -> TreeCleanup {
        let error = append_error(
            self.terminate(label, context),
            self.wait_until_empty(label, context),
        );
        TreeCleanup {
            process_tree: if error.is_none() {
                ProcessTreeEvidence::VerifiedEmpty(ContainmentBackend::WindowsJobObject)
            } else {
                ProcessTreeEvidence::Unverified(ContainmentBackend::WindowsJobObject)
            },
            side_effects,
            error,
        }
    }

    fn wait_until_empty(&self, label: &str, context: &str) -> Option<String> {
        use std::{mem::size_of, ptr};
        use windows_sys::Win32::System::JobObjects::{
            JobObjectBasicAccountingInformation, QueryInformationJobObject,
            JOBOBJECT_BASIC_ACCOUNTING_INFORMATION,
        };

        let deadline = Instant::now() + EXIT_AND_DRAIN_GRACE;
        loop {
            let mut accounting = JOBOBJECT_BASIC_ACCOUNTING_INFORMATION::default();
            // SAFETY: `accounting` is valid writable storage for the requested information class.
            let queried = unsafe {
                QueryInformationJobObject(
                    self.handle.raw(),
                    JobObjectBasicAccountingInformation,
                    ptr::from_mut(&mut accounting).cast(),
                    size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
                    ptr::null_mut(),
                )
            };
            if queried == 0 {
                return Some(format!(
                    "{label} {context} failed to query Windows Job emptiness: {}",
                    std::io::Error::last_os_error()
                ));
            }
            if accounting.ActiveProcesses == 0 {
                return None;
            }
            if Instant::now() >= deadline {
                return Some(format!(
                    "{label} {context} Windows Job remained populated after {} ms",
                    EXIT_AND_DRAIN_GRACE.as_millis()
                ));
            }
            thread::sleep(IO_CANCEL_POLL_INTERVAL);
        }
    }
}

#[cfg(target_os = "windows")]
struct WindowsOwnedHandle {
    handle: windows_sys::Win32::Foundation::HANDLE,
}

#[cfg(target_os = "windows")]
impl WindowsOwnedHandle {
    fn raw(&self) -> windows_sys::Win32::Foundation::HANDLE {
        self.handle
    }
}

#[cfg(target_os = "windows")]
impl Drop for WindowsOwnedHandle {
    fn drop(&mut self) {
        use windows_sys::Win32::Foundation::CloseHandle;

        // SAFETY: this RAII owner closes its valid handle exactly once.
        let _ = unsafe { CloseHandle(self.handle) };
    }
}

#[cfg(target_os = "windows")]
fn resume_suspended_child(child: &Child) -> std::io::Result<()> {
    use std::mem::size_of;
    use windows_sys::Win32::{
        Foundation::{ERROR_NO_MORE_FILES, INVALID_HANDLE_VALUE},
        System::{
            Diagnostics::ToolHelp::{
                CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD,
                THREADENTRY32,
            },
            Threading::{OpenThread, ResumeThread, THREAD_SUSPEND_RESUME},
        },
    };

    // SAFETY: the snapshot API has no borrowed pointer inputs and returns an owned handle.
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
    if snapshot == INVALID_HANDLE_VALUE {
        return Err(std::io::Error::other(format!(
            "CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD) failed: {}",
            std::io::Error::last_os_error()
        )));
    }
    let snapshot = WindowsOwnedHandle { handle: snapshot };
    let mut entry = THREADENTRY32 {
        dwSize: size_of::<THREADENTRY32>() as u32,
        ..THREADENTRY32::default()
    };
    // SAFETY: `entry` is correctly sized writable storage and the snapshot handle is valid.
    if unsafe { Thread32First(snapshot.raw(), &mut entry) } == 0 {
        return Err(std::io::Error::other(format!(
            "Thread32First failed while locating suspended child thread: {}",
            std::io::Error::last_os_error()
        )));
    }

    let mut thread_ids = Vec::new();
    loop {
        if entry.th32OwnerProcessID == child.id() {
            thread_ids.push(entry.th32ThreadID);
        }
        entry.dwSize = size_of::<THREADENTRY32>() as u32;
        // SAFETY: the same valid snapshot and writable entry storage are reused for iteration.
        if unsafe { Thread32Next(snapshot.raw(), &mut entry) } != 0 {
            continue;
        }
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(ERROR_NO_MORE_FILES as i32) {
            return Err(std::io::Error::other(format!(
                "Thread32Next failed while locating suspended child thread: {error}"
            )));
        }
        break;
    }
    if thread_ids.len() != 1 {
        return Err(std::io::Error::other(format!(
            "expected exactly one suspended primary thread for child {}, found {}",
            child.id(),
            thread_ids.len()
        )));
    }

    // SAFETY: the enumerated thread id belongs to the still-suspended child process; the returned
    // handle is owned locally and is not inheritable.
    let thread_handle = unsafe { OpenThread(THREAD_SUSPEND_RESUME, 0, thread_ids[0]) };
    if thread_handle.is_null() {
        return Err(std::io::Error::other(format!(
            "OpenThread(THREAD_SUSPEND_RESUME) failed: {}",
            std::io::Error::last_os_error()
        )));
    }
    let thread_handle = WindowsOwnedHandle {
        handle: thread_handle,
    };
    // SAFETY: the handle identifies the unique suspended primary thread owned by the child.
    let previous_suspend_count = unsafe { ResumeThread(thread_handle.raw()) };
    if previous_suspend_count == u32::MAX {
        return Err(std::io::Error::other(format!(
            "ResumeThread failed: {}",
            std::io::Error::last_os_error()
        )));
    }
    if previous_suspend_count != 1 {
        return Err(std::io::Error::other(format!(
            "ResumeThread observed unexpected suspend count {previous_suspend_count}; refusing to run child"
        )));
    }
    Ok(())
}

fn wait_for_exit_until(
    child: &mut Child,
    deadline: Instant,
) -> std::io::Result<Option<ExitStatus>> {
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(Some(status));
        }
        if Instant::now() >= deadline {
            return Ok(None);
        }
        thread::sleep(POLL_INTERVAL);
    }
}

fn append_error(existing: Option<String>, next: Option<String>) -> Option<String> {
    match (existing, next) {
        (Some(existing), Some(next)) => Some(format!("{existing}; {next}")),
        (Some(existing), None) => Some(existing),
        (None, Some(next)) => Some(next),
        (None, None) => None,
    }
}

struct PreparedChildIo {
    stdin: Option<ChildStdin>,
    stdout: ChildStdout,
    stderr: ChildStderr,
}

impl PreparedChildIo {
    fn take(child: &mut Child, stdin_mode: &StdinMode) -> std::io::Result<Self> {
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| std::io::Error::other("failed to open child stdout pipe"))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| std::io::Error::other("failed to open child stderr pipe"))?;
        let stdin = if matches!(stdin_mode, StdinMode::Bytes(_) | StdinMode::Interactive) {
            Some(
                child
                    .stdin
                    .take()
                    .ok_or_else(|| std::io::Error::other("failed to open child stdin pipe"))?,
            )
        } else {
            None
        };

        configure_cancellable_io(&stdout)?;
        configure_cancellable_io(&stderr)?;
        if let Some(stdin) = &stdin {
            configure_cancellable_io(stdin)?;
        }
        Ok(Self {
            stdin,
            stdout,
            stderr,
        })
    }

    fn start(
        self,
        label: &str,
        stdin_mode: StdinMode,
        stdout_limit: usize,
        stderr_limit: usize,
        stdout_tee: Option<TeeWriter>,
        stderr_tee: Option<TeeWriter>,
    ) -> (InputWriter, OutputDrainers) {
        let input_writer = InputWriter::start(self.stdin, label, stdin_mode);
        let output_drainers = OutputDrainers::start(
            self.stdout,
            self.stderr,
            label,
            stdout_limit,
            stderr_limit,
            stdout_tee,
            stderr_tee,
        );
        (input_writer, output_drainers)
    }

    #[allow(clippy::too_many_arguments)]
    fn start_interactive<'a>(
        self,
        label: &str,
        cancellation: &'a ProcessCancellation,
        operation_deadline: Option<Instant>,
        max_stdin_bytes: usize,
        stdout_limit: usize,
        stderr_limit: usize,
        stdout_tee: Option<TeeWriter>,
        stderr_tee: Option<TeeWriter>,
    ) -> std::io::Result<ContainedProcessSession<'a>> {
        let stdin = self.stdin.ok_or_else(|| {
            std::io::Error::other("failed to open contained interactive stdin pipe")
        })?;
        Ok(ContainedProcessSession {
            label: label.to_string(),
            cancellation,
            operation_deadline,
            stdin: Some(stdin),
            stdin_bytes_written: 0,
            max_stdin_bytes,
            pending_stdout: Vec::new(),
            stdout_eof: false,
            io_error: None,
            output_drainers: OutputDrainers::start(
                self.stdout,
                self.stderr,
                label,
                stdout_limit,
                stderr_limit,
                stdout_tee,
                stderr_tee,
            ),
        })
    }
}

/// Borrowed line-oriented access to one contained child.
///
/// All fields are private and the value is constructed only after containment attachment and the
/// start gate. The callback receives `&mut ContainedProcessSession`, so neither this value nor any
/// stdio handle can be retained after [`run_process_interactive`] returns.
pub(crate) struct ContainedProcessSession<'a> {
    label: String,
    cancellation: &'a ProcessCancellation,
    operation_deadline: Option<Instant>,
    stdin: Option<ChildStdin>,
    stdin_bytes_written: usize,
    max_stdin_bytes: usize,
    pending_stdout: Vec<u8>,
    stdout_eof: bool,
    io_error: Option<String>,
    output_drainers: OutputDrainers,
}

impl ContainedProcessSession<'_> {
    pub(crate) fn receive_line(
        &mut self,
        wait: Duration,
        max_line_bytes: usize,
        destination: &mut Vec<u8>,
    ) -> Result<InteractiveProcessRead, String> {
        destination.clear();
        if max_line_bytes == 0 || max_line_bytes > MAX_REQUIRED_STREAM_BYTES {
            return self.fail_io("interactive line bound is zero or exceeds the hard ceiling");
        }
        if let Some(line) = self.take_pending_line(max_line_bytes)? {
            destination.extend_from_slice(&line);
            return Ok(InteractiveProcessRead::Line);
        }
        if self.stdout_eof {
            return Ok(InteractiveProcessRead::Eof);
        }

        let requested_deadline = Instant::now()
            .checked_add(wait)
            .unwrap_or_else(Instant::now);
        let deadline = self
            .operation_deadline
            .map_or(requested_deadline, |operation| {
                operation.min(requested_deadline)
            });
        loop {
            self.ensure_interactive_live()?;
            let now = Instant::now();
            if now >= deadline {
                return Ok(InteractiveProcessRead::Timeout);
            }
            self.output_drainers.stderr.drain_ready(&self.label);
            let remaining = deadline.saturating_duration_since(now);
            match self
                .output_drainers
                .stdout
                .receive_interactive(remaining, &self.label)?
            {
                InteractivePipeRead::Chunk(chunk) => {
                    self.pending_stdout.extend_from_slice(&chunk);
                    if let Some(line) = self.take_pending_line(max_line_bytes)? {
                        destination.extend_from_slice(&line);
                        return Ok(InteractiveProcessRead::Line);
                    }
                }
                InteractivePipeRead::Timeout => return Ok(InteractiveProcessRead::Timeout),
                InteractivePipeRead::Eof => {
                    self.stdout_eof = true;
                    if self.pending_stdout.is_empty() {
                        return Ok(InteractiveProcessRead::Eof);
                    }
                    if self.pending_stdout.len() > max_line_bytes {
                        return self.fail_io(
                            "contained interactive message exceeded its configured line bound",
                        );
                    }
                    destination.extend_from_slice(&self.pending_stdout);
                    self.pending_stdout.clear();
                    return Ok(InteractiveProcessRead::Line);
                }
            }
        }
    }

    pub(crate) fn send_line(&mut self, line: &[u8]) -> Result<(), String> {
        if line.contains(&b'\n') || line.contains(&b'\r') {
            return self.fail_io("contained interactive line contains a raw newline");
        }
        let framed_len = line.len().checked_add(1).ok_or_else(|| {
            "contained interactive stdin byte count overflowed its bound".to_string()
        })?;
        let next_total = self
            .stdin_bytes_written
            .checked_add(framed_len)
            .ok_or_else(|| {
                "contained interactive stdin byte count overflowed its bound".to_string()
            })?;
        if next_total > self.max_stdin_bytes {
            return self
                .fail_io("contained interactive stdin exceeded its configured aggregate bound");
        }
        let mut framed = Vec::with_capacity(framed_len);
        framed.extend_from_slice(line);
        framed.push(b'\n');
        let mut written = 0usize;
        while written < framed.len() {
            self.ensure_interactive_live()?;
            self.output_drainers.stderr.drain_ready(&self.label);
            let Some(stdin) = self.stdin.as_mut() else {
                return self.fail_io("contained interactive stdin was already closed");
            };
            match stdin.write(&framed[written..]) {
                Ok(0) => {
                    return self
                        .fail_io("contained interactive stdin returned a zero-length write");
                }
                Ok(count) => written = written.saturating_add(count),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(IO_CANCEL_POLL_INTERVAL);
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(error) => {
                    return self.fail_io(format!(
                        "failed to write contained interactive stdin: {error}"
                    ));
                }
            }
        }
        self.stdin_bytes_written = next_total;
        Ok(())
    }

    fn take_pending_line(&mut self, max_line_bytes: usize) -> Result<Option<Vec<u8>>, String> {
        let Some(newline) = self.pending_stdout.iter().position(|byte| *byte == b'\n') else {
            if self.pending_stdout.len() > max_line_bytes {
                return self
                    .fail_io("contained interactive message exceeded its configured line bound");
            }
            return Ok(None);
        };
        if newline > max_line_bytes {
            return self
                .fail_io("contained interactive message exceeded its configured line bound");
        }
        let mut line = self.pending_stdout.drain(..=newline).collect::<Vec<_>>();
        line.pop();
        if line.last() == Some(&b'\r') {
            line.pop();
        }
        Ok(Some(line))
    }

    fn ensure_interactive_live(&mut self) -> Result<(), String> {
        if self.cancellation.is_cancelled() {
            return self.fail_io("contained interactive session was cancelled");
        }
        if self
            .operation_deadline
            .is_some_and(|deadline| Instant::now() >= deadline)
        {
            return self.fail_io("contained interactive session reached its operation deadline");
        }
        Ok(())
    }

    fn fail_io<T>(&mut self, message: impl Into<String>) -> Result<T, String> {
        let message = message.into();
        if self.io_error.is_none() {
            self.io_error = Some(message.clone());
        }
        Err(message)
    }

    fn into_runner_io(mut self) -> (InputWriter, OutputDrainers) {
        drop(self.stdin.take());
        (InputWriter::completed(self.io_error), self.output_drainers)
    }
}

#[cfg(unix)]
fn configure_cancellable_io<T: std::os::fd::AsRawFd>(io: &T) -> std::io::Result<()> {
    let fd = io.as_raw_fd();
    // SAFETY: `fd` is borrowed from a live child pipe and both fcntl operations preserve ownership.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags == -1 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: the same live descriptor is updated only to add nonblocking mode.
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } == -1 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(unix))]
fn configure_cancellable_io<T>(_io: &T) -> std::io::Result<()> {
    Ok(())
}

#[derive(Debug, Error)]
enum IoThreadCleanupError {
    #[error("{label} synchronous I/O cancellation failed: {source}")]
    Cancellation {
        label: String,
        #[source]
        source: std::io::Error,
    },
    #[error("{label} thread panicked during cleanup")]
    Panicked { label: String },
}

struct OwnedIoThread {
    handle: thread::JoinHandle<()>,
    cancel: Arc<AtomicBool>,
}

trait IoThreadClock {
    type Deadline;

    fn deadline_after(&self, duration: Duration) -> Self::Deadline;
    fn before(&self, deadline: &Self::Deadline) -> bool;
    fn wait(&self, duration: Duration);
}

struct RealIoThreadClock;

impl IoThreadClock for RealIoThreadClock {
    type Deadline = Instant;

    fn deadline_after(&self, duration: Duration) -> Self::Deadline {
        Instant::now()
            .checked_add(duration)
            .unwrap_or_else(Instant::now)
    }

    fn before(&self, deadline: &Self::Deadline) -> bool {
        Instant::now() < *deadline
    }

    fn wait(&self, duration: Duration) {
        thread::sleep(duration);
    }
}

/// Unit-test finalization advances by the waits the poller requested, excluding time when the
/// poller itself was descheduled by unrelated host load. Production always uses
/// `RealIoThreadClock`, while focused deadline tests can inject their own clocks directly.
#[cfg(test)]
#[derive(Default)]
struct TestIoFinalizationClock {
    elapsed: std::cell::Cell<Duration>,
}

#[cfg(test)]
impl IoThreadClock for TestIoFinalizationClock {
    type Deadline = Duration;

    fn deadline_after(&self, duration: Duration) -> Self::Deadline {
        self.elapsed.get().saturating_add(duration)
    }

    fn before(&self, deadline: &Self::Deadline) -> bool {
        self.elapsed.get() < *deadline
    }

    fn wait(&self, duration: Duration) {
        thread::sleep(duration);
        self.elapsed
            .set(self.elapsed.get().saturating_add(duration));
    }
}

impl OwnedIoThread {
    fn request_cancel(&self, label: &str) -> Option<IoThreadCleanupError> {
        self.cancel.store(true, Ordering::Release);
        cancel_synchronous_io(&self.handle)
            .err()
            .map(|source| IoThreadCleanupError::Cancellation {
                label: label.to_string(),
                source,
            })
    }

    fn finish(self, completion_observed: bool, label: &str) -> Vec<IoThreadCleanupError> {
        self.finish_with_clock(completion_observed, label, &RealIoThreadClock)
    }

    fn finish_with_clock<C: IoThreadClock>(
        self,
        completion_observed: bool,
        label: &str,
        clock: &C,
    ) -> Vec<IoThreadCleanupError> {
        let mut errors = Vec::new();
        if !completion_observed {
            if let Some(error) = self.request_cancel(label) {
                errors.push(error);
            }
        }
        let Self { handle, .. } = self;
        let deadline = clock.deadline_after(THREAD_JOIN_GRACE);
        while !handle.is_finished() && clock.before(&deadline) {
            clock.wait(IO_CANCEL_POLL_INTERVAL);
        }
        if !handle.is_finished() {
            fail_closed_stuck_owner(label);
        }
        if handle.join().is_err() {
            errors.push(IoThreadCleanupError::Panicked {
                label: label.to_string(),
            });
        }
        errors
    }
}

#[cfg(target_os = "windows")]
fn cancel_synchronous_io(handle: &thread::JoinHandle<()>) -> std::io::Result<()> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::{Foundation::ERROR_NOT_FOUND, System::IO::CancelSynchronousIo};

    let deadline = Instant::now() + THREAD_JOIN_GRACE;
    loop {
        if handle.is_finished() {
            return Ok(());
        }
        // SAFETY: the raw handle is borrowed from the live owned JoinHandle and identifies the
        // exact thread whose synchronous pipe operation must be cancelled.
        if unsafe { CancelSynchronousIo(handle.as_raw_handle().cast()) } != 0 {
            return Ok(());
        }
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(ERROR_NOT_FOUND as i32) {
            return Err(error);
        }
        if Instant::now() >= deadline {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "thread never exposed a cancellable synchronous I/O operation",
            ));
        }
        thread::sleep(IO_CANCEL_POLL_INTERVAL);
    }
}

#[cfg(not(target_os = "windows"))]
fn cancel_synchronous_io(_handle: &thread::JoinHandle<()>) -> std::io::Result<()> {
    Ok(())
}

fn cleanup_errors(errors: Vec<IoThreadCleanupError>) -> Option<String> {
    let errors = errors
        .into_iter()
        .map(|error| error.to_string())
        .collect::<Vec<_>>();
    (!errors.is_empty()).then(|| errors.join("; "))
}

struct InputWriter {
    state: InputWriterState,
}

enum InputWriterState {
    None,
    Complete {
        error: Option<String>,
    },
    Thread {
        receiver: Receiver<Option<String>>,
        thread: OwnedIoThread,
        error: Option<String>,
        complete: bool,
    },
}

impl InputWriter {
    fn completed(error: Option<String>) -> Self {
        Self {
            state: InputWriterState::Complete { error },
        }
    }

    fn start(child_stdin: Option<ChildStdin>, label: &str, stdin: StdinMode) -> Self {
        let StdinMode::Bytes(input) = stdin else {
            return Self {
                state: InputWriterState::None,
            };
        };
        let Some(mut child_stdin) = child_stdin else {
            return Self {
                state: InputWriterState::Complete {
                    error: Some(format!("failed to open {label} stdin")),
                },
            };
        };
        let (sender, receiver) = mpsc::channel();
        let label = label.to_string();
        let cancel = Arc::new(AtomicBool::new(false));
        let thread_cancel = Arc::clone(&cancel);
        let handle = thread::spawn(move || {
            let error = write_stdin_cancellable(&mut child_stdin, &input, &thread_cancel, &label);
            let _ = sender.send(error);
        });
        Self {
            state: InputWriterState::Thread {
                receiver,
                thread: OwnedIoThread { handle, cancel },
                error: None,
                complete: false,
            },
        }
    }

    fn drain_ready(&mut self) {
        let InputWriterState::Thread {
            receiver,
            error,
            complete,
            ..
        } = &mut self.state
        else {
            return;
        };
        if *complete {
            return;
        }
        match receiver.try_recv() {
            Ok(next_error) => {
                *error = next_error;
                *complete = true;
            }
            Err(TryRecvError::Empty) => {}
            Err(TryRecvError::Disconnected) => {
                *error = Some("stdin writer thread stopped unexpectedly".to_string());
                *complete = true;
            }
        }
    }

    fn is_complete(&self) -> bool {
        match &self.state {
            InputWriterState::None | InputWriterState::Complete { .. } => true,
            InputWriterState::Thread { complete, .. } => *complete,
        }
    }

    fn finish_with_clock<C: IoThreadClock>(&mut self, clock: &C, deadline: &C::Deadline) -> bool {
        loop {
            self.drain_ready();
            if self.is_complete() {
                return true;
            }
            if !clock.before(deadline) {
                return false;
            }
            clock.wait(POLL_INTERVAL);
        }
    }

    fn cancel_incomplete(&mut self, label: &str) -> Option<String> {
        let InputWriterState::Thread {
            thread, complete, ..
        } = &self.state
        else {
            return None;
        };
        if *complete {
            None
        } else {
            cleanup_errors(
                thread
                    .request_cancel(&format!("{label} stdin writer"))
                    .into_iter()
                    .collect(),
            )
        }
    }

    fn into_result(self, label: &str) -> (Option<String>, Option<String>) {
        match self.state {
            InputWriterState::None => (None, None),
            InputWriterState::Complete { error } => (error, None),
            InputWriterState::Thread {
                receiver,
                thread,
                mut error,
                complete,
            } => {
                let cleanup_error =
                    cleanup_errors(thread.finish(complete, &format!("{label} stdin writer")));
                if !complete {
                    match receiver.try_recv() {
                        Ok(next_error) => error = next_error,
                        Err(TryRecvError::Empty | TryRecvError::Disconnected) => {}
                    }
                }
                (error, cleanup_error)
            }
        }
    }
}

fn write_stdin_cancellable(
    child_stdin: &mut ChildStdin,
    input: &[u8],
    cancel: &AtomicBool,
    label: &str,
) -> Option<String> {
    let mut written = 0;
    while written < input.len() {
        if cancel.load(Ordering::Acquire) {
            return Some(format!(
                "cancelled {label} stdin after writing {written} of {} bytes",
                input.len()
            ));
        }
        match child_stdin.write(&input[written..]) {
            Ok(0) => {
                return Some(format!(
                    "failed to write {label} stdin: write returned zero after {written} bytes"
                ));
            }
            Ok(bytes) => written += bytes,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(IO_CANCEL_POLL_INTERVAL);
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) if cancel.load(Ordering::Acquire) => {
                return Some(format!(
                    "cancelled {label} stdin after writing {written} of {} bytes: {error}",
                    input.len()
                ));
            }
            Err(error) => return Some(format!("failed to write {label} stdin: {error}")),
        }
    }
    None
}

struct OutputDrainers {
    stdout: PipeReader,
    stderr: PipeReader,
    label: String,
}

impl OutputDrainers {
    fn start(
        stdout: ChildStdout,
        stderr: ChildStderr,
        label: &str,
        stdout_limit: usize,
        stderr_limit: usize,
        stdout_tee: Option<TeeWriter>,
        stderr_tee: Option<TeeWriter>,
    ) -> Self {
        Self {
            stdout: start_pipe_reader("stdout", stdout, stdout_tee, label, stdout_limit),
            stderr: start_pipe_reader("stderr", stderr, stderr_tee, label, stderr_limit),
            label: label.to_string(),
        }
    }

    fn drain_ready(&mut self) -> bool {
        let stdout_backlog = self.stdout.drain_ready(&self.label);
        let stderr_backlog = self.stderr.drain_ready(&self.label);
        stdout_backlog || stderr_backlog
    }

    fn is_complete(&self) -> bool {
        self.stdout.complete && self.stderr.complete
    }

    fn finish_with_clock<C: IoThreadClock>(&mut self, clock: &C, deadline: &C::Deadline) -> bool {
        loop {
            let backlog = self.drain_ready();
            if self.is_complete() {
                return true;
            }
            if !clock.before(deadline) {
                return false;
            }
            if !backlog {
                clock.wait(POLL_INTERVAL);
            }
        }
    }

    fn cancel_incomplete(&mut self, label: &str) -> Option<String> {
        append_error(
            self.stdout.cancel_incomplete(label),
            self.stderr.cancel_incomplete(label),
        )
    }

    fn into_outputs(self) -> (CapturedBytes, CapturedBytes, Option<String>) {
        let (stdout, stdout_error) = self.stdout.into_output(&self.label);
        let (stderr, stderr_error) = self.stderr.into_output(&self.label);
        (stdout, stderr, append_error(stdout_error, stderr_error))
    }
}

struct PipeReader {
    stream: &'static str,
    receiver: Option<Receiver<PipeReadEvent>>,
    thread: Option<OwnedIoThread>,
    tee_helper: Option<TeeHelperHandle>,
    capture: BoundedBuffer,
    complete: bool,
    error: Option<String>,
}

enum InteractivePipeRead {
    Chunk(Vec<u8>),
    Timeout,
    Eof,
}

impl PipeReader {
    fn receive_interactive(
        &mut self,
        wait: Duration,
        label: &str,
    ) -> Result<InteractivePipeRead, String> {
        if self.complete {
            return match &self.error {
                Some(error) => Err(error.clone()),
                None => Ok(InteractivePipeRead::Eof),
            };
        }
        let deadline = Instant::now()
            .checked_add(wait)
            .unwrap_or_else(Instant::now);
        loop {
            let Some(receiver) = &self.receiver else {
                let message = format!("{label} {} receiver is unavailable", self.stream);
                self.error = Some(message.clone());
                self.complete = true;
                return Err(message);
            };
            let remaining = deadline.saturating_duration_since(Instant::now());
            let event = match receiver.recv_timeout(remaining) {
                Ok(event) => event,
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    return Ok(InteractivePipeRead::Timeout);
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    let message =
                        format!("{label} {} reader thread stopped unexpectedly", self.stream);
                    self.error = Some(message.clone());
                    self.complete = true;
                    return Err(message);
                }
            };
            match event {
                PipeReadEvent::Chunk(chunk) => {
                    self.capture.push(&chunk);
                    return Ok(InteractivePipeRead::Chunk(chunk));
                }
                PipeReadEvent::Finished => {
                    self.complete = true;
                    return Ok(InteractivePipeRead::Eof);
                }
                PipeReadEvent::Error(error) => {
                    self.error = Some(error.clone());
                    self.complete = true;
                    return Err(error);
                }
                PipeReadEvent::TeeLimitExceeded(error) => {
                    self.error = append_error(self.error.take(), Some(error));
                    if Instant::now() >= deadline {
                        return Ok(InteractivePipeRead::Timeout);
                    }
                }
            }
        }
    }

    fn cancel_incomplete(&mut self, label: &str) -> Option<String> {
        if self.complete {
            return None;
        }
        self.thread.as_ref().and_then(|thread| {
            cleanup_errors(
                thread
                    .request_cancel(&format!("{label} {} reader", self.stream))
                    .into_iter()
                    .collect(),
            )
        })
    }

    fn drain_ready(&mut self, label: &str) -> bool {
        let Some(receiver) = &self.receiver else {
            return false;
        };
        let mut processed = 0;
        while !self.complete && processed < MAX_PIPE_EVENTS_PER_POLL {
            match receiver.try_recv() {
                Ok(PipeReadEvent::Chunk(chunk)) => {
                    processed += 1;
                    self.capture.push(&chunk);
                }
                Ok(PipeReadEvent::Finished) => {
                    processed += 1;
                    self.complete = true;
                }
                Ok(PipeReadEvent::Error(error)) => {
                    processed += 1;
                    self.error = Some(error);
                    self.complete = true;
                }
                Ok(PipeReadEvent::TeeLimitExceeded(error)) => {
                    processed += 1;
                    self.error = append_error(self.error.take(), Some(error));
                }
                Err(TryRecvError::Empty) => return false,
                Err(TryRecvError::Disconnected) => {
                    self.error = Some(format!(
                        "{label} {} reader thread stopped unexpectedly",
                        self.stream
                    ));
                    self.complete = true;
                }
            }
        }
        !self.complete && processed == MAX_PIPE_EVENTS_PER_POLL
    }

    fn into_output(mut self, label: &str) -> (CapturedBytes, Option<String>) {
        let cleanup_error = self.thread.take().and_then(|thread| {
            cleanup_errors(thread.finish(self.complete, &format!("{label} {} reader", self.stream)))
        });
        self.drain_after_join();
        let tee_error = self
            .tee_helper
            .take()
            .and_then(|helper| helper.finish(label, self.stream));
        (
            self.capture.into_captured(),
            append_error(append_error(self.error, cleanup_error), tee_error),
        )
    }

    fn drain_after_join(&mut self) {
        let Some(receiver) = &self.receiver else {
            return;
        };
        loop {
            match receiver.try_recv() {
                Ok(PipeReadEvent::Chunk(chunk)) => self.capture.push(&chunk),
                Ok(PipeReadEvent::Finished) => self.complete = true,
                Ok(PipeReadEvent::Error(error)) => {
                    self.error = Some(error);
                    self.complete = true;
                }
                Ok(PipeReadEvent::TeeLimitExceeded(error)) => {
                    self.error = append_error(self.error.take(), Some(error));
                }
                Err(TryRecvError::Empty | TryRecvError::Disconnected) => break,
            }
        }
    }
}

enum PipeReadEvent {
    Chunk(Vec<u8>),
    Finished,
    Error(String),
    TeeLimitExceeded(String),
}

fn start_pipe_reader<R>(
    stream: &'static str,
    mut reader: R,
    tee: Option<TeeWriter>,
    label: &str,
    capture_limit: usize,
) -> PipeReader
where
    R: Read + Send + 'static,
{
    let (mut tee, tee_helper, tee_path) = match tee {
        Some(tee) => {
            let (sink, helper, path) = tee.split();
            (Some(sink), helper, Some(path))
        }
        None => (None, None, None),
    };
    let (sender, receiver) = mpsc::sync_channel(PIPE_CHANNEL_CAPACITY);
    let label = label.to_string();
    let cancel = Arc::new(AtomicBool::new(false));
    let thread_cancel = Arc::clone(&cancel);
    let handle = thread::spawn(move || loop {
        let mut buffer = vec![0_u8; PIPE_READ_CHUNK_SIZE];
        if thread_cancel.load(Ordering::Acquire) {
            break;
        }
        match reader.read(&mut buffer) {
            Ok(0) => {
                let _ = send_pipe_event(&sender, &thread_cancel, PipeReadEvent::Finished);
                break;
            }
            Ok(bytes_read) => {
                buffer.truncate(bytes_read);
                if let Some(tee) = tee.as_mut() {
                    match tee.write_all_cancellable(&buffer, &thread_cancel) {
                        Ok(true) => {
                            let _ = send_pipe_event(
                                &sender,
                                &thread_cancel,
                                PipeReadEvent::TeeLimitExceeded(format!(
                                    "{label} {stream} tee {} exceeded its configured byte limit",
                                    tee_path
                                        .as_deref()
                                        .map(Path::display)
                                        .map(|path| path.to_string())
                                        .unwrap_or_else(|| "<unknown>".to_string())
                                )),
                            );
                        }
                        Ok(false) => {}
                        Err(error) => {
                            if thread_cancel.load(Ordering::Acquire) {
                                break;
                            }
                            if send_pipe_event(
                                &sender,
                                &thread_cancel,
                                PipeReadEvent::Chunk(buffer),
                            )
                            .is_ok()
                            {
                                let _ = send_pipe_event(
                                    &sender,
                                    &thread_cancel,
                                    PipeReadEvent::Error(format!(
                                        "failed to write {label} {stream} tee {}: {error}",
                                        tee_path
                                            .as_deref()
                                            .map(Path::display)
                                            .map(|path| path.to_string())
                                            .unwrap_or_else(|| "<unknown>".to_string())
                                    )),
                                );
                            }
                            break;
                        }
                    }
                }
                if send_pipe_event(&sender, &thread_cancel, PipeReadEvent::Chunk(buffer)).is_err() {
                    break;
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(IO_CANCEL_POLL_INTERVAL);
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_error) if thread_cancel.load(Ordering::Acquire) => break,
            Err(error) => {
                let _ = send_pipe_event(
                    &sender,
                    &thread_cancel,
                    PipeReadEvent::Error(format!("failed to read {label} {stream}: {error}")),
                );
                break;
            }
        }
    });

    PipeReader {
        stream,
        receiver: Some(receiver),
        thread: Some(OwnedIoThread { handle, cancel }),
        tee_helper,
        capture: BoundedBuffer::new(capture_limit),
        complete: false,
        error: None,
    }
}

fn send_pipe_event(
    sender: &SyncSender<PipeReadEvent>,
    cancel: &AtomicBool,
    mut event: PipeReadEvent,
) -> Result<(), ()> {
    loop {
        if cancel.load(Ordering::Acquire) {
            return Err(());
        }
        match sender.try_send(event) {
            Ok(()) => return Ok(()),
            Err(TrySendError::Full(next)) => {
                event = next;
                thread::sleep(IO_CANCEL_POLL_INTERVAL);
            }
            Err(TrySendError::Disconnected(_)) => return Err(()),
        }
    }
}

struct BoundedBuffer {
    bytes: Vec<u8>,
    limit: usize,
    truncated: bool,
}

impl BoundedBuffer {
    fn new(limit: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(limit.min(PIPE_READ_CHUNK_SIZE)),
            limit,
            truncated: false,
        }
    }

    fn push(&mut self, chunk: &[u8]) {
        let remaining = self.limit.saturating_sub(self.bytes.len());
        let keep = remaining.min(chunk.len());
        self.bytes.extend_from_slice(&chunk[..keep]);
        if keep < chunk.len() {
            self.truncated = true;
        }
    }

    fn into_captured(self) -> CapturedBytes {
        CapturedBytes {
            bytes: self.bytes,
            truncated: self.truncated,
        }
    }
}

fn duration_millis(duration: Duration) -> u64 {
    duration.as_millis().min(u64::MAX as u128) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn sandbox_program_visibility_rejects_private_tmp_and_hidden_roots() {
        let hidden_roots = vec![PathBuf::from("/srv/private")];
        for program in [
            Path::new("/tmp/target/debug/probe"),
            Path::new("/var/tmp/target/debug/probe"),
            Path::new("/srv/private/bin/probe"),
        ] {
            let error = validate_systemd_program_visibility(program, &hidden_roots)
                .expect_err("hidden program path must be rejected");
            let (failure, target_process_started) =
                environment_failure_from_source(&error).expect("typed environment failure");
            assert_eq!(
                failure.category,
                crate::external_agent::EnvironmentFailureCategory::SandboxUnavailable
            );
            assert!(!target_process_started);
            assert!(failure.summary.contains(&program.display().to_string()));
        }

        assert!(validate_systemd_program_visibility(
            Path::new("/opt/maco/bin/probe"),
            &hidden_roots
        )
        .is_ok());
        assert!(validate_systemd_program_visibility(
            Path::new("/tmp-adjacent/bin/probe"),
            &hidden_roots
        )
        .is_ok());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn sandbox_program_visibility_checks_invocation_and_canonical_symlink_paths() {
        use std::os::unix::{fs::symlink, fs::PermissionsExt};

        let private_tmp = tempfile::Builder::new()
            .prefix("maco-private-tmp-link-")
            .tempdir_in("/tmp")
            .expect("private tmp symlink directory");
        let hidden_invocation = private_tmp.path().join("probe");
        symlink("/usr/bin/true", &hidden_invocation).expect("symlink hidden invocation");
        let spec = ProcessSpec::direct(
            "hidden invocation",
            &hidden_invocation,
            Vec::<OsString>::new(),
            Path::new("/"),
            128,
        );
        let paths = resolved_direct_program_paths(&spec, Path::new("/"))
            .expect("resolve hidden invocation and target");
        assert_eq!(paths.first(), Some(&hidden_invocation));
        assert!(validate_systemd_program_visibility(&paths[0], &[]).is_err());
        assert!(validate_systemd_program_visibility(&paths[1], &[]).is_ok());

        let hidden_target_root = tempfile::Builder::new()
            .prefix("maco-hidden-target-")
            .tempdir_in("/var/tmp")
            .expect("hidden target directory");
        let hidden_target = hidden_target_root.path().join("probe");
        fs::write(&hidden_target, b"#!/bin/sh\nexit 0\n").expect("hidden target");
        fs::set_permissions(&hidden_target, fs::Permissions::from_mode(0o755))
            .expect("hidden target permissions");
        let visible_invocation_root = tempfile::Builder::new()
            .prefix("maco-visible-link-")
            .tempdir_in("/dev/shm")
            .expect("visible symlink directory");
        let visible_invocation = visible_invocation_root.path().join("probe");
        symlink(&hidden_target, &visible_invocation).expect("symlink to hidden target");
        let spec = ProcessSpec::direct(
            "hidden target",
            &visible_invocation,
            Vec::<OsString>::new(),
            Path::new("/"),
            128,
        );
        let paths = resolved_direct_program_paths(&spec, Path::new("/"))
            .expect("resolve visible invocation and hidden target");
        assert!(validate_systemd_program_visibility(&paths[0], &[]).is_ok());
        assert_eq!(paths.get(1), Some(&hidden_target));
        assert!(validate_systemd_program_visibility(&paths[1], &[]).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn systemd_namespace_exit_classifier_is_typed_and_corroboration_aware() {
        use std::os::unix::process::ExitStatusExt;

        let program = Path::new("/tmp/maco-target/debug/probe");
        let corroborated = classify_systemd_namespace_failure(
            ExitStatus::from_raw(226 << 8),
            "Failed at step NAMESPACE spawning child",
            program,
        )
        .expect("226 with NAMESPACE must be typed");
        assert_eq!(
            corroborated.category,
            crate::external_agent::EnvironmentFailureCategory::SandboxUnavailable
        );
        assert!(corroborated.summary.contains("226/NAMESPACE"));
        assert!(corroborated.summary.contains("also reported NAMESPACE"));

        let uncorroborated = classify_systemd_namespace_failure(
            ExitStatus::from_raw(226 << 8),
            "transient unit failed",
            program,
        )
        .expect("226 without NAMESPACE output must still be typed");
        assert!(uncorroborated.summary.contains("did not repeat NAMESPACE"));
        assert!(classify_systemd_namespace_failure(
            ExitStatus::from_raw(17 << 8),
            "NAMESPACE",
            program,
        )
        .is_none());

        let typed = process_ownership_error(
            "sandbox probe".to_string(),
            program.display().to_string(),
            systemd_launcher_exit_error(
                ExitStatus::from_raw(226 << 8),
                "Failed at step NAMESPACE spawning child",
                Some(program),
                "before target PID publication",
            ),
        );
        assert!(matches!(
            &typed,
            ProcessRunError::EnvironmentFailure {
                failure,
                target_process_started: false,
                ..
            } if failure.category
                == crate::external_agent::EnvironmentFailureCategory::SandboxUnavailable
        ));
        assert!(typed.to_string().contains(&program.display().to_string()));

        let unrelated = process_ownership_error(
            "sandbox probe".to_string(),
            program.display().to_string(),
            systemd_launcher_exit_error(
                ExitStatus::from_raw(17 << 8),
                "NAMESPACE",
                Some(program),
                "before target PID publication",
            ),
        );
        assert!(matches!(
            unrelated,
            ProcessRunError::ProcessOwnership { .. }
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn sandbox_environment_failure_message_names_cause_and_program_path() {
        let program = Path::new("/tmp/maco-target/debug/probe");
        let source = validate_systemd_program_visibility(program, &[])
            .expect_err("PrivateTmp-hidden program must fail preflight");
        let error = containment_setup_error(
            "hostile scope probe".to_string(),
            program.display().to_string(),
            source,
        );
        let rendered = error.to_string();
        assert!(rendered.contains("sandbox environment is unavailable"));
        assert!(rendered.contains("PrivateTmp=yes"));
        assert!(rendered.contains(&program.display().to_string()));
        assert!(!is_verified_backend_unavailable(&error));
    }

    #[cfg(unix)]
    fn assert_process_not_executable(pid: &str, context: &str) {
        let process_state = Command::new("ps")
            .args(["-o", "stat=", "-p", pid.trim()])
            .output()
            .unwrap_or_else(|error| panic!("inspect {context} process state: {error}"));
        if process_state.status.success() {
            let state = String::from_utf8_lossy(&process_state.stdout);
            assert!(
                matches!(state.trim().as_bytes().first(), Some(b'Z' | b'X')),
                "{context} remained executable after owned lifecycle completion: {state:?}"
            );
        }
    }

    #[cfg(unix)]
    fn assert_process_gone(pid: &str, context: &str) {
        let pid = pid
            .trim()
            .parse::<libc::pid_t>()
            .unwrap_or_else(|error| panic!("parse {context} pid: {error}"));
        // Reaping is the behavior under test, so this remains a real-time liveness fuse. Thirty
        // seconds is deliberately much wider than the three-second operation contract below;
        // expiry means the PID remained allocated, not that ordinary cleanup was slightly late.
        let deadline = Instant::now()
            .checked_add(Duration::from_secs(30))
            .expect("representable process-reaping deadline");
        loop {
            // SAFETY: signal 0 probes whether the captured PID still exists without delivering a
            // signal. A zombie must continue to return success here and therefore cannot pass.
            if unsafe { libc::kill(pid, 0) } == -1 {
                let error = std::io::Error::last_os_error();
                assert_eq!(
                    error.raw_os_error(),
                    Some(libc::ESRCH),
                    "probe {context} existence: {error}"
                );
                break;
            }
            assert!(
                Instant::now() < deadline,
                "{context} PID still existed after the process-reaping liveness margin"
            );
            thread::sleep(POLL_INTERVAL);
        }
    }

    #[cfg(unix)]
    #[test]
    fn nonpublishable_trusted_compatibility_interactive_session_round_trips() {
        let temp = tempfile::tempdir().expect("tempdir");
        let spec = ProcessSpec::direct(
            "interactive JSONL child",
            PathBuf::from("/bin/sh"),
            [
                OsString::from("-c"),
                OsString::from(
                    "IFS= read -r request && test \"$request\" = '{\"request\":1}' && printf '%s\\n' '{\"response\":1}'",
                ),
            ],
            temp.path(),
            1024,
        )
        .with_stdin_limit(1024)
        .with_timeout(Some(Duration::from_secs(5)))
        .with_containment(ContainmentPolicy::TrustedBestEffort);
        let result = run_process_interactive(spec, &ProcessCancellation::new(), |session| {
            session.send_line(br#"{"request":1}"#)?;
            let mut response = Vec::new();
            let read = session.receive_line(Duration::from_secs(1), 1024, &mut response)?;
            Ok((read, response))
        })
        .expect("run contained interactive child");

        let (read, response) = result.interaction.expect("interactive exchange");
        assert_eq!(read, InteractiveProcessRead::Line);
        assert_eq!(response, br#"{"response":1}"#);
        assert!(result.process.status.is_some_and(|status| status.success()));
        assert!(matches!(
            result.process.process_tree,
            ProcessTreeEvidence::TrustedBestEffort(ContainmentBackend::UnixProcessGroup)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn nonpublishable_trusted_compatibility_interactive_rejects_unframed_input() {
        let temp = tempfile::tempdir().expect("tempdir");
        let spec = ProcessSpec::direct(
            "interactive malformed input child",
            PathBuf::from("/bin/sh"),
            [OsString::from("-c"), OsString::from("read -r _ || true")],
            temp.path(),
            1024,
        )
        .with_stdin_limit(1024)
        .with_timeout(Some(Duration::from_secs(5)))
        .with_containment(ContainmentPolicy::TrustedBestEffort);
        let result = run_process_interactive(spec, &ProcessCancellation::new(), |session| {
            session.send_line(b"two\nframes")
        })
        .expect("run contained interactive child");

        assert!(result
            .interaction
            .is_err_and(|message| message.contains("raw newline")));
        assert!(matches!(
            result.process.process_tree,
            ProcessTreeEvidence::TrustedBestEffort(ContainmentBackend::UnixProcessGroup)
        ));
        assert!(result.process.stdin_error.is_some());
    }

    #[cfg(unix)]
    #[test]
    fn nonpublishable_trusted_compatibility_interactive_panic_is_redacted() {
        let temp = tempfile::tempdir().expect("tempdir");
        let spec = ProcessSpec::direct(
            "interactive panicking handler child",
            PathBuf::from("/bin/sh"),
            [OsString::from("-c"), OsString::from("read -r _ || true")],
            temp.path(),
            1024,
        )
        .with_stdin_limit(1024)
        .with_timeout(Some(Duration::from_secs(5)))
        .with_containment(ContainmentPolicy::TrustedBestEffort);
        let result =
            run_process_interactive::<(), _>(spec, &ProcessCancellation::new(), |_session| {
                panic!("sensitive panic details")
            })
            .expect("runner must preserve process evidence after handler panic");

        assert!(result.interaction.is_err_and(|message| {
            message.contains("handler panicked") && !message.contains("sensitive panic details")
        }));
        assert!(matches!(
            result.process.process_tree,
            ProcessTreeEvidence::TrustedBestEffort(ContainmentBackend::UnixProcessGroup)
        ));
        assert!(result.process.status.is_some());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn verified_contained_interactive_session_proves_tree_and_side_effects() {
        let temp = tempfile::tempdir().expect("tempdir");
        let spec = ProcessSpec::direct(
            "verified interactive JSONL child",
            PathBuf::from("/bin/sh"),
            [
                OsString::from("-c"),
                OsString::from(
                    "IFS= read -r request && test \"$request\" = '{\"request\":1}' && printf '%s\\n' '{\"response\":1}'",
                ),
            ],
            temp.path(),
            1024,
        )
        .with_stdin_limit(1024)
        .with_timeout(Some(CONTENTION_RESILIENT_PROCESS_TEST_TIMEOUT));
        let result = match run_process_interactive(spec, &ProcessCancellation::new(), |session| {
            session.send_line(br#"{"request":1}"#)?;
            let mut response = Vec::new();
            let read = session.receive_line(Duration::from_secs(1), 1024, &mut response)?;
            Ok((read, response))
        }) {
            Ok(result) => result,
            Err(ProcessRunError::ContainmentUnavailable { .. }) => return,
            Err(error) => panic!("verified interactive runner failed: {error:?}"),
        };

        let (read, response) = result.interaction.expect("interactive exchange");
        assert_eq!(read, InteractiveProcessRead::Line);
        assert_eq!(response, br#"{"response":1}"#);
        assert!(result.process.status.is_some_and(|status| status.success()));
        assert!(result.process.process_tree.is_verified_empty());
        assert!(result.process.side_effects.is_verified());
        assert!(result.process.safety_evidence_verified());
    }

    #[test]
    fn failed_host_capacity_measurement_falls_back_to_one_lane() {
        let capacity =
            HostProcessCapacity::from_measurement(Err(io::Error::other("injected failure")));

        assert_eq!(capacity.supervisor_children(), 1);
        #[cfg(target_os = "linux")]
        assert_eq!(
            capacity.systemd_unit_slots(),
            1 + RESERVED_EXPEDITED_SYSTEMD_SLOTS
        );
    }

    #[test]
    fn measured_host_capacity_is_pinned_for_test_supervise_and_containment() {
        let capacity = HostProcessCapacity::measured();

        assert_eq!(capacity.supervisor_children(), 3);
        #[cfg(target_os = "linux")]
        assert_eq!(capacity.systemd_unit_slots(), 4);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn containment_slot_bound_tracks_injected_host_capacity_without_a_fixed_ceiling() {
        for (parallelism, expected_slots) in [(1, 2), (4, 5), (17, 18)] {
            let parallelism = NonZeroUsize::new(parallelism).expect("test parallelism is non-zero");
            let capacity = HostProcessCapacity::from_parallelism(parallelism);
            assert_eq!(capacity.systemd_unit_slots(), expected_slots);
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_containment_slot_limit_constrains_real_permit_acquisition() {
        let runtime_root = tempfile::tempdir().expect("tempdir");
        let cancellation = ProcessCancellation::new();
        let test_slot_limit = HostProcessCapacity::measured().systemd_unit_slots();
        let mut ordinary_permits = Vec::new();
        for _ in RESERVED_EXPEDITED_SYSTEMD_SLOTS..test_slot_limit {
            ordinary_permits.push(
                SystemdUnitPermit::acquire(runtime_root.path(), None, &cancellation)
                    .expect("acquire ordinary test containment permit"),
            );
        }
        assert_eq!(ordinary_permits.len(), 3);

        let expedited_permit = SystemdUnitPermit::acquire(
            runtime_root.path(),
            Some(Instant::now() + Duration::from_millis(500)),
            &cancellation,
        )
        .expect("acquire reserved expedited test containment permit");

        // Real deadline handling is the subject here: all real permit files are held, so the
        // overflow acquire must remain blocked until its caller-supplied deadline. The assertion
        // does not compare elapsed wall time; failure means acquisition escaped the fixed slot set
        // or did not return the required TimedOut result after the deadline became observable.
        let overflow_result = SystemdUnitPermit::acquire(
            runtime_root.path(),
            Some(Instant::now() + Duration::from_secs(2)),
            &cancellation,
        );
        let error = match overflow_result {
            Ok(_) => panic!("test containment limit must prevent acquisition beyond four slots"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(
            !runtime_root
                .path()
                .join(format!("maco-process-runner-slot-{}.lock", test_slot_limit))
                .exists(),
            "real acquisition path must not probe a host-derived slot beyond the test limit"
        );

        drop(expedited_permit);
        drop(ordinary_permits);
    }

    #[test]
    fn process_spec_bounds_reject_oversized_vectors_controls_and_streams() {
        let temp = tempfile::tempdir().expect("tempdir");
        let mut profile = StrictOfflineWorkspaceProfile::read_write(temp.path());
        for _ in 0..=MAX_SANDBOX_PATHS_PER_CLASS {
            profile = profile.with_hidden_root(temp.path());
        }
        let oversized_paths = ProcessSpec::direct(
            "bounded paths",
            PathBuf::from("/bin/true"),
            Vec::<OsString>::new(),
            temp.path(),
            128,
        )
        .with_side_effect_confinement(
            SideEffectConfinementProfile::StrictOfflineWorkspace(profile),
        );
        assert!(validate_process_spec_bounds(&oversized_paths).is_err());

        let controlled_argument = ProcessSpec::direct(
            "bounded args",
            PathBuf::from("/bin/true"),
            vec![OsString::from("line\nfeed")],
            temp.path(),
            128,
        );
        assert!(validate_process_spec_bounds(&controlled_argument).is_err());

        let oversized_capture = ProcessSpec::direct(
            "bounded capture",
            PathBuf::from("/bin/true"),
            Vec::<OsString>::new(),
            temp.path(),
            MAX_REQUIRED_STREAM_BYTES + 1,
        );
        assert!(validate_process_spec_bounds(&oversized_capture).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn process_spec_bounds_measure_non_utf8_arguments_without_lossy_shortening() {
        use std::os::unix::ffi::OsStringExt;

        let temp = tempfile::tempdir().expect("tempdir");
        let argument = OsString::from_vec(vec![0xff; MAX_PROCESS_ARGUMENT_BYTES + 1]);
        let spec = ProcessSpec::direct(
            "non UTF-8 bound",
            PathBuf::from("/bin/true"),
            vec![argument],
            temp.path(),
            128,
        );
        assert!(validate_process_spec_bounds(&spec).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn trusted_network_properties_require_exact_ip_families_without_private_network() {
        let mut properties = BTreeMap::from([
            (
                "RestrictAddressFamilies".to_string(),
                "AF_INET AF_INET6".to_string(),
            ),
            ("PrivateNetwork".to_string(), "no".to_string()),
        ]);
        verify_systemd_network_properties(
            SideEffectConfinementProfileKind::TrustedFixedNetwork,
            &properties,
        )
        .expect("exact trusted network properties");

        properties.insert(
            "RestrictAddressFamilies".to_string(),
            "AF_UNIX AF_INET AF_INET6".to_string(),
        );
        assert!(verify_systemd_network_properties(
            SideEffectConfinementProfileKind::TrustedFixedNetwork,
            &properties,
        )
        .is_err());
        properties.insert(
            "RestrictAddressFamilies".to_string(),
            "AF_INET AF_INET6".to_string(),
        );
        properties.insert("PrivateNetwork".to_string(), "yes".to_string());
        assert!(verify_systemd_network_properties(
            SideEffectConfinementProfileKind::TrustedFixedNetwork,
            &properties,
        )
        .is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn external_codex_writable_workspace_resolves_nested_read_only_controls() {
        let temp = tempfile::tempdir().expect("tempdir");
        let workspace = temp.path().join("worktree");
        let control_root = workspace.join(".maco");
        let cache_root = workspace.join(".maco-cache");
        let control_file = workspace.join(".git");
        let policy_root = workspace.join(".agents");
        let exception_root = policy_root.join("docs");
        let exception_file = workspace.join("AGENTS.md");
        let runtime = temp.path().join("runtime");
        fs::create_dir(&workspace).expect("workspace");
        fs::create_dir(&control_root).expect("control root");
        fs::create_dir(&cache_root).expect("cache root");
        fs::create_dir(&policy_root).expect("policy root");
        fs::create_dir(&exception_root).expect("exception root");
        fs::write(&control_file, "gitdir: ../primary/.git/worktrees/child\n")
            .expect("linked-worktree marker");
        fs::write(&exception_file, "policy\n").expect("exception file");
        fs::create_dir(&runtime).expect("runtime");

        let profile = ExternalCodexProfile::read_write(&workspace)
            .with_visible_read_only_root(&control_root)
            .with_visible_read_only_root(&cache_root)
            .with_visible_read_only_root(&policy_root)
            .with_visible_read_only_file(&control_file)
            .with_visible_read_write_root(&exception_root)
            .with_visible_read_write_file(&exception_file);
        let spec = ProcessSpec::direct(
            "external Codex protected controls",
            PathBuf::from("/bin/true"),
            Vec::<OsString>::new(),
            &workspace,
            128,
        )
        .with_side_effect_confinement(SideEffectConfinementProfile::ExternalCodex(profile));
        let mut sandbox = resolve_systemd_sandbox(&spec)
            .expect("resolve ExternalCodex sandbox")
            .expect("workspace sandbox");
        sandbox
            .add_private_runtime_root(&runtime)
            .expect("private runtime mount");

        assert_eq!(
            sandbox.kind,
            SideEffectConfinementProfileKind::ExternalCodex
        );
        assert_eq!(sandbox.workspace_access, WorkspaceAccess::ReadWrite);
        assert_eq!(sandbox.workspace_root, workspace);
        assert_eq!(
            sandbox.visible_read_only_roots,
            vec![
                policy_root.clone(),
                control_root.clone(),
                cache_root.clone()
            ]
        );
        assert_eq!(sandbox.visible_read_only_files, vec![control_file.clone()]);
        assert_eq!(
            sandbox.visible_read_write_roots,
            vec![exception_root.clone()]
        );
        assert_eq!(
            sandbox.visible_read_write_files,
            vec![exception_file.clone()]
        );
        for (path, access) in [
            (&workspace, SandboxMountAccess::ReadWrite),
            (&control_root, SandboxMountAccess::ReadOnly),
            (&cache_root, SandboxMountAccess::ReadOnly),
            (&policy_root, SandboxMountAccess::ReadOnly),
            (&control_file, SandboxMountAccess::ReadOnly),
            (&exception_root, SandboxMountAccess::ReadWrite),
            (&exception_file, SandboxMountAccess::ReadWrite),
            (&runtime, SandboxMountAccess::PrivateRuntime),
        ] {
            assert!(
                sandbox
                    .mount_checks
                    .iter()
                    .any(|check| check.path == *path && check.access == access && !check.optional),
                "missing {access:?} mount check for {}",
                path.display()
            );
        }

        let mut command = Command::new("systemd-run");
        apply_systemd_sandbox_properties(&mut command, &sandbox);
        command
            .arg(systemd_path_property("BindPaths=", &runtime, false))
            .arg(systemd_path_property("ReadWritePaths=", &runtime, false));
        let arguments = command
            .get_args()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect::<BTreeSet<_>>();
        for expected in [
            format!("--property=BindPaths={}", workspace.display()),
            format!("--property=ReadWritePaths={}", workspace.display()),
            format!("--property=BindReadOnlyPaths={}", control_root.display()),
            format!("--property=ReadOnlyPaths={}", control_root.display()),
            format!("--property=BindReadOnlyPaths={}", cache_root.display()),
            format!("--property=ReadOnlyPaths={}", cache_root.display()),
            format!("--property=BindReadOnlyPaths={}", policy_root.display()),
            format!("--property=ReadOnlyPaths={}", policy_root.display()),
            format!("--property=BindReadOnlyPaths={}", control_file.display()),
            format!("--property=ReadOnlyPaths={}", control_file.display()),
            format!("--property=BindPaths={}", exception_root.display()),
            format!("--property=ReadWritePaths={}", exception_root.display()),
            format!("--property=BindPaths={}", exception_file.display()),
            format!("--property=ReadWritePaths={}", exception_file.display()),
            format!("--property=BindPaths={}", runtime.display()),
            format!("--property=ReadWritePaths={}", runtime.display()),
        ] {
            assert!(
                arguments.contains(&expected),
                "missing appended systemd property {expected}"
            );
        }
        for permanently_read_only in [&control_root, &cache_root, &policy_root] {
            assert!(!arguments.contains(&format!(
                "--property=BindPaths={}",
                permanently_read_only.display()
            )));
            assert!(!arguments.contains(&format!(
                "--property=ReadWritePaths={}",
                permanently_read_only.display()
            )));
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn external_codex_exact_writable_root_rejects_hardlink_alias_outside_exception() {
        let temp = tempfile::tempdir().expect("tempdir");
        let workspace = temp.path().join("worktree");
        let policy_root = workspace.join(".agents");
        let exception_root = policy_root.join("docs");
        let exception_file = exception_root.join("policy.md");
        let outside_alias = workspace.join("AGENTS.md");
        fs::create_dir(&workspace).expect("workspace");
        fs::create_dir(&policy_root).expect("policy root");
        fs::create_dir(&exception_root).expect("exception root");
        fs::write(&exception_file, "policy\n").expect("exception file");
        fs::hard_link(&exception_file, &outside_alias).expect("outside hard-link alias");

        let profile = ExternalCodexProfile::read_write(&workspace)
            .with_visible_read_only_root(&policy_root)
            .with_visible_read_write_root(&exception_root);
        let spec = ProcessSpec::direct(
            "external Codex hard-link scope",
            PathBuf::from("/bin/true"),
            Vec::<OsString>::new(),
            &workspace,
            128,
        )
        .with_side_effect_confinement(SideEffectConfinementProfile::ExternalCodex(profile));
        let error = match resolve_systemd_sandbox(&spec) {
            Err(error) => error,
            Ok(_) => panic!("hard-link alias outside exact writable root must fail closed"),
        };
        assert!(error.to_string().contains("hard-link alias outside"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn external_codex_rejects_writable_aliases_to_every_protected_file_class() {
        for protected_class in ["linked-git", "policy-root", "permanent-root"] {
            let temp = tempfile::tempdir().expect("tempdir");
            let workspace = temp.path().join("worktree");
            let git_marker = workspace.join(".git");
            let policy_root = workspace.join(".agents");
            let policy_file = policy_root.join("policy.md");
            let permanent_root = workspace.join(".maco");
            let permanent_file = permanent_root.join("state");
            let incoming = temp.path().join("incoming");
            fs::create_dir(&workspace).expect("workspace");
            fs::create_dir(&policy_root).expect("policy root");
            fs::create_dir(&permanent_root).expect("permanent root");
            fs::create_dir(&incoming).expect("incoming root");
            fs::write(&git_marker, "gitdir: ../primary/.git/worktrees/child\n")
                .expect("linked-worktree marker");
            fs::write(&policy_file, "policy\n").expect("policy file");
            fs::write(&permanent_file, "state\n").expect("permanent state");

            let (protected, alias) = match protected_class {
                "linked-git" => (&git_marker, workspace.join("git-alias")),
                "policy-root" => (&policy_file, workspace.join("policy-alias")),
                "permanent-root" => (&permanent_file, incoming.join("state-alias")),
                _ => unreachable!("bounded protected class"),
            };
            fs::hard_link(protected, &alias).expect("writable hard-link alias");

            let profile = ExternalCodexProfile::read_write(&workspace)
                .with_visible_read_only_root(&policy_root)
                .with_visible_read_only_root(&permanent_root)
                .with_visible_read_only_file(&git_marker)
                .with_writable_artifact_root(&incoming);
            let spec = ProcessSpec::direct(
                "external Codex protected inode aliases",
                PathBuf::from("/bin/true"),
                Vec::<OsString>::new(),
                &workspace,
                128,
            )
            .with_side_effect_confinement(SideEffectConfinementProfile::ExternalCodex(profile));
            let error = match resolve_systemd_sandbox(&spec) {
                Err(error) => error,
                Ok(_) => panic!("{protected_class} writable alias must fail closed"),
            };
            assert!(
                error
                    .to_string()
                    .contains("protected read-only sandbox file has a writable hard-link alias"),
                "unexpected {protected_class} rejection: {error}"
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn protected_alias_scan_skips_read_only_roots_without_a_writable_surface() {
        let temp = tempfile::tempdir().expect("tempdir");
        let workspace = temp.path().join("read-only-workspace");
        fs::create_dir(&workspace).expect("workspace");
        // This absent root is a fail-if-traversed sentinel for an irrelevant large read-only tree.
        let irrelevant_read_only_root = temp.path().join("irrelevant-large-read-only-root");
        let sandbox = ResolvedSystemdSandbox {
            kind: SideEffectConfinementProfileKind::StrictOfflineWorkspace,
            workspace_root: workspace.clone(),
            current_dir: workspace,
            workspace_access: WorkspaceAccess::ReadOnly,
            visible_read_only_roots: vec![irrelevant_read_only_root],
            visible_read_only_files: Vec::new(),
            visible_read_write_roots: Vec::new(),
            visible_read_write_files: Vec::new(),
            external_codex_writable_file_capabilities: Vec::new(),
            writable_artifact_roots: Vec::new(),
            hidden_roots: Vec::new(),
            isolated_host_view: false,
            resource_limits: ProcessResourceLimits::default(),
            path_identities: Vec::new(),
            mount_checks: Vec::new(),
        };

        sandbox
            .verify_protected_read_only_hardlink_scope()
            .expect("no writable boundary means no protected alias traversal");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn protected_alias_scan_ignores_special_entries_but_preserves_writable_checks() {
        use std::os::unix::net::UnixListener;

        let temp = tempfile::tempdir().expect("tempdir");
        let protected_root = temp.path().join("protected");
        let writable_root = temp.path().join("writable");
        fs::create_dir(&protected_root).expect("protected root");
        fs::create_dir(&writable_root).expect("writable root");
        let socket_path = protected_root.join("socket");
        let _socket = UnixListener::bind(&socket_path).expect("protected socket");
        let protected_file = protected_root.join("policy.md");
        fs::write(&protected_file, "policy\n").expect("protected file");
        let sandbox = ResolvedSystemdSandbox {
            kind: SideEffectConfinementProfileKind::StrictOfflineWorkspace,
            workspace_root: writable_root.clone(),
            current_dir: writable_root.clone(),
            workspace_access: WorkspaceAccess::ReadWrite,
            visible_read_only_roots: vec![protected_root.clone()],
            visible_read_only_files: Vec::new(),
            visible_read_write_roots: Vec::new(),
            visible_read_write_files: Vec::new(),
            external_codex_writable_file_capabilities: Vec::new(),
            writable_artifact_roots: Vec::new(),
            hidden_roots: Vec::new(),
            isolated_host_view: false,
            resource_limits: ProcessResourceLimits::default(),
            path_identities: Vec::new(),
            mount_checks: Vec::new(),
        };

        sandbox
            .verify_protected_read_only_hardlink_scope()
            .expect("read-only socket is irrelevant to regular-file alias identity");

        let mut remaining = MAX_SANDBOX_ENTRY_SCAN;
        let mut writable_links = BTreeMap::new();
        let error = scan_sandbox_tree(&protected_root, true, &mut remaining, &mut writable_links)
            .expect_err("the same socket on a writable surface must remain forbidden");
        assert!(error.to_string().contains("socket, FIFO, or device node"));

        fs::hard_link(&protected_file, writable_root.join("policy-alias.md"))
            .expect("writable hard-link alias");
        let error = sandbox
            .verify_protected_read_only_hardlink_scope()
            .expect_err("protected regular-file alias must remain forbidden");
        assert!(
            error
                .to_string()
                .contains("protected read-only sandbox file has a writable hard-link alias"),
            "unexpected hard-link rejection: {error}"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn external_codex_legitimate_exact_file_exception_is_not_protected_read_only() {
        let temp = tempfile::tempdir().expect("tempdir");
        let workspace = temp.path().join("worktree");
        let policy_root = workspace.join(".agents");
        let exception = policy_root.join("docs/worker.md");
        fs::create_dir_all(exception.parent().expect("exception parent")).expect("policy tree");
        fs::write(&exception, "worker policy\n").expect("writable exception");

        let profile = ExternalCodexProfile::read_write(&workspace)
            .with_visible_read_only_root(&policy_root)
            .with_visible_read_write_file(&exception);
        let spec = ProcessSpec::direct(
            "external Codex exact exception",
            PathBuf::from("/bin/true"),
            Vec::<OsString>::new(),
            &workspace,
            128,
        )
        .with_side_effect_confinement(SideEffectConfinementProfile::ExternalCodex(profile));
        let sandbox = resolve_systemd_sandbox(&spec)
            .expect("legitimate exact exception")
            .expect("resolved sandbox");
        assert_eq!(
            sandbox
                .effective_path_access(&exception)
                .expect("effective exception access"),
            Some(SandboxMountAccess::ReadWrite)
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn external_codex_held_file_capability_rejects_replacement_before_resolution() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().expect("tempdir");
        let workspace = temp.path().join("worktree");
        let policy_root = workspace.join(".agents");
        let exception = policy_root.join("docs/worker.md");
        fs::create_dir_all(exception.parent().expect("exception parent")).expect("policy tree");
        fs::write(&exception, "worker policy\n").expect("writable exception");
        fs::set_permissions(&exception, fs::Permissions::from_mode(0o600)).expect("exception mode");
        let held_file = Arc::new(
            OpenOptions::new()
                .read(true)
                .write(true)
                .open(&exception)
                .expect("held exception"),
        );

        let profile = ExternalCodexProfile::read_write(&workspace)
            .with_visible_read_only_root(&policy_root)
            .with_visible_read_write_file_capability(&exception, held_file)
            .expect("held exact exception capability");
        let spec = ProcessSpec::direct(
            "external Codex held exact exception",
            PathBuf::from("/bin/true"),
            Vec::<OsString>::new(),
            &workspace,
            128,
        )
        .with_side_effect_confinement(SideEffectConfinementProfile::ExternalCodex(profile));
        let sandbox = resolve_systemd_sandbox(&spec)
            .expect("unchanged held exception")
            .expect("resolved sandbox");
        assert_eq!(
            sandbox
                .effective_path_access(&exception)
                .expect("effective exception access"),
            Some(SandboxMountAccess::ReadWrite)
        );

        fs::rename(&exception, workspace.join("original-worker.md"))
            .expect("exchange original exception");
        fs::write(&exception, "replacement\n").expect("replacement exception");
        fs::set_permissions(&exception, fs::Permissions::from_mode(0o600))
            .expect("replacement mode");
        assert!(
            sandbox.verify_path_identities().is_err(),
            "resolved sandbox must retain and revalidate the held capability"
        );
        let error = match resolve_systemd_sandbox(&spec) {
            Err(error) => error,
            Ok(_) => panic!("replacement must not inherit the held writable capability"),
        };
        assert!(
            error
                .to_string()
                .contains("writable file capability identity changed"),
            "unexpected replacement rejection: {error}"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn external_codex_outer_sandbox_enforces_control_and_report_write_boundaries() {
        const CHILD_ENV: &str = "MACO_TEST_EXTERNAL_CODEX_WRITE_BOUNDARY_CHILD";
        const ASSIGNED_PATH_ENV: &str = "MACO_TEST_EXTERNAL_CODEX_ASSIGNED_PATH";
        const REPORT_PATH_ENV: &str = "MACO_TEST_EXTERNAL_CODEX_REPORT_PATH";
        const PROTECTED_PATH_ENVS: &[&str] = &[
            "MACO_TEST_EXTERNAL_CODEX_PROTECTED_0",
            "MACO_TEST_EXTERNAL_CODEX_PROTECTED_1",
            "MACO_TEST_EXTERNAL_CODEX_PROTECTED_2",
            "MACO_TEST_EXTERNAL_CODEX_PROTECTED_3",
            "MACO_TEST_EXTERNAL_CODEX_PROTECTED_4",
            "MACO_TEST_EXTERNAL_CODEX_PROTECTED_5",
            "MACO_TEST_EXTERNAL_CODEX_PROTECTED_6",
            "MACO_TEST_EXTERNAL_CODEX_PROTECTED_7",
        ];

        if env::var_os(CHILD_ENV).is_some() {
            let protected = PROTECTED_PATH_ENVS
                .iter()
                .map(|name| PathBuf::from(env::var_os(name).expect("protected-path fixture")))
                .collect::<Vec<_>>();
            for path in protected {
                assert!(
                    fs::write(&path, b"forbidden mutation\n").is_err(),
                    "outer sandbox allowed a protected write to {}",
                    path.display()
                );
            }
            let assigned =
                PathBuf::from(env::var_os(ASSIGNED_PATH_ENV).expect("assigned-path fixture"));
            let report = PathBuf::from(env::var_os(REPORT_PATH_ENV).expect("report-path fixture"));
            fs::write(assigned, b"assigned writable\n").expect("write ordinary assigned file");
            fs::write(report, b"incoming writable\n").expect("write designated incoming report");
            return;
        }

        if !strict_backend_available_for_tests() {
            return;
        }

        let test_binary = env::current_exe().expect("current test executable");
        let test_output_root = test_binary
            .parent()
            .and_then(Path::parent)
            .expect("test output root");
        let temp = tempfile::tempdir_in(test_output_root).expect("test output tempdir");
        let primary = temp.path().join("primary");
        let primary_git = primary.join(".git");
        let common_state = primary_git.join("maco/state");
        let workspace = temp.path().join("worktree");
        let permanent_control = workspace.join(".maco/control");
        let cache_control = workspace.join(".maco-cache/state");
        let codex_control = workspace.join(".codex/state");
        let policy_control = workspace.join(".agents/policy.md");
        let git_marker = workspace.join(".git");
        let ignore_control = workspace.join(".gitignore");
        let assigned = workspace.join("src/assigned.txt");
        let incoming = temp.path().join("incoming");
        let report = incoming.join("report.txt");
        fs::create_dir_all(primary_git.join("worktrees/child")).expect("primary worktree state");
        fs::create_dir_all(&common_state).expect("common claim state");
        fs::create_dir_all(workspace.join(".maco")).expect("MACO control root");
        fs::create_dir_all(workspace.join(".maco-cache")).expect("MACO cache root");
        fs::create_dir_all(workspace.join(".codex")).expect("Codex control root");
        fs::create_dir_all(workspace.join(".agents")).expect("policy control root");
        fs::create_dir_all(workspace.join("src")).expect("assigned source root");
        fs::create_dir(&incoming).expect("incoming report root");
        fs::write(primary_git.join("config"), "primary-config\n").expect("primary config");
        fs::write(common_state.join("claims.json"), "common-state\n").expect("common state");
        fs::write(
            &git_marker,
            format!(
                "gitdir: {}\n",
                primary_git.join("worktrees/child").display()
            ),
        )
        .expect("linked-worktree marker");
        fs::write(&permanent_control, "MACO control\n").expect("MACO control");
        fs::write(&cache_control, "cache control\n").expect("cache control");
        fs::write(&codex_control, "Codex control\n").expect("Codex control");
        fs::write(&policy_control, "policy control\n").expect("policy control");
        fs::write(&ignore_control, "ignore control\n").expect("ignore control");
        fs::write(&assigned, "assigned original\n").expect("assigned file");

        let protected = [
            primary_git.join("config"),
            common_state.join("claims.json"),
            git_marker.clone(),
            permanent_control.clone(),
            cache_control.clone(),
            codex_control.clone(),
            policy_control.clone(),
            ignore_control.clone(),
        ];
        let mut environment = BTreeMap::new();
        environment.insert(CHILD_ENV.to_string(), "1".to_string());
        for (name, path) in PROTECTED_PATH_ENVS.iter().zip(&protected) {
            environment.insert((*name).to_string(), path.display().to_string());
        }
        environment.insert(
            ASSIGNED_PATH_ENV.to_string(),
            assigned.display().to_string(),
        );
        environment.insert(REPORT_PATH_ENV.to_string(), report.display().to_string());
        let profile = ExternalCodexProfile::read_write(&workspace)
            .with_visible_read_only_root(workspace.join(".maco"))
            .with_visible_read_only_root(workspace.join(".maco-cache"))
            .with_visible_read_only_root(workspace.join(".codex"))
            .with_visible_read_only_root(workspace.join(".agents"))
            .with_visible_read_only_file(&git_marker)
            .with_visible_read_only_file(&ignore_control)
            .with_writable_artifact_root(&incoming)
            .with_hidden_root(&primary);
        let output = run_process(
            ProcessSpec::direct(
                "ExternalCodex live write-boundary probe",
                env::current_exe().expect("current test executable"),
                [
                    OsString::from("--exact"),
                    OsString::from(
                        "process_runner::tests::external_codex_outer_sandbox_enforces_control_and_report_write_boundaries",
                    ),
                ],
                &workspace,
                4 * 1024,
            )
            .with_environment(EnvironmentMode::InheritAndSet(environment))
            .with_stdin(StdinMode::Null)
            .with_timeout(Some(CONTENTION_RESILIENT_PROCESS_TEST_TIMEOUT))
            .with_side_effect_confinement(SideEffectConfinementProfile::ExternalCodex(profile)),
        )
        .expect("run ExternalCodex live write-boundary probe");

        assert!(output.status.is_some_and(|status| status.success()));
        assert!(output.safety_evidence_verified());
        assert_eq!(
            output.side_effects,
            SideEffectConfinementEvidence::Verified(
                SideEffectConfinementProfileKind::ExternalCodex
            )
        );
        assert_eq!(
            fs::read_to_string(primary_git.join("config")).expect("primary config evidence"),
            "primary-config\n"
        );
        assert_eq!(
            fs::read_to_string(common_state.join("claims.json")).expect("common state evidence"),
            "common-state\n"
        );
        for (path, expected) in [
            (&permanent_control, "MACO control\n"),
            (&cache_control, "cache control\n"),
            (&codex_control, "Codex control\n"),
            (&policy_control, "policy control\n"),
            (&ignore_control, "ignore control\n"),
        ] {
            assert_eq!(
                fs::read_to_string(path).expect("protected control evidence"),
                expected
            );
        }
        assert!(fs::read_to_string(&git_marker)
            .expect("linked-worktree marker evidence")
            .starts_with("gitdir: "));
        assert_eq!(
            fs::read_to_string(&assigned).expect("assigned write evidence"),
            "assigned writable\n"
        );
        assert_eq!(
            fs::read_to_string(&report).expect("incoming report evidence"),
            "incoming writable\n"
        );
        assert_current_runner_has_no_systemd_residue();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn mountinfo_parser_decodes_paths_and_rejects_malformed_or_oversized_input() {
        let parsed = parse_sandbox_mountinfo(
            b"10 1 8:1 / / rw,relatime - ext4 /dev/root rw\n\
              11 10 8:1 /repo/policy /repo/work\\040tree/policy rw - ext4 /dev/root rw\n",
        )
        .expect("synthetic mountinfo");
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[1].root, PathBuf::from("/repo/policy"));
        assert_eq!(
            parsed[1].mount_point,
            PathBuf::from("/repo/work tree/policy")
        );
        assert!(parse_sandbox_mountinfo(b"10 1 8:1 / /\n").is_err());
        assert!(
            parse_sandbox_mountinfo(b"10 1 8:1 /bad\\escape /point rw - ext4 /dev/root rw\n")
                .is_err()
        );
        let oversized = vec![b'x'; MAX_SANDBOX_MOUNTINFO_LINE_BYTES + 1];
        assert!(parse_sandbox_mountinfo(&oversized).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn same_filesystem_mount_identity_rejects_rw_aliases_and_nested_conflicts() {
        let workspace = PathBuf::from("/repo/worktree");
        let policy_root = workspace.join(".agents");
        let protected_file = workspace.join(".git");
        let exception = policy_root.join("docs/worker.md");
        let incoming = PathBuf::from("/run/maco/incoming");
        let sandbox = ResolvedSystemdSandbox {
            kind: SideEffectConfinementProfileKind::ExternalCodex,
            workspace_root: workspace.clone(),
            current_dir: workspace.clone(),
            workspace_access: WorkspaceAccess::ReadWrite,
            visible_read_only_roots: vec![policy_root.clone()],
            visible_read_only_files: vec![protected_file.clone()],
            visible_read_write_roots: Vec::new(),
            visible_read_write_files: vec![exception.clone()],
            external_codex_writable_file_capabilities: Vec::new(),
            writable_artifact_roots: vec![incoming.clone()],
            hidden_roots: Vec::new(),
            isolated_host_view: false,
            resource_limits: ProcessResourceLimits::default(),
            path_identities: Vec::new(),
            mount_checks: Vec::new(),
        };
        let base = b"10 1 8:1 / / rw,relatime - ext4 /dev/root rw\n";

        let mut alias = base.to_vec();
        alias.extend_from_slice(
            b"11 10 8:1 /repo/worktree/.git /repo/worktree/alias rw - ext4 /dev/root rw\n",
        );
        let alias_mountinfo = parse_sandbox_mountinfo(&alias).expect("alias mountinfo");
        let error = verify_sandbox_mount_alias_conflicts(&sandbox, &alias_mountinfo)
            .expect_err("same-filesystem writable alias");
        assert!(error.to_string().contains("mount identity conflict"));

        let mut artifact_alias = base.to_vec();
        artifact_alias.extend_from_slice(
            b"12 10 8:1 /repo/worktree/.agents /run/maco/incoming rw - ext4 /dev/root rw\n",
        );
        let artifact_mountinfo =
            parse_sandbox_mountinfo(&artifact_alias).expect("artifact alias mountinfo");
        assert!(
            verify_sandbox_mount_alias_conflicts(&sandbox, &artifact_mountinfo).is_err(),
            "incoming artifact alias to protected policy root must fail closed"
        );

        let mut nested_exception = base.to_vec();
        nested_exception.extend_from_slice(
            b"13 10 8:1 /repo/worktree/.git /repo/worktree/.agents/docs/worker.md rw - ext4 /dev/root rw\n",
        );
        let nested_mountinfo =
            parse_sandbox_mountinfo(&nested_exception).expect("nested mountinfo");
        assert!(
            verify_sandbox_mount_alias_conflicts(&sandbox, &nested_mountinfo).is_err(),
            "writable exception mounted over protected content must fail closed"
        );

        let ordinary_mountinfo = parse_sandbox_mountinfo(base).expect("ordinary mountinfo");
        verify_sandbox_mount_alias_conflicts(&sandbox, &ordinary_mountinfo)
            .expect("ordinary direct RO/RW nesting");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn ordinary_external_codex_exact_path_properties_reject_drift() {
        let sandbox = ResolvedSystemdSandbox {
            kind: SideEffectConfinementProfileKind::ExternalCodex,
            workspace_root: PathBuf::from("/worktree"),
            current_dir: PathBuf::from("/worktree"),
            workspace_access: WorkspaceAccess::ReadWrite,
            visible_read_only_roots: vec![PathBuf::from("/worktree/.maco")],
            visible_read_only_files: vec![PathBuf::from("/worktree/.git")],
            visible_read_write_roots: vec![PathBuf::from("/worktree/.agents/docs")],
            visible_read_write_files: vec![PathBuf::from("/worktree/AGENTS.md")],
            external_codex_writable_file_capabilities: Vec::new(),
            writable_artifact_roots: Vec::new(),
            hidden_roots: vec![PathBuf::from("/primary")],
            isolated_host_view: false,
            resource_limits: ProcessResourceLimits::default(),
            path_identities: Vec::new(),
            mount_checks: Vec::new(),
        };
        let runtime = Path::new("/run/user/1000/maco-process");
        let mut inaccessible = BTreeSet::from([PathBuf::from("/primary")]);
        inaccessible.extend(known_sensitive_socket_paths());
        let exact = BTreeMap::from([
            (
                "InaccessiblePaths".to_string(),
                joined_property_paths(&inaccessible),
            ),
            (
                "ReadOnlyPaths".to_string(),
                "/worktree/.git /worktree/.maco".to_string(),
            ),
            (
                "BindReadOnlyPaths".to_string(),
                "/worktree/.maco /worktree/.git".to_string(),
            ),
            (
                "ReadWritePaths".to_string(),
                "/worktree /worktree/.agents/docs /worktree/AGENTS.md /run/user/1000/maco-process"
                    .to_string(),
            ),
            (
                "BindPaths".to_string(),
                "/run/user/1000/maco-process /worktree /worktree/.agents/docs /worktree/AGENTS.md"
                    .to_string(),
            ),
        ]);
        verify_exact_systemd_path_properties(&sandbox, &exact, runtime)
            .expect("exact ordinary ExternalCodex properties");

        for name in [
            "ReadOnlyPaths",
            "BindReadOnlyPaths",
            "BindPaths",
            "ReadWritePaths",
            "InaccessiblePaths",
        ] {
            let mut extra = exact.clone();
            extra
                .get_mut(name)
                .expect("fixture property")
                .push_str(" /unexpected");
            let error = verify_exact_systemd_path_properties(&sandbox, &extra, runtime)
                .expect_err("unexpected effective path must fail closed");
            assert!(
                error.to_string().contains(name),
                "unexpected {name} extra-entry failure: {error}"
            );

            let mut omitted = exact.clone();
            let remaining = omitted[name]
                .split_whitespace()
                .skip(1)
                .collect::<Vec<_>>()
                .join(" ");
            omitted.insert(name.to_string(), remaining);
            let error = verify_exact_systemd_path_properties(&sandbox, &omitted, runtime)
                .expect_err("omitted effective path must fail closed");
            assert!(
                error.to_string().contains(name),
                "unexpected {name} omission failure: {error}"
            );
        }

        let mut remapped = exact;
        remapped.insert(
            "BindPaths".to_string(),
            format!(
                "/worktree:/unexpected {runtime_path}",
                runtime_path = runtime.display()
            ),
        );
        let error = verify_exact_systemd_path_properties(&sandbox, &remapped, runtime)
            .expect_err("remapped writable bind must fail closed");
        assert!(error.to_string().contains("BindPaths"));
    }

    #[cfg(target_os = "linux")]
    fn joined_property_paths(paths: &BTreeSet<PathBuf>) -> String {
        paths
            .iter()
            .map(|path| path.to_string_lossy())
            .collect::<Vec<_>>()
            .join(" ")
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn isolated_host_view_resolves_disjoint_required_mounts_and_root_tmpfs() {
        let temp = tempfile::tempdir().expect("tempdir");
        let view = temp.path().join("view");
        let materialized = temp.path().join("materialized");
        let source = temp.path().join("source");
        let runtime = temp.path().join("runtime");
        for path in [&view, &materialized, &source, &runtime] {
            fs::create_dir(path).expect("fixture directory");
        }
        let profile = StrictOfflineWorkspaceProfile::read_only(&view)
            .with_visible_read_only_root("/nix/store")
            .with_visible_read_only_root(&materialized)
            .with_hidden_root(&source)
            .with_isolated_host_view();
        let spec = ProcessSpec::direct(
            "isolated reviewer fixture",
            PathBuf::from("/nix/store/reviewer-fixture"),
            Vec::<OsString>::new(),
            &view,
            128,
        )
        .with_side_effect_confinement(
            SideEffectConfinementProfile::StrictOfflineWorkspace(profile),
        );
        let mut sandbox = resolve_systemd_sandbox(&spec)
            .expect("resolve isolated sandbox")
            .expect("sandbox config");
        let env_helper = trusted_system_executable(
            "env",
            &["/usr/bin/env", "/bin/env", "/run/current-system/sw/bin/env"],
        )
        .expect("trusted env helper");
        sandbox
            .add_isolated_runtime_file(&env_helper)
            .expect("bind exact helper alias");
        let canonical_env_helper = fs::canonicalize(&env_helper).expect("canonical env helper");
        sandbox
            .add_isolated_runtime_file(&canonical_env_helper)
            .expect("bind helper nested under visible Nix store");
        sandbox
            .add_private_runtime_root(&runtime)
            .expect("bind private runtime");
        assert!(sandbox.isolated_host_view);
        assert!(sandbox.mount_checks.iter().any(|check| {
            check.path == Path::new("/")
                && check.access == SandboxMountAccess::IsolatedRoot
                && !check.optional
        }));
        assert!(sandbox.visible_read_only_files.contains(&env_helper));
        assert!(sandbox
            .visible_read_only_files
            .contains(&canonical_env_helper));
        assert!(sandbox.mount_checks.iter().any(|check| {
            check.path == env_helper && check.access == SandboxMountAccess::ReadOnly
        }));
        assert!(sandbox.mount_checks.iter().any(|check| {
            check.path == runtime && check.access == SandboxMountAccess::PrivateRuntime
        }));
        assert!(sandbox.mount_checks.iter().any(|check| {
            check.path == source
                && check.access == SandboxMountAccess::Inaccessible
                && !check.optional
        }));
        assert!(sandbox.mount_checks.iter().any(|check| {
            check.path == materialized
                && check.access == SandboxMountAccess::ReadOnly
                && !check.optional
        }));

        let mut command = Command::new("systemd-run");
        apply_systemd_sandbox_properties(&mut command, &sandbox);
        assert!(command
            .get_args()
            .any(|arg| arg == OsStr::new("--property=TemporaryFileSystem=/:ro")));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn isolated_root_property_requires_exact_single_read_only_root() {
        for value in ["/:ro", "  /:ro\n"] {
            assert!(
                is_exact_isolated_host_view_property(value),
                "expected exact isolated root property: {value:?}"
            );
        }

        for value in [
            "",
            "/tmp:ro",
            "/:ro /etc:ro",
            "/:ro /etc:rw",
            "/:ro /:ro",
            "/:rw",
            "/:ro,rw",
            "/:rw,ro",
            "/:ro,nodev",
            "/:",
            "/",
        ] {
            assert!(
                !is_exact_isolated_host_view_property(value),
                "unexpectedly accepted isolated root property: {value:?}"
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn isolated_root_property_and_required_inaccessible_report_fail_closed() {
        let sandbox = ResolvedSystemdSandbox {
            kind: SideEffectConfinementProfileKind::StrictOfflineWorkspace,
            workspace_root: PathBuf::from("/view"),
            current_dir: PathBuf::from("/view"),
            workspace_access: WorkspaceAccess::ReadOnly,
            visible_read_only_roots: vec![PathBuf::from("/nix/store")],
            visible_read_only_files: Vec::new(),
            visible_read_write_roots: Vec::new(),
            visible_read_write_files: Vec::new(),
            external_codex_writable_file_capabilities: Vec::new(),
            writable_artifact_roots: Vec::new(),
            hidden_roots: vec![PathBuf::from("/source")],
            isolated_host_view: true,
            resource_limits: ProcessResourceLimits::default(),
            path_identities: Vec::new(),
            mount_checks: Vec::new(),
        };
        let mut properties =
            BTreeMap::from([("TemporaryFileSystem".to_string(), "/:ro".to_string())]);
        verify_isolated_host_view_property(&sandbox, &properties)
            .expect("exact isolated root property");
        properties.insert("TemporaryFileSystem".to_string(), "/tmp:ro".to_string());
        assert!(verify_isolated_host_view_property(&sandbox, &properties).is_err());

        use std::os::unix::fs::PermissionsExt;
        let temp = tempfile::tempdir().expect("tempdir");
        let report = temp.path().join("report");
        fs::write(
            &report,
            "security 0000000000000000 0000000000000000 0000000000000000 0000000000000000 1 2\nisolated-root tmpfs tmpfs ro,nodev\ninaccessible\ninaccessible-missing\n",
        )
        .expect("write report");
        fs::set_permissions(&report, fs::Permissions::from_mode(0o600)).expect("report mode");
        let checks = vec![
            SandboxMountCheck {
                path: PathBuf::from("/"),
                device: 0,
                inode: 0,
                access: SandboxMountAccess::IsolatedRoot,
                optional: false,
            },
            SandboxMountCheck {
                path: PathBuf::from("/source"),
                device: 0,
                inode: 0,
                access: SandboxMountAccess::Inaccessible,
                optional: false,
            },
            SandboxMountCheck {
                path: PathBuf::from("/optional-socket"),
                device: 0,
                inode: 0,
                access: SandboxMountAccess::Inaccessible,
                optional: true,
            },
        ];
        verify_sandbox_mount_report(&report, &checks).expect("isolated mount evidence");
        fs::write(
            &report,
            "security 0000000000000000 0000000000000000 0000000000000000 0000000000000000 1 2\nisolated-root tmpfs tmpfs ro,nodev\ninaccessible-missing\ninaccessible-missing\n",
        )
        .expect("replace report");
        assert!(verify_sandbox_mount_report(&report, &checks).is_err());
        assert!(SYSTEMD_GUARDIAN_SCRIPT.contains("required inaccessible path was not mounted"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn isolated_exact_bindings_are_order_independent_and_alias_mounts_bind_target_identity() {
        use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};

        let expected = BTreeSet::from([
            (PathBuf::from("/nix/store"), PathBuf::from("/nix/store")),
            (PathBuf::from("/review-view"), PathBuf::from("/review-view")),
            (PathBuf::from("/usr/bin/env"), PathBuf::from("/usr/bin/env")),
            (
                PathBuf::from("/nix/store/helper/bin/maco"),
                PathBuf::from("/nix/store/helper/bin/maco"),
            ),
        ]);
        verify_exact_property_bindings(
            "BindReadOnlyPaths",
            "/usr/bin/env /nix/store/helper/bin/maco /review-view /nix/store",
            &expected,
        )
        .expect("canonical binding set ignores property order");
        assert!(verify_exact_property_bindings(
            "BindReadOnlyPaths",
            "/usr/bin/env /nix/store/helper/bin/maco /review-view /nix/store /unexpected",
            &expected,
        )
        .is_err());

        let temp = tempfile::tempdir().expect("tempdir");
        let target = temp.path().join("target");
        let alias = temp.path().join("alias");
        fs::write(&target, "helper").expect("target");
        fs::set_permissions(&target, fs::Permissions::from_mode(0o500)).expect("target mode");
        symlink(&target, &alias).expect("alias");
        let target_metadata = fs::metadata(&alias).expect("follow alias metadata");
        let report = temp.path().join("report");
        fs::write(
            &report,
            format!(
                "security 0000000000000000 0000000000000000 0000000000000000 0000000000000000 1 2\nmounted {} {} ro\n",
                target_metadata.dev(),
                target_metadata.ino()
            ),
        )
        .expect("report");
        fs::set_permissions(&report, fs::Permissions::from_mode(0o600)).expect("report mode");
        verify_sandbox_mount_report(
            &report,
            &[SandboxMountCheck {
                path: alias,
                device: target_metadata.dev(),
                inode: target_metadata.ino(),
                access: SandboxMountAccess::ReadOnly,
                optional: false,
            }],
        )
        .expect("alias path may become a mounted regular target with the bound identity");
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires the trusted user-systemd/cgroup runtime; compile-only in claimed validation waves"]
    fn trusted_network_profile_masks_repo_state_and_seals_private_objects() {
        let temp = tempfile::tempdir().expect("tempdir");
        let primary = temp.path().join("primary");
        let state = primary.join(".git/maco/state");
        let runtime = temp.path().join("runtime");
        let sealed_objects = runtime.join("objects");
        fs::create_dir_all(&state).expect("state");
        fs::create_dir_all(&sealed_objects).expect("sealed objects");
        fs::write(sealed_objects.join("visible"), "object").expect("visible object");
        fs::write(state.join("auth-key"), "secret").expect("state secret");
        let script = format!(
            "test -r '{}' && test ! -r '{}'",
            sealed_objects.join("visible").display(),
            state.join("auth-key").display()
        );
        let profile = TrustedFixedNetworkProfile::read_write(&runtime)
            .with_visible_read_only_root(&sealed_objects)
            .with_hidden_root(&primary);
        let output = run_process(
            ProcessSpec::direct(
                "trusted network mount denial",
                PathBuf::from("/bin/sh"),
                [OsString::from("-c"), OsString::from(script)],
                &runtime,
                1024,
            )
            .with_side_effect_confinement(
                SideEffectConfinementProfile::TrustedFixedNetwork(profile),
            ),
        )
        .expect("run trusted network mount test");
        assert!(output.status.is_some_and(|status| status.success()));
        assert_eq!(
            output.side_effects,
            SideEffectConfinementEvidence::Verified(
                SideEffectConfinementProfileKind::TrustedFixedNetwork
            )
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires the trusted user-systemd/cgroup runtime; compile-only in claimed validation waves"]
    fn trusted_network_profile_bounds_timeout_output_and_cleanup() {
        let temp = tempfile::tempdir().expect("tempdir");
        let output = run_process(
            ProcessSpec::direct(
                "trusted network bounded output",
                PathBuf::from("/bin/sh"),
                [OsString::from("-c"), OsString::from("printf 123456789")],
                temp.path(),
                8,
            )
            .with_side_effect_confinement(
                SideEffectConfinementProfile::TrustedFixedNetwork(
                    TrustedFixedNetworkProfile::read_write(temp.path()),
                ),
            ),
        )
        .expect("run bounded output test");
        assert!(output.stdout.is_truncated());
        assert!(output.process_tree.is_verified_empty());

        let timeout = run_process(
            ProcessSpec::direct(
                "trusted network bounded timeout",
                PathBuf::from("/bin/sh"),
                [OsString::from("-c"), OsString::from("sleep 30")],
                temp.path(),
                128,
            )
            .with_side_effect_confinement(SideEffectConfinementProfile::TrustedFixedNetwork(
                TrustedFixedNetworkProfile::read_write(temp.path()),
            ))
            .with_timeout(Some(Duration::from_millis(50))),
        )
        .expect("run timeout test");
        assert!(timeout.timed_out);
        assert!(timeout.process_tree.is_verified_empty());
    }

    #[test]
    fn required_confinement_rejects_existing_tee_before_target_start() {
        let temp = tempfile::tempdir().expect("tempdir");
        let tee = temp.path().join("existing.log");
        let marker = temp.path().join("target-ran");
        fs::write(&tee, "preserve").expect("seed existing tee");
        let error = run_process(
            ProcessSpec::shell(
                "strict existing tee",
                Shell::for_current_platform(),
                format!("touch '{}'", marker.display()),
                temp.path(),
                128,
            )
            .with_stdout(StreamCapture::bounded(128).tee_to(&tee)),
        )
        .expect_err("required mode must reject an existing tee");

        assert!(matches!(error, ProcessRunError::OpenTee { .. }));
        assert_eq!(fs::read_to_string(tee).expect("preserved tee"), "preserve");
        assert!(!marker.exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn sandbox_scan_rejects_fifo_and_external_hardlink_alias() {
        use std::os::unix::ffi::OsStrExt;

        let temp = tempfile::tempdir().expect("tempdir");
        let workspace = temp.path().join("workspace");
        fs::create_dir(&workspace).expect("workspace");
        let fifo = workspace.join("ipc");
        let fifo_name = std::ffi::CString::new(fifo.as_os_str().as_bytes()).expect("fifo path");
        // SAFETY: fifo_name is a valid NUL-terminated path and mode has no invalid bits.
        assert_eq!(unsafe { libc::mkfifo(fifo_name.as_ptr(), 0o600) }, 0);
        let sandbox = ResolvedSystemdSandbox {
            kind: SideEffectConfinementProfileKind::StrictOfflineWorkspace,
            workspace_root: workspace.clone(),
            current_dir: workspace.clone(),
            workspace_access: WorkspaceAccess::ReadWrite,
            visible_read_only_roots: Vec::new(),
            visible_read_only_files: Vec::new(),
            visible_read_write_roots: Vec::new(),
            visible_read_write_files: Vec::new(),
            external_codex_writable_file_capabilities: Vec::new(),
            writable_artifact_roots: Vec::new(),
            hidden_roots: Vec::new(),
            isolated_host_view: false,
            resource_limits: ProcessResourceLimits::default(),
            path_identities: Vec::new(),
            mount_checks: Vec::new(),
        };
        assert!(sandbox.verify_no_special_entries().is_err());

        fs::remove_file(&fifo).expect("remove fifo");
        let outside = temp.path().join("outside");
        fs::write(&outside, "outside").expect("outside file");
        fs::hard_link(&outside, workspace.join("alias")).expect("external hardlink alias");
        assert!(sandbox.verify_no_special_entries().is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn unit_mount_report_binds_identity_access_and_inaccessibility() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let temp = tempfile::tempdir().expect("tempdir");
        let visible = temp.path().join("visible");
        fs::write(&visible, "visible").expect("visible");
        let metadata = fs::metadata(&visible).expect("visible metadata");
        let report = temp.path().join("report");
        fs::write(
            &report,
            format!(
                "security 0000000000000000 0000000000000000 0000000000000000 0000000000000000 1 2\nmounted {} {} ro\ninaccessible\n",
                metadata.dev(),
                metadata.ino()
            ),
        )
        .expect("report");
        fs::set_permissions(&report, fs::Permissions::from_mode(0o600)).expect("report mode");
        let checks = vec![
            SandboxMountCheck {
                path: visible,
                device: metadata.dev(),
                inode: metadata.ino(),
                access: SandboxMountAccess::ReadOnly,
                optional: false,
            },
            SandboxMountCheck {
                path: PathBuf::from("/masked"),
                device: 0,
                inode: 0,
                access: SandboxMountAccess::Inaccessible,
                optional: false,
            },
        ];

        verify_sandbox_mount_report(&report, &checks).expect("valid unit mount report");
        fs::write(
            &report,
            format!(
                "security 0000000000000000 0000000000000000 0000000000000000 0000000000000000 1 2\nmounted {} {} rw\ninaccessible\n",
                metadata.dev(),
                metadata.ino()
            ),
        )
        .expect("replace report");
        assert!(verify_sandbox_mount_report(&report, &checks).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn system_call_error_number_accepts_name_and_numeric_eperm_only() {
        verify_system_call_error_number("EPERM").expect("named EPERM");
        verify_system_call_error_number(&libc::EPERM.to_string()).expect("numeric EPERM");
        assert!(verify_system_call_error_number("0").is_err());
        assert!(verify_system_call_error_number("EACCES").is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn system_call_filter_accepts_retained_and_complete_expanded_deny_forms() {
        let retained = retained_system_call_filter_fixture();
        verify_effective_system_call_filter(
            SideEffectConfinementProfileKind::StrictOfflineWorkspace,
            &retained,
        )
        .expect("retained deny groups");

        let expanded = expanded_system_call_filter_fixture();
        verify_effective_system_call_filter(
            SideEffectConfinementProfileKind::StrictOfflineWorkspace,
            &expanded.join(" "),
        )
        .expect("complete expanded deny groups");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn system_call_filter_rejects_each_incomplete_group_and_allow_list() {
        let expanded = expanded_system_call_filter_fixture();
        for (group, representatives) in required_denied_group_representatives() {
            let Some(missing) = representatives.first() else {
                continue;
            };
            let incomplete = expanded
                .iter()
                .filter(|token| token.trim_start_matches('~') != *missing)
                .cloned()
                .collect::<Vec<_>>()
                .join(" ");
            let error = verify_effective_system_call_filter(
                SideEffectConfinementProfileKind::StrictOfflineWorkspace,
                &incomplete,
            )
            .expect_err("incomplete group expansion must fail closed");
            assert!(
                error.to_string().contains(group),
                "unexpected {group} failure: {error}"
            );
        }
        assert!(verify_effective_system_call_filter(
            SideEffectConfinementProfileKind::StrictOfflineWorkspace,
            "read write exit exit_group",
        )
        .is_err());
    }

    #[cfg(target_os = "linux")]
    fn retained_system_call_filter_fixture() -> String {
        let mut tokens = required_denied_group_representatives()
            .into_iter()
            .map(|(group, _)| group.to_string())
            .collect::<Vec<_>>();
        tokens[0].insert(0, '~');
        tokens.extend(
            REQUIRED_DENIED_SYSCALLS
                .iter()
                .map(|value| value.to_string()),
        );
        tokens.extend(["socket", "socketpair", "socketcall"].map(str::to_string));
        tokens.join(" ")
    }

    #[cfg(target_os = "linux")]
    fn expanded_system_call_filter_fixture() -> Vec<String> {
        let mut tokens = vec!["~expanded-deny-list".to_string()];
        for (group, representatives) in required_denied_group_representatives() {
            if representatives.is_empty() {
                tokens.push(group.to_string());
            } else {
                tokens.extend(representatives.iter().map(|value| value.to_string()));
            }
        }
        tokens.extend(
            REQUIRED_DENIED_SYSCALLS
                .iter()
                .map(|value| value.to_string()),
        );
        tokens.extend(["socket", "socketpair", "socketcall"].map(str::to_string));
        tokens
    }

    #[cfg(unix)]
    #[test]
    fn drains_large_stdout_and_stderr_without_false_timeout() {
        let temp = tempfile::tempdir().expect("tempdir");
        let output_log = temp.path().join("stdout.log");
        let spec = ProcessSpec::shell(
            "large-output command",
            Shell::UnixSh,
            "i=0; while [ \"$i\" -lt 256 ]; do printf '%4096s' O; i=$((i + 1)); done; i=0; while [ \"$i\" -lt 256 ]; do printf '%4096s' E >&2; i=$((i + 1)); done",
            temp.path(),
            16 * 1024,
        )
        .with_containment(ContainmentPolicy::TrustedBestEffort)
        // The timeout is a liveness fuse for a functional pipe-drain test, not a throughput
        // benchmark. Thirty seconds is intentionally far above the 2 MiB fixture's ordinary
        // runtime; expiry means the drain stopped making progress, not ordinary scheduler jitter.
        .with_timeout(Some(Duration::from_secs(30)))
        .with_stdout(StreamCapture::bounded(16 * 1024).tee_to(&output_log));

        let output = run_process(spec).expect("run large-output command");

        assert!(output.status.is_some_and(|status| status.success()));
        assert!(!output.timed_out);
        assert!(output.stdout.is_truncated());
        assert!(output.stderr.is_truncated());
        assert_eq!(output.stdout.as_bytes().len(), 16 * 1024);
        assert_eq!(output.stderr.as_bytes().len(), 16 * 1024);
        assert!(
            std::fs::metadata(&output_log)
                .expect("stdout log metadata")
                .len()
                >= 256 * 4096
        );
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&output_log)
                .expect("stdout log permissions")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }

    #[cfg(unix)]
    #[test]
    fn continuous_output_does_not_starve_timeout_polling() {
        let temp = tempfile::tempdir().expect("tempdir");
        let spec = ProcessSpec::shell(
            "continuous-output command",
            Shell::UnixSh,
            "trap '' TERM; while :; do printf '%4096s' O; printf '%4096s' E >&2; done",
            temp.path(),
            1024,
        )
        .with_containment(ContainmentPolicy::TrustedBestEffort)
        .with_timeout(Some(Duration::from_secs(1)));
        let started = Instant::now();

        let output = run_process(spec).expect("run continuous-output command");
        let elapsed = started.elapsed();

        assert!(output.timed_out);
        assert!(output.stdout.is_truncated());
        assert!(output.stderr.is_truncated());
        assert!(elapsed >= Duration::from_millis(900));
        // Real timeout polling is the subject here. The upper bound is deliberately ten times the
        // requested timeout so a failure means continuous backlog prevented timeout observation,
        // not that a loaded host scheduled the runner a few milliseconds late.
        assert!(
            elapsed < Duration::from_secs(10),
            "continuous output delayed the one-second timeout for {elapsed:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn cancellation_terminates_owned_process_group_and_delayed_descendant() {
        let temp = tempfile::tempdir().expect("tempdir");
        let ready = temp.path().join("ready");
        let delayed = temp.path().join("delayed");
        let release_delayed = temp.path().join("release-delayed");
        let descendant_pid = temp.path().join("descendant.pid");
        let command = format!(
            "(while [ ! -e '{}' ]; do sleep 0.01; done; touch '{}') & descendant=$!; echo \"$descendant\" > '{}'; touch '{}'; trap '' TERM; while :; do sleep 1; done",
            release_delayed.display(),
            delayed.display(),
            descendant_pid.display(),
            ready.display(),
        );
        let cancellation = ProcessCancellation::new();
        let worker_cancellation = cancellation.clone();
        let workdir = temp.path().to_path_buf();
        let worker = thread::spawn(move || {
            run_process_cancellable(
                ProcessSpec::shell(
                    "cancellable process group",
                    Shell::UnixSh,
                    command,
                    workdir,
                    1024,
                )
                .with_containment(ContainmentPolicy::TrustedBestEffort)
                .with_timeout(Some(Duration::from_secs(5))),
                &worker_cancellation,
            )
        });

        while !ready.exists() && !worker.is_finished() {
            thread::sleep(POLL_INTERVAL);
        }
        assert!(
            ready.exists(),
            "process runner completed before the child reached its ready gate"
        );
        cancellation.cancel();
        let output = worker
            .join()
            .unwrap_or_else(|_| panic!("cancellable runner thread panicked"))
            .expect("cancel contained process group");

        assert!(!output.timed_out);
        assert!(output
            .process_error
            .as_deref()
            .is_some_and(|error| error.contains("cancelled")));
        let pid = fs::read_to_string(descendant_pid).expect("cancelled descendant pid");
        assert_process_not_executable(&pid, "cancelled descendant");
        fs::write(release_delayed, b"release").expect("release any surviving descendant");
        assert!(!delayed.exists());
    }

    #[cfg(unix)]
    #[test]
    fn completion_first_observed_after_deadline_is_a_timeout() {
        let started = Instant::now();
        let deadline = started
            .checked_add(Duration::from_millis(50))
            .expect("representable deadline");
        let before_deadline = started
            .checked_add(Duration::from_millis(40))
            .expect("representable early observation");
        let after_deadline = started
            .checked_add(Duration::from_millis(60))
            .expect("representable late observation");

        assert_eq!(
            process_loop_decision(true, false, Some(deadline), before_deadline),
            ProcessLoopDecision::Complete
        );
        assert_eq!(
            process_loop_decision(true, false, Some(deadline), after_deadline),
            ProcessLoopDecision::Timeout
        );
    }

    #[cfg(unix)]
    #[test]
    fn normal_exit_terminates_descendants_holding_pipes() {
        const WHOLE_CALL_BOUND: Duration = Duration::from_secs(3);

        let temp = tempfile::tempdir().expect("tempdir");
        let descendant_pid = temp.path().join("descendant.pid");
        let command = format!(
            "(trap '' TERM; echo descendant-started; echo descendant-error >&2; while :; do sleep 1; done) & descendant=$!; echo \"$descendant\" > '{}'; echo parent-exiting",
            descendant_pid.display()
        );
        let spec = ProcessSpec::shell(
            "hung command",
            Shell::UnixSh,
            command,
            temp.path(),
            8 * 1024,
        )
        .with_containment(ContainmentPolicy::TrustedBestEffort)
        .with_timeout(Some(Duration::from_secs(2)));

        let (completion_tx, completion_rx) = mpsc::channel();
        // Start before `thread::spawn`: worker creation and scheduling are part of the whole call.
        let whole_call_started = Instant::now();
        let _worker = thread::spawn(move || {
            let _ = completion_tx.send(run_process(spec));
        });
        // Prompt whole-call completion is the contract here. The event is emitted only after
        // `run_process` has completed process-tree cleanup, pipe finalization, and its internal
        // joins. Three seconds preserves the original bound; expiry means lifecycle completion
        // itself stopped being prompt. There is no unbounded JoinHandle wait on this path.
        let completion = completion_rx
            .recv_timeout(WHOLE_CALL_BOUND.saturating_sub(whole_call_started.elapsed()))
            .expect("descendant pipe lifecycle completed within its three-second contract");
        let whole_call_elapsed = whole_call_started.elapsed();
        assert!(
            whole_call_elapsed < WHOLE_CALL_BOUND,
            "descendant pipe lifecycle exceeded its whole-call three-second contract: {whole_call_elapsed:?}"
        );
        let output = completion.expect("run descendant-spawning command");

        assert!(!output.timed_out);
        assert!(output.status.is_some_and(|status| status.success()));
        assert_eq!(output.process_error, None);
        assert!(output
            .stdout
            .summarize_chars(8 * 1024)
            .text
            .contains("descendant-started"));
        assert!(output
            .stderr
            .summarize_chars(8 * 1024)
            .text
            .contains("descendant-error"));
        let pid = std::fs::read_to_string(descendant_pid).expect("descendant pid");
        assert_process_gone(&pid, "output-pipe descendant");
    }

    #[cfg(unix)]
    #[test]
    fn normal_exit_kills_delayed_background_mutation_before_return() {
        let temp = tempfile::tempdir().expect("tempdir");
        let marker = temp.path().join("delayed-mutation");
        let release = temp.path().join("release-delayed-mutation");
        let descendant_pid = temp.path().join("delayed-descendant.pid");
        let command = format!(
            "(while [ ! -e '{}' ]; do sleep 0.01; done; touch '{}') >/dev/null 2>&1 & echo $! > '{}'",
            release.display(),
            marker.display(),
            descendant_pid.display(),
        );
        let spec = ProcessSpec::shell(
            "delayed descendant command",
            Shell::UnixSh,
            command,
            temp.path(),
            1024,
        )
        .with_containment(ContainmentPolicy::TrustedBestEffort)
        .with_timeout(Some(Duration::from_secs(2)));

        let output = run_process(spec).expect("run delayed descendant command");

        assert!(output.status.is_some_and(|status| status.success()));
        assert!(!output.timed_out);
        let pid = fs::read_to_string(descendant_pid).expect("delayed descendant pid");
        assert_process_not_executable(&pid, "delayed-mutation descendant");
        fs::write(release, b"release").expect("release any surviving delayed mutation");
        assert!(!marker.exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires the trusted user-systemd/cgroup runtime; compile-only in claimed validation waves"]
    fn required_containment_verifies_normal_nonzero_and_timeout_units_empty() {
        let temp = tempfile::tempdir().expect("tempdir");
        let normal = match run_process(
            ProcessSpec::shell(
                "normal contained command",
                Shell::UnixSh,
                "exit 0",
                temp.path(),
                128,
            )
            .with_timeout(Some(Duration::from_secs(2))),
        ) {
            Ok(output) => output,
            Err(error) if is_verified_backend_unavailable(&error) => {
                assert_current_runner_has_no_systemd_residue();
                return;
            }
            Err(error) => panic!("run normal contained command: {error:?}"),
        };
        assert!(normal.status.is_some_and(|status| status.success()));
        assert!(normal.process_tree.is_verified_empty());
        assert_eq!(normal.process_error, None);

        let nonzero = run_process(
            ProcessSpec::shell(
                "nonzero contained command",
                Shell::UnixSh,
                "exit 7",
                temp.path(),
                128,
            )
            .with_timeout(Some(Duration::from_secs(2))),
        )
        .expect("run nonzero contained command");
        assert_eq!(nonzero.status.and_then(|status| status.code()), Some(7));
        assert!(nonzero.process_tree.is_verified_empty());
        assert_eq!(nonzero.process_error, None);

        let timed_out = run_process(
            ProcessSpec::shell(
                "timed out contained command",
                Shell::UnixSh,
                "sleep 30",
                temp.path(),
                128,
            )
            .with_timeout(Some(Duration::from_secs(2))),
        )
        .expect("run timed out contained command");
        assert!(timed_out.timed_out);
        assert!(
            timed_out.process_tree.is_verified_empty(),
            "timed out strict run did not prove cleanup: {timed_out:?}"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn unsupported_path_masking_refuses_before_target_and_leaves_no_residue() {
        let temp = tempfile::tempdir().expect("tempdir");
        let marker = temp.path().join("target-ran");
        let result = run_process(
            ProcessSpec::shell(
                "path-mask enforcement probe",
                Shell::UnixSh,
                format!("touch '{}'", marker.display()),
                temp.path(),
                256,
            )
            .with_timeout(Some(CONTENTION_RESILIENT_PROCESS_TEST_TIMEOUT)),
        );

        match result {
            Ok(output) => {
                assert!(output.safety_evidence_verified());
                assert!(marker.exists());
            }
            Err(error) if is_verified_backend_unavailable(&error) => {
                assert!(!marker.exists());
                assert_current_runner_has_no_systemd_residue();
            }
            Err(error) => panic!("unexpected strict backend probe failure: {error:?}"),
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires the trusted user-systemd/cgroup runtime; compile-only in claimed validation waves"]
    fn inaccessible_placeholder_blocks_nix_daemon_socket_access() {
        use std::os::unix::net::UnixStream;

        const CHILD_ENV: &str = "MACO_TEST_INACCESSIBLE_SOCKET_CHILD";
        const SOCKET_PATH: &str = "/nix/var/nix/daemon-socket/socket";
        if env::var_os(CHILD_ENV).is_some() {
            let marker = PathBuf::from(
                env::var_os("MACO_TEST_INACCESSIBLE_SOCKET_MARKER").expect("marker path"),
            );
            let open_error = File::open(SOCKET_PATH).expect_err("masked socket must not open");
            let connect_error =
                UnixStream::connect(SOCKET_PATH).expect_err("masked socket must not connect");
            fs::write(
                marker,
                format!(
                    "open={:?};connect={:?}\n",
                    open_error.raw_os_error(),
                    connect_error.raw_os_error()
                ),
            )
            .expect("write inaccessible-socket evidence");
            return;
        }
        match UnixStream::connect(SOCKET_PATH) {
            Ok(control) => drop(control),
            Err(error) => {
                eprintln!(
                    "skipping inaccessible-placeholder causal probe because the host Nix daemon socket is unavailable: {error}"
                );
                return;
            }
        }
        if !strict_backend_available_for_tests() {
            return;
        }

        let temp = tempfile::tempdir().expect("tempdir");
        let marker = temp.path().join("socket-access-blocked");
        let mut environment = BTreeMap::new();
        environment.insert(CHILD_ENV.to_string(), "1".to_string());
        environment.insert(
            "MACO_TEST_INACCESSIBLE_SOCKET_MARKER".to_string(),
            marker.display().to_string(),
        );
        let output = run_process(
            ProcessSpec::direct(
                "inaccessible socket placeholder probe",
                env::current_exe().expect("current test executable"),
                [
                    OsString::from("--exact"),
                    OsString::from(
                        "process_runner::tests::inaccessible_placeholder_blocks_nix_daemon_socket_access",
                    ),
                ],
                temp.path(),
                4 * 1024,
            )
            .with_environment(EnvironmentMode::InheritAndSet(environment))
            .with_timeout(Some(Duration::from_secs(5))),
        )
        .expect("run inaccessible socket placeholder probe");

        assert!(output.status.is_some_and(|status| status.success()));
        assert!(output.safety_evidence_verified());
        let evidence = fs::read_to_string(&marker).expect("socket denial evidence");
        assert!(evidence.contains("open=Some("));
        assert!(evidence.contains("connect=Some("));
        assert_current_runner_has_no_systemd_residue();
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires the trusted user-systemd/cgroup runtime; compile-only in claimed validation waves"]
    fn one_cancellation_cleans_two_simultaneous_strict_process_trees() {
        let temp = tempfile::tempdir().expect("tempdir");
        let cancellation = ProcessCancellation::new();
        let mut workers = Vec::new();
        let mut ready_paths = Vec::new();
        for index in 0..2usize {
            let ready = temp.path().join(format!("ready-{index}"));
            ready_paths.push(ready.clone());
            let workdir = temp.path().to_path_buf();
            let worker_cancellation = cancellation.clone();
            workers.push(thread::spawn(move || {
                run_process_cancellable(
                    ProcessSpec::shell(
                        format!("simultaneous cancellable process {index}"),
                        Shell::UnixSh,
                        format!(
                            "touch '{}'; trap '' TERM; while :; do sleep 1; done",
                            ready.display()
                        ),
                        workdir,
                        1024,
                    )
                    .with_timeout(Some(Duration::from_secs(10))),
                    &worker_cancellation,
                )
            }));
        }

        while !ready_paths.iter().all(|path| path.exists())
            && workers.iter().any(|worker| !worker.is_finished())
        {
            thread::sleep(POLL_INTERVAL);
        }
        cancellation.cancel();
        let results = workers
            .into_iter()
            .map(|worker| {
                worker
                    .join()
                    .unwrap_or_else(|_| panic!("strict cancellation worker panicked"))
            })
            .collect::<Vec<_>>();

        if results
            .iter()
            .any(|result| result.as_ref().is_err_and(is_verified_backend_unavailable))
        {
            assert_current_runner_has_no_systemd_residue();
            return;
        }
        assert!(ready_paths.iter().all(|path| path.exists()));
        for output in results {
            let output = output.expect("cancel strict contained process");
            assert!(output.process_tree.is_verified_empty());
            assert!(output.side_effects.is_verified());
            assert!(output
                .process_error
                .as_deref()
                .is_some_and(|error| error.contains("cancelled")));
        }
        assert_current_runner_has_no_systemd_residue();
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires the trusted user-systemd/cgroup runtime; compile-only in claimed validation waves"]
    fn exact_git_read_roots_do_not_expose_private_tmp_sibling() {
        if !strict_backend_available_for_tests() {
            return;
        }

        let temp = tempfile::tempdir().expect("tempdir");
        let workspace = temp.path().join("bounded-runtime");
        let worktree = temp.path().join("verified-worktree");
        let objects = temp.path().join("verified-common-objects");
        let sibling = temp.path().join("unrelated-sibling");
        for directory in [&workspace, &worktree, &objects, &sibling] {
            fs::create_dir(directory).expect("create sandbox fixture directory");
        }
        fs::write(worktree.join("tracked"), "tracked\n").expect("worktree marker");
        fs::write(objects.join("object"), "object\n").expect("objects marker");
        fs::write(sibling.join("sentinel"), "untouched\n").expect("sibling sentinel");
        let completed = workspace.join("completed");
        let command = format!(
            "test -r '{}' && test -r '{}' && test ! -e '{}' && touch '{}'",
            worktree.join("tracked").display(),
            objects.join("object").display(),
            sibling.join("sentinel").display(),
            completed.display()
        );
        let profile = StrictOfflineWorkspaceProfile::read_write(&workspace)
            .with_visible_read_only_root(&worktree)
            .with_visible_read_only_root(&objects);
        let output = run_process(
            ProcessSpec::shell(
                "exact bounded Git read roots",
                Shell::UnixSh,
                command,
                &workspace,
                1024,
            )
            .with_side_effect_confinement(SideEffectConfinementProfile::StrictOfflineWorkspace(
                profile,
            ))
            .with_timeout(Some(Duration::from_secs(3))),
        )
        .expect("run exact bounded Git read-root probe");

        assert!(output.status.is_some_and(|status| status.success()));
        assert!(output.safety_evidence_verified());
        assert!(completed.is_file());
        assert_eq!(
            fs::read_to_string(sibling.join("sentinel")).expect("preserved sibling sentinel"),
            "untouched\n"
        );
        assert_current_runner_has_no_systemd_residue();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn strict_target_cannot_launch_sibling_user_unit() {
        if !strict_backend_available_for_tests() {
            return;
        }
        let temp = tempfile::tempdir().expect("tempdir");
        let marker = temp.path().join("sibling-unit-ran");
        let release = temp.path().join("release-sibling-unit");
        let unit = format!(
            "maco-escape-test-{}-{}",
            std::process::id(),
            NEXT_SYSTEMD_UNIT_ID.fetch_add(1, Ordering::Relaxed)
        );
        let systemd_run = trusted_system_executable(
            "systemd-run",
            &[
                "/run/current-system/sw/bin/systemd-run",
                "/usr/bin/systemd-run",
                "/bin/systemd-run",
            ],
        )
        .expect("trusted systemd-run");
        let shell = trusted_system_executable(
            "sh",
            &["/run/current-system/sw/bin/sh", "/usr/bin/sh", "/bin/sh"],
        )
        .expect("trusted shell");
        let command = format!(
            r#"'{}' --user --quiet --collect --unit '{}' -- '{}' -c "while [ ! -e '{}' ]; do sleep 0.01; done; touch '{}'"#,
            systemd_run.display(),
            unit,
            shell.display(),
            release.display(),
            marker.display()
        );
        let output = run_process(
            ProcessSpec::shell(
                "sibling systemd escape",
                Shell::UnixSh,
                command,
                temp.path(),
                4096,
            )
            .with_timeout(Some(Duration::from_secs(3))),
        )
        .expect("run blocked sibling-unit attempt");

        assert!(!output.status.is_some_and(|status| status.success()));
        assert!(output.process_tree.is_verified_empty());
        assert!(output.side_effects.is_verified());

        let systemctl = trusted_system_executable(
            "systemctl",
            &[
                "/run/current-system/sw/bin/systemctl",
                "/usr/bin/systemctl",
                "/bin/systemctl",
            ],
        )
        .expect("trusted systemctl");
        let status = Command::new(&systemctl)
            .args(["--user", "--quiet", "is-active", &unit])
            .status()
            .expect("query sibling unit");
        if status.success() {
            let _ = Command::new(&systemctl)
                .args(["--user", "stop", &unit])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
        assert!(!status.success(), "sibling transient unit survived");
        assert!(!marker.exists(), "sibling transient unit mutated the host");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn strict_target_cannot_create_hardlinks_or_fifos_after_start_gate() {
        if !strict_backend_available_for_tests() {
            return;
        }
        let temp = tempfile::tempdir().expect("tempdir");
        fs::write(temp.path().join("source"), "source").expect("source");
        let output = run_process(
            ProcessSpec::shell(
                "post-gate IPC creation",
                Shell::UnixSh,
                "ln source alias >/dev/null 2>&1 || :; mkfifo fifo >/dev/null 2>&1 || :",
                temp.path(),
                128,
            )
            .with_timeout(Some(Duration::from_secs(2))),
        )
        .expect("run post-gate creation attempts");

        assert!(output.status.is_some_and(|status| status.success()));
        assert!(output.safety_evidence_verified());
        assert!(!temp.path().join("alias").exists());
        assert!(!temp.path().join("fifo").exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires the trusted user-systemd/cgroup runtime; compile-only in claimed validation waves"]
    fn strict_target_cannot_create_network_or_sysv_ipc_endpoints() {
        let temp = tempfile::tempdir().expect("tempdir");
        let marker = temp.path().join("all-blocked");
        let python = trusted_system_executable(
            "python3",
            &[
                "/run/current-system/sw/bin/python3",
                "/usr/bin/python3",
                "/bin/python3",
            ],
        )
        .expect("trusted python3");
        let probe = r#"
import ctypes
import errno
import pathlib
import socket
import sys

try:
    socket.socket(socket.AF_INET, socket.SOCK_STREAM)
except OSError as error:
    if error.errno != errno.EPERM:
        raise
else:
    raise SystemExit("IPv4 socket creation unexpectedly succeeded")

libc = ctypes.CDLL(None, use_errno=True)
probes = [
    ("shmget", (0, 4096, 0o600), libc.shmctl),
    ("msgget", (0, 0o600), libc.msgctl),
    ("semget", (0, 1, 0o600), libc.semctl),
]
for name, arguments, cleanup in probes:
    ctypes.set_errno(0)
    identifier = getattr(libc, name)(*arguments)
    error = ctypes.get_errno()
    if identifier != -1:
        cleanup(identifier, 0, 0)
        raise SystemExit(f"{name} unexpectedly succeeded")
    if error != errno.EPERM:
        raise OSError(error, f"{name} returned an unexpected error")

pathlib.Path(sys.argv[1]).write_text("blocked\n", encoding="utf-8")
"#;
        let result = run_process(
            ProcessSpec::direct(
                "network and SysV IPC denial probe",
                python,
                vec![
                    OsString::from("-c"),
                    OsString::from(probe),
                    marker.as_os_str().to_os_string(),
                ],
                temp.path(),
                4096,
            )
            .with_timeout(Some(Duration::from_secs(3))),
        );

        match result {
            Ok(output) => {
                assert!(
                    output.status.is_some_and(|status| status.success()),
                    "denial probe failed unexpectedly: {output:?}"
                );
                assert!(output.safety_evidence_verified());
                assert!(marker.exists());
            }
            Err(error) if is_verified_backend_unavailable(&error) => {
                assert!(!marker.exists());
                assert_current_runner_has_no_systemd_residue();
            }
            Err(error) => panic!("unexpected denial probe failure: {error:?}"),
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn required_containment_kills_setsid_delayed_mutation_with_closed_stdio() {
        if !strict_backend_available_for_tests() {
            return;
        }
        let temp = tempfile::tempdir().expect("tempdir");
        let marker = temp.path().join("escaped-delayed-mutation");
        let pid_file = temp.path().join("escaped-delayed.pid");
        let release = temp.path().join("release-escaped-delayed");
        let command = format!(
            "setsid sh -c 'echo $$ > \"{}\"; while [ ! -e \"{}\" ]; do sleep 0.01; done; touch \"{}\"' >/dev/null 2>&1 & i=0; while [ ! -s \"{}\" ] && [ \"$i\" -lt 100 ]; do sleep 0.01; i=$((i + 1)); done",
            pid_file.display(),
            release.display(),
            marker.display(),
            pid_file.display()
        );
        let output = run_process(
            ProcessSpec::shell(
                "setsid delayed mutation",
                Shell::UnixSh,
                command,
                temp.path(),
                128,
            )
            .with_timeout(Some(Duration::from_secs(2))),
        )
        .expect("run setsid delayed mutation");

        assert!(output.status.is_some_and(|status| status.success()));
        assert!(output.process_tree.is_verified_empty());
        let escaped_pid = fs::read_to_string(&pid_file)
            .expect("escaped delayed process pid")
            .trim()
            .parse::<libc::pid_t>()
            .expect("numeric escaped delayed process pid");
        // SAFETY: signal 0 probes existence without delivering a signal.
        assert_eq!(unsafe { libc::kill(escaped_pid, 0) }, -1);
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ESRCH),
            "escaped delayed descendant survived return"
        );
        fs::write(release, b"release").expect("release any surviving delayed descendant");
        assert!(!marker.exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn required_containment_unavailable_refuses_before_spawn() {
        const CHILD_ENV: &str = "MACO_TEST_CONTAINMENT_UNAVAILABLE_CHILD";
        if env::var_os(CHILD_ENV).is_some() {
            let marker =
                PathBuf::from(env::var_os("MACO_TEST_CONTAINMENT_MARKER").expect("marker"));
            let spec = ProcessSpec::shell(
                "unavailable strict containment",
                Shell::UnixSh,
                format!("touch '{}'", marker.display()),
                marker.parent().expect("marker parent"),
                128,
            );
            let error = run_process(spec).expect_err("strict containment must be unavailable");
            assert!(matches!(
                error,
                ProcessRunError::ContainmentUnavailable { .. }
            ));
            assert!(!marker.exists());
            return;
        }

        let temp = tempfile::tempdir().expect("tempdir");
        let marker = temp.path().join("must-not-run");
        let status = Command::new(std::env::current_exe().expect("current test executable"))
            .args([
                "--exact",
                "process_runner::tests::required_containment_unavailable_refuses_before_spawn",
            ])
            .env(CHILD_ENV, "1")
            .env("MACO_TEST_DISABLE_STRICT_CONTAINMENT", "1")
            .env("MACO_TEST_CONTAINMENT_MARKER", &marker)
            .current_dir(temp.path())
            .status()
            .expect("run unavailable-containment child test");
        assert!(status.success());
        assert!(!marker.exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn exhausted_total_budget_returns_typed_setup_timeout_without_starting_target() {
        let temp = tempfile::tempdir().expect("tempdir");
        let marker = temp.path().join("must-not-run");
        let error = run_process(
            ProcessSpec::shell(
                "expired setup budget",
                Shell::UnixSh,
                format!("touch '{}'", marker.display()),
                temp.path(),
                128,
            )
            .with_timeout(Some(Duration::ZERO)),
        )
        .expect_err("zero total budget must expire before target release");

        assert!(matches!(error, ProcessRunError::SetupTimeout { .. }));
        assert!(!marker.exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn strict_runtime_files_ignore_ambient_tmpdir() {
        const CHILD_ENV: &str = "MACO_TEST_AMBIENT_TMP_CHILD";
        if env::var_os(CHILD_ENV).is_some() {
            let ambient =
                PathBuf::from(env::var_os("MACO_TEST_AMBIENT_TMP_PATH").expect("ambient"));
            let output = run_process(ProcessSpec::shell(
                "ambient temp containment",
                Shell::UnixSh,
                ":",
                &ambient,
                128,
            ))
            .expect("run with ambient TMPDIR");
            assert!(output.process_tree.is_verified_empty());
            assert_eq!(fs::read_dir(&ambient).expect("ambient entries").count(), 0);
            return;
        }

        if !strict_backend_available_for_tests() {
            return;
        }

        let temp = tempfile::tempdir().expect("tempdir");
        let ambient = temp.path().join("redirected-temp");
        fs::create_dir(&ambient).expect("create redirected temp");
        let status = Command::new(std::env::current_exe().expect("current test executable"))
            .args([
                "--exact",
                "process_runner::tests::strict_runtime_files_ignore_ambient_tmpdir",
            ])
            .env(CHILD_ENV, "1")
            .env("MACO_TEST_AMBIENT_TMP_PATH", &ambient)
            .env("TMPDIR", &ambient)
            .current_dir(temp.path())
            .status()
            .expect("run ambient-temp child test");
        assert!(status.success());
        assert_eq!(fs::read_dir(&ambient).expect("ambient entries").count(), 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires the trusted user-systemd/cgroup runtime; compile-only in claimed validation waves"]
    fn parent_death_around_launcher_spawn_leaves_no_runtime_or_secret() {
        const CHILD_ENV: &str = "MACO_TEST_LAUNCHER_DEATH_CHILD";
        if env::var_os(CHILD_ENV).is_some() {
            let root = PathBuf::from(env::var_os("MACO_TEST_LAUNCHER_DEATH_ROOT").expect("root"));
            let marker = root.join("target-ran");
            let mut environment = BTreeMap::new();
            environment.insert(
                "MACO_PRIVATE_LAUNCH_SECRET".to_string(),
                "never-persist-before-service".to_string(),
            );
            let _ = run_process(
                ProcessSpec::shell(
                    "launcher death child",
                    Shell::UnixSh,
                    format!("touch '{}'", marker.display()),
                    &root,
                    128,
                )
                .with_environment(EnvironmentMode::ClearAndSet(environment))
                .with_timeout(Some(Duration::from_secs(10))),
            );
            panic!("launcher death child unexpectedly returned");
        }

        if !strict_backend_available_for_tests() {
            return;
        }

        for case in ["before-spawn", "after-spawn"] {
            let temp = tempfile::tempdir().expect("tempdir");
            let spawned = temp.path().join("launcher-spawned");
            let mut command =
                Command::new(std::env::current_exe().expect("current test executable"));
            command
                .args([
                    "--exact",
                    "process_runner::tests::parent_death_around_launcher_spawn_leaves_no_runtime_or_secret",
                ])
                .env(CHILD_ENV, "1")
                .env("MACO_TEST_LAUNCHER_DEATH_ROOT", temp.path());
            if case == "before-spawn" {
                command.env("MACO_TEST_ABORT_BEFORE_CHILD_SPAWN", "1");
            } else {
                command
                    .env("MACO_TEST_AFTER_CHILD_SPAWN_MARKER", &spawned)
                    .env("MACO_TEST_HOLD_AFTER_CHILD_SPAWN", "1");
            }
            let mut child = command.spawn().expect("spawn launcher death child");
            let runner_pid = child.id();
            if case == "after-spawn" {
                let deadline = Instant::now() + Duration::from_secs(10);
                while !spawned.exists() {
                    assert!(child.try_wait().unwrap().is_none());
                    assert!(Instant::now() < deadline, "launcher spawn marker missing");
                    thread::sleep(POLL_INTERVAL);
                }
                let pid = libc::pid_t::try_from(runner_pid).expect("runner pid_t");
                // SAFETY: pid identifies the live isolated test child.
                assert_eq!(unsafe { libc::kill(pid, libc::SIGKILL) }, 0);
            }
            let status = child.wait().expect("reap launcher death child");
            assert!(!status.success());
            assert!(!temp.path().join("target-ran").exists());
            let deadline = Instant::now() + Duration::from_secs(10);
            loop {
                let residue = systemd_runner_residue(runner_pid);
                if residue.is_empty() {
                    break;
                }
                assert!(
                    Instant::now() < deadline,
                    "{case} runner left residue: {}",
                    residue.join("; ")
                );
                thread::sleep(Duration::from_millis(50));
            }
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires the trusted user-systemd/cgroup runtime; compile-only in claimed validation waves"]
    fn parent_sigkill_after_environment_publish_removes_secret_and_unit() {
        const CHILD_ENV: &str = "MACO_TEST_PUBLISHED_ENV_DEATH_CHILD";
        if env::var_os(CHILD_ENV).is_some() {
            let root = PathBuf::from(env::var_os("MACO_TEST_PUBLISHED_ENV_ROOT").expect("root"));
            let marker = root.join("target-ran");
            let mut environment = BTreeMap::new();
            environment.insert(
                "MACO_PUBLISHED_PRIVATE_SECRET".to_string(),
                "remove-me-with-runtime-directory".to_string(),
            );
            let _ = run_process(
                ProcessSpec::shell(
                    "published environment death child",
                    Shell::UnixSh,
                    format!("touch '{}'", marker.display()),
                    &root,
                    128,
                )
                .with_environment(EnvironmentMode::ClearAndSet(environment))
                .with_timeout(Some(Duration::from_secs(10))),
            );
            panic!("published environment death child unexpectedly returned");
        }

        if !strict_backend_available_for_tests() {
            return;
        }

        let temp = tempfile::tempdir().expect("tempdir");
        let published = temp.path().join("environment-published");
        let mut child = Command::new(std::env::current_exe().expect("current test executable"))
            .args([
                "--exact",
                "process_runner::tests::parent_sigkill_after_environment_publish_removes_secret_and_unit",
            ])
            .env(CHILD_ENV, "1")
            .env("MACO_TEST_PUBLISHED_ENV_ROOT", temp.path())
            .env("MACO_TEST_ENVIRONMENT_PUBLISHED_MARKER", &published)
            .env("MACO_TEST_HOLD_AFTER_ENVIRONMENT_PUBLISH", "1")
            .spawn()
            .expect("spawn published environment death child");
        let runner_pid = child.id();
        let deadline = Instant::now() + Duration::from_secs(10);
        while !published.exists() {
            assert!(child.try_wait().unwrap().is_none());
            assert!(
                Instant::now() < deadline,
                "environment publish marker missing"
            );
            thread::sleep(POLL_INTERVAL);
        }
        let runtime_root = trusted_linux_runtime_root().expect("runtime root");
        let prefix = format!("maco-process-{runner_pid}-");
        let environment_path = fs::read_dir(&runtime_root)
            .unwrap()
            .filter_map(Result::ok)
            .find(|entry| entry.file_name().to_string_lossy().starts_with(&prefix))
            .expect("managed runtime directory")
            .path()
            .join("environment");
        assert!(fs::read_to_string(&environment_path)
            .expect("published environment")
            .contains("remove-me-with-runtime-directory"));
        {
            use std::os::unix::fs::PermissionsExt;

            assert_eq!(
                fs::metadata(&environment_path)
                    .expect("published environment metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        let pid = libc::pid_t::try_from(runner_pid).expect("runner pid_t");
        // SAFETY: pid identifies the live isolated test child.
        assert_eq!(unsafe { libc::kill(pid, libc::SIGKILL) }, 0);
        assert!(!child
            .wait()
            .expect("reap published environment child")
            .success());
        assert!(!temp.path().join("target-ran").exists());

        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let residue = systemd_runner_residue(runner_pid);
            if residue.is_empty() {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "published environment runner left residue: {}",
                residue.join("; ")
            );
            thread::sleep(Duration::from_millis(50));
        }
        assert!(!environment_path.exists());
        let next = run_process(
            ProcessSpec::shell(
                "post-publish-death slot probe",
                Shell::UnixSh,
                ":",
                temp.path(),
                128,
            )
            .with_timeout(Some(Duration::from_secs(2))),
        )
        .expect("slot reusable after published environment owner death");
        assert!(next.process_tree.is_verified_empty());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn target_environment_cannot_overwrite_guardian_gate_state() {
        if !strict_backend_available_for_tests() {
            return;
        }
        let temp = tempfile::tempdir().expect("tempdir");
        let preloaded_start = temp.path().join("preloaded-start");
        let bogus_ready = temp.path().join("bogus-ready");
        let malicious_sleep = temp.path().join("malicious-sleep");
        fs::write(&preloaded_start, "start\n").expect("preload fake start gate");
        let mut environment = BTreeMap::new();
        environment.insert(
            "start_fifo".to_string(),
            preloaded_start.display().to_string(),
        );
        environment.insert("ready".to_string(), bogus_ready.display().to_string());
        environment.insert(
            "sleep_program".to_string(),
            malicious_sleep.display().to_string(),
        );
        environment.insert("owner_pid".to_string(), "1".to_string());
        let output = run_process(
            ProcessSpec::shell(
                "guardian environment collision",
                Shell::UnixSh,
                "printf '%s|%s|%s' \"$start_fifo\" \"$ready\" \"$sleep_program\"",
                temp.path(),
                1024,
            )
            .with_environment(EnvironmentMode::ClearAndSet(environment))
            .with_timeout(Some(CONTENTION_RESILIENT_PROCESS_TEST_TIMEOUT)),
        )
        .expect("run guardian collision environment");

        assert!(output.status.is_some_and(|status| status.success()));
        assert!(output.process_tree.is_verified_empty());
        assert!(output
            .stdout
            .summarize_chars(1024)
            .text
            .contains("preloaded-start"));
        assert!(!bogus_ready.exists());
        assert!(!malicious_sleep.exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires the trusted user-systemd/cgroup runtime; compile-only in claimed validation waves"]
    fn guardian_reaps_unit_when_runner_aborts_before_start_release() {
        const CHILD_ENV: &str = "MACO_TEST_PRE_GATE_ABORT_CHILD";
        if env::var_os(CHILD_ENV).is_some() {
            let marker = PathBuf::from(
                env::var_os("MACO_TEST_PRE_GATE_MARKER").expect("pre-gate marker path"),
            );
            let _ = run_process(
                ProcessSpec::shell(
                    "pre-gate abort guardian child",
                    Shell::UnixSh,
                    format!("touch '{}'", marker.display()),
                    marker.parent().expect("pre-gate marker parent"),
                    128,
                )
                .with_timeout(Some(Duration::from_secs(10))),
            );
            panic!("pre-gate guardian child unexpectedly returned");
        }

        if !strict_backend_available_for_tests() {
            return;
        }

        let temp = tempfile::tempdir().expect("tempdir");
        let marker = temp.path().join("must-not-run");
        let mut child = Command::new(std::env::current_exe().expect("current test executable"))
            .args([
                "--exact",
                "process_runner::tests::guardian_reaps_unit_when_runner_aborts_before_start_release",
            ])
            .env(CHILD_ENV, "1")
            .env("MACO_TEST_ABORT_BEFORE_START_RELEASE", "1")
            .env("MACO_TEST_PRE_GATE_MARKER", &marker)
            .current_dir(temp.path())
            .spawn()
            .expect("spawn isolated pre-gate guardian child test");
        let runner_pid = child.id();
        let exit_deadline = Instant::now() + Duration::from_secs(10);
        let status = loop {
            if let Some(status) = child.try_wait().expect("query pre-gate guardian child") {
                break status;
            }
            if Instant::now() >= exit_deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("pre-gate failpoint did not abort its isolated runner");
            }
            thread::sleep(POLL_INTERVAL);
        };
        assert!(!status.success());
        assert!(!marker.exists(), "target crossed the unreleased start gate");

        let residue_deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let residue = systemd_runner_residue(runner_pid);
            if residue.is_empty() {
                break;
            }
            assert!(
                Instant::now() < residue_deadline,
                "pre-gate runner abort left containment residue: {}",
                residue.join("; ")
            );
            thread::sleep(Duration::from_millis(50));
        }

        let next = run_process(
            ProcessSpec::shell(
                "post-pre-gate-abort slot probe",
                Shell::UnixSh,
                ":",
                temp.path(),
                128,
            )
            .with_timeout(Some(Duration::from_secs(2))),
        )
        .expect("kernel released the pre-gate aborted runner's slot lock");
        assert!(next.status.is_some_and(|status| status.success()));
        assert!(next.process_tree.is_verified_empty());
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires the trusted user-systemd/cgroup runtime; compile-only in claimed validation waves"]
    fn guardian_reaps_unit_and_blocks_mutation_after_runner_sigabrt() {
        const CHILD_ENV: &str = "MACO_TEST_ABORTED_GUARDIAN_CHILD";
        if env::var_os(CHILD_ENV).is_some() {
            let started = PathBuf::from(
                env::var_os("MACO_TEST_GUARDIAN_STARTED").expect("started marker path"),
            );
            let mutation = PathBuf::from(
                env::var_os("MACO_TEST_GUARDIAN_MUTATION").expect("mutation marker path"),
            );
            let trigger = PathBuf::from(
                env::var_os("MACO_TEST_GUARDIAN_TRIGGER").expect("mutation trigger path"),
            );
            let command = format!(
                "touch '{}'; while [ ! -e '{}' ]; do sleep 0.01; done; touch '{}'; sleep 30",
                started.display(),
                trigger.display(),
                mutation.display()
            );
            let _ = run_process(
                ProcessSpec::shell(
                    "runner abort guardian child",
                    Shell::UnixSh,
                    command,
                    started.parent().expect("started marker parent"),
                    128,
                )
                .with_timeout(Some(Duration::from_secs(35))),
            );
            panic!("guardian child unexpectedly returned before its runner was aborted");
        }

        if !strict_backend_available_for_tests() {
            return;
        }

        let temp = tempfile::tempdir().expect("tempdir");
        let started = temp.path().join("target-started");
        let mutation = temp.path().join("delayed-mutation");
        let trigger = temp.path().join("allow-mutation");
        let mut child = Command::new(std::env::current_exe().expect("current test executable"))
            .args([
                "--exact",
                "process_runner::tests::guardian_reaps_unit_and_blocks_mutation_after_runner_sigabrt",
            ])
            .env(CHILD_ENV, "1")
            .env("MACO_TEST_GUARDIAN_STARTED", &started)
            .env("MACO_TEST_GUARDIAN_MUTATION", &mutation)
            .env("MACO_TEST_GUARDIAN_TRIGGER", &trigger)
            .current_dir(temp.path())
            .spawn()
            .expect("spawn isolated guardian child test");
        let runner_pid = child.id();
        let start_deadline = Instant::now() + Duration::from_secs(10);
        while !started.exists() {
            assert!(
                child.try_wait().expect("query guardian child").is_none(),
                "guardian child exited before launching its target"
            );
            assert!(
                Instant::now() < start_deadline,
                "guardian child did not launch its target"
            );
            thread::sleep(POLL_INTERVAL);
        }

        let runner_pid_t = libc::pid_t::try_from(runner_pid).expect("runner pid_t");
        // SAFETY: runner_pid identifies the live isolated child owned by this test.
        assert_eq!(unsafe { libc::kill(runner_pid_t, libc::SIGABRT) }, 0);
        let status = child.wait().expect("reap aborted guardian child");
        assert!(!status.success());

        thread::sleep(Duration::from_millis(100));
        fs::write(&trigger, "go").expect("release any surviving target mutation");
        thread::sleep(Duration::from_millis(300));
        assert!(
            !mutation.exists(),
            "contained target mutated state after its runner was aborted"
        );

        let residue_deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let residue = systemd_runner_residue(runner_pid);
            if residue.is_empty() {
                break;
            }
            assert!(
                Instant::now() < residue_deadline,
                "aborted runner left containment residue: {}",
                residue.join("; ")
            );
            thread::sleep(Duration::from_millis(50));
        }

        let next = run_process(
            ProcessSpec::shell(
                "post-abort slot probe",
                Shell::UnixSh,
                ":",
                temp.path(),
                128,
            )
            .with_timeout(Some(Duration::from_secs(2))),
        )
        .expect("kernel released the aborted runner's slot lock");
        assert!(next.status.is_some_and(|status| status.success()));
        assert!(next.process_tree.is_verified_empty());
    }

    #[cfg(target_os = "linux")]
    fn strict_backend_available_for_tests() -> bool {
        static AVAILABLE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
        *AVAILABLE.get_or_init(|| {
            let temp = tempfile::tempdir().expect("strict backend probe tempdir");
            let marker = temp.path().join("target-ran");
            match run_process(
                ProcessSpec::shell(
                    "cached strict backend capability probe",
                    Shell::UnixSh,
                    format!("touch '{}'", marker.display()),
                    temp.path(),
                    128,
                )
                .with_timeout(Some(CONTENTION_RESILIENT_PROCESS_TEST_TIMEOUT)),
            ) {
                Ok(output) => {
                    assert!(output.safety_evidence_verified());
                    assert!(marker.exists());
                    true
                }
                Err(error) if is_verified_backend_unavailable(&error) => {
                    assert!(!marker.exists());
                    assert_current_runner_has_no_systemd_residue();
                    false
                }
                Err(error) => panic!("unexpected strict backend capability failure: {error:?}"),
            }
        })
    }

    #[cfg(target_os = "linux")]
    fn assert_current_runner_has_no_systemd_residue() {
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            let residue = systemd_runner_residue(std::process::id());
            if residue.is_empty() {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "strict backend refusal left containment residue: {}",
                residue.join("; ")
            );
            thread::sleep(Duration::from_millis(25));
        }
    }

    #[cfg(target_os = "linux")]
    fn systemd_runner_residue(runner_pid: u32) -> Vec<String> {
        let prefix = format!("maco-process-{runner_pid}-");
        let pattern = format!("{prefix}*");
        let mut residue = Vec::new();
        let systemctl = find_trusted_unix_executable(
            "systemctl",
            &[
                "/usr/bin/systemctl",
                "/bin/systemctl",
                "/run/current-system/sw/bin/systemctl",
            ],
        )
        .expect("trusted systemctl");
        let units = Command::new(systemctl)
            .args([
                "--user",
                "list-units",
                &pattern,
                "--all",
                "--no-legend",
                "--no-pager",
                "--plain",
            ])
            .output()
            .expect("list runner units");
        if !units.status.success() {
            residue.push(format!("systemctl exited with {}", units.status));
        } else {
            residue.extend(
                String::from_utf8_lossy(&units.stdout)
                    .lines()
                    .map(|line| format!("unit {line}")),
            );
        }

        let runtime_root = trusted_linux_runtime_root().expect("trusted runtime root");
        residue.extend(
            fs::read_dir(runtime_root)
                .expect("read runtime root")
                .filter_map(Result::ok)
                .filter_map(|entry| entry.file_name().into_string().ok())
                .filter(|name| name.starts_with(&prefix))
                .map(|name| format!("runtime {name}")),
        );

        let manager = systemd_user_manager_cgroup().expect("systemd user manager cgroup");
        let app_slice = Path::new("/sys/fs/cgroup")
            .join(manager.strip_prefix("/").unwrap_or(&manager))
            .join("app.slice");
        residue.extend(
            fs::read_dir(app_slice)
                .expect("read user app.slice")
                .filter_map(Result::ok)
                .filter_map(|entry| entry.file_name().into_string().ok())
                .filter(|name| name.starts_with(&prefix))
                .map(|name| format!("cgroup {name}")),
        );

        for entry in fs::read_dir("/proc").expect("read proc") {
            let Ok(entry) = entry else {
                continue;
            };
            if entry.file_name().to_string_lossy().parse::<u32>().is_err() {
                continue;
            }
            let Ok(command_line) = fs::read(entry.path().join("cmdline")) else {
                continue;
            };
            if String::from_utf8_lossy(&command_line).contains(&prefix) {
                residue.push(format!("process {}", entry.file_name().to_string_lossy()));
            }
        }
        residue
    }

    #[test]
    fn stuck_owned_io_thread_aborts_instead_of_detaching() {
        const CHILD_ENV: &str = "MACO_TEST_STUCK_IO_CHILD";
        if env::var_os(CHILD_ENV).is_some() {
            let deadline_observed = PathBuf::from(
                env::var_os("MACO_TEST_STUCK_IO_DEADLINE_OBSERVED")
                    .expect("logical deadline marker"),
            );
            let unexpected_return = PathBuf::from(
                env::var_os("MACO_TEST_STUCK_IO_UNEXPECTED_RETURN")
                    .expect("unexpected-return marker"),
            );

            struct StepClock {
                elapsed: std::cell::Cell<Duration>,
                deadline_observed: PathBuf,
                deadline_published: std::cell::Cell<bool>,
            }

            impl IoThreadClock for StepClock {
                type Deadline = Duration;

                fn deadline_after(&self, duration: Duration) -> Self::Deadline {
                    self.elapsed.get().saturating_add(duration)
                }

                fn before(&self, deadline: &Self::Deadline) -> bool {
                    self.elapsed.get() < *deadline
                }

                fn wait(&self, duration: Duration) {
                    let elapsed = self.elapsed.get().saturating_add(duration);
                    self.elapsed.set(elapsed);
                    if elapsed >= THREAD_JOIN_GRACE && !self.deadline_published.replace(true) {
                        fs::write(&self.deadline_observed, b"deadline-elapsed")
                            .expect("publish logical deadline observation");
                    }
                }
            }

            let cancel = Arc::new(AtomicBool::new(false));
            let handle = thread::spawn(|| loop {
                thread::sleep(Duration::from_secs(60));
            });
            let thread = OwnedIoThread { handle, cancel };
            let clock = StepClock {
                elapsed: std::cell::Cell::new(Duration::ZERO),
                deadline_observed,
                deadline_published: std::cell::Cell::new(false),
            };
            let _ = thread.finish_with_clock(false, "synthetic stuck I/O owner", &clock);
            fs::write(unexpected_return, b"returned")
                .expect("publish unexpected stuck-owner return");
            panic!("stuck owner unexpectedly returned");
        }

        let temp = tempfile::tempdir().expect("tempdir");
        let deadline_observed = temp.path().join("deadline-observed");
        let unexpected_return = temp.path().join("unexpected-return");
        let mut child = Command::new(std::env::current_exe().expect("current test executable"))
            .args([
                "--exact",
                "process_runner::tests::stuck_owned_io_thread_aborts_instead_of_detaching",
            ])
            .env(CHILD_ENV, "1")
            .env("MACO_TEST_STUCK_IO_DEADLINE_OBSERVED", &deadline_observed)
            .env("MACO_TEST_STUCK_IO_UNEXPECTED_RETURN", &unexpected_return)
            .current_dir(temp.path())
            .spawn()
            .expect("spawn stuck-owner child test");
        // This is only a harness liveness fuse, not the cleanup-deadline assertion. Its 60-second
        // margin is 120 times the production join grace; expiry means the injected clock no longer
        // drives the owner to its fail-closed state, rather than that cleanup was slightly slow.
        let harness_deadline = Instant::now() + Duration::from_secs(60);
        let status = loop {
            if let Some(status) = child.try_wait().expect("poll logical-deadline child") {
                break status;
            }
            if Instant::now() >= harness_deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("stuck-owner child did not react to the injected cleanup deadline");
            }
            thread::sleep(POLL_INTERVAL);
        };
        assert!(!status.success());
        assert!(
            deadline_observed.exists(),
            "owner failed closed before the injected join deadline elapsed"
        );
        assert!(
            !unexpected_return.exists(),
            "stuck I/O owner was detached instead of failing closed"
        );
    }

    #[cfg(unix)]
    #[test]
    fn absent_process_group_skips_termination_grace() {
        use std::os::unix::process::CommandExt;

        let mut command = Command::new("sh");
        command.args(["-c", "exit 0"]);
        command.process_group(0);
        let mut child = command.spawn().expect("spawn short-lived child");
        child.wait().expect("wait for short-lived child");
        let wait_calls = std::cell::Cell::new(0usize);

        let error =
            terminate_unix_process_group_with_wait(&mut child, true, "short-lived child", |_| {
                wait_calls.set(wait_calls.get() + 1)
            });

        assert_eq!(error, None);
        assert_eq!(wait_calls.get(), 0, "missing groups must skip TERM grace");
    }

    #[cfg(unix)]
    #[test]
    fn required_containment_kills_setsid_pipe_and_stdin_holders() {
        const READINESS_FUSE: Duration = Duration::from_secs(10);
        const POST_RELEASE_BOUND: Duration = Duration::from_secs(2);

        if !strict_backend_available_for_tests() {
            return;
        }
        let temp = tempfile::tempdir().expect("tempdir");
        let escaped_pid_path = temp.path().join("escaped.pid");
        let target_ready_path = temp.path().join("target-ready");
        let release_target_path = temp.path().join("release-target");
        let command = format!(
            "exec 3<&0; setsid sh -c 'echo $$ > \"{}\"; sleep 30' <&3 & i=0; while [ ! -s \"{}\" ] && [ \"$i\" -lt 100 ]; do sleep 0.01; i=$((i + 1)); done; test -s \"{}\" || exit 1; touch \"{}\"; while [ ! -e \"{}\" ]; do sleep 0.01; done",
            escaped_pid_path.display(),
            escaped_pid_path.display(),
            escaped_pid_path.display(),
            target_ready_path.display(),
            release_target_path.display(),
        );
        let spec = ProcessSpec::shell(
            "escaped pipe holder",
            Shell::UnixSh,
            command,
            temp.path(),
            1024,
        )
        .with_stdin(StdinMode::Bytes(vec![b'x'; 4 * 1024 * 1024]))
        // Allow shared systemd-slot and setup contention to settle before the target publishes
        // readiness; the post-ready cleanup remains independently bounded below.
        .with_timeout(Some(Duration::from_secs(10)));
        let (completion_tx, completion_rx) = mpsc::channel();
        let worker = thread::spawn(move || {
            let _ = completion_tx.send(run_process(spec));
        });
        let output = {
            // This fuse is independent of the process timeout and post-release bound. Expiry
            // means the strict target made no observable readiness progress for ten seconds.
            let readiness_deadline = Instant::now()
                .checked_add(READINESS_FUSE)
                .expect("representable strict readiness deadline");
            while !target_ready_path.exists() && !worker.is_finished() {
                assert!(
                    Instant::now() < readiness_deadline,
                    "escaped pipe holder did not publish readiness within ten seconds"
                );
                thread::sleep(POLL_INTERVAL);
            }
            assert!(
                target_ready_path.exists(),
                "escaped pipe holder exited before publishing readiness"
            );

            // Shared systemd-slot and setup contention is not kill latency. Release the main
            // shell only after its escaped stdin/pipe holder is ready, then keep the safety bound
            // focused on finalization proving the complete contained tree empty. The completion
            // event is emitted after the complete `run_process` call, including its blocking
            // containment commands and internal I/O joins. Two seconds preserves the original
            // post-release contract; expiry means cleanup itself stopped being prompt. Avoiding a
            // JoinHandle wait ensures a regression fails this test instead of hanging the suite.
            let release_started = Instant::now();
            fs::write(&release_target_path, b"release").expect("release escaped pipe holder");
            let completion = completion_rx
                .recv_timeout(POST_RELEASE_BOUND.saturating_sub(release_started.elapsed()))
                .expect(
                    "escaped pipe holder completed within its two-second post-release contract",
                );
            let post_release_elapsed = release_started.elapsed();
            assert!(
                post_release_elapsed < POST_RELEASE_BOUND,
                "escaped pipe holder exceeded its whole post-release two-second contract: {post_release_elapsed:?}"
            );
            completion.expect("run escaped pipe holder")
        };

        let escaped_pid = std::fs::read_to_string(&escaped_pid_path)
            .expect("escaped process pid")
            .trim()
            .parse::<u32>()
            .expect("numeric escaped process pid");
        assert!(output.status.is_some_and(|status| status.success()));
        assert!(!output.timed_out);
        assert_eq!(output.process_error, None);
        assert!(output.process_tree.is_verified_empty());
        let escaped_pid = libc::pid_t::try_from(escaped_pid).expect("pid_t escaped pid");
        // SAFETY: signal 0 probes existence without delivering a signal.
        assert_eq!(unsafe { libc::kill(escaped_pid, 0) }, -1);
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ESRCH),
            "escaped descendant survived return"
        );
    }

    #[cfg(unix)]
    #[test]
    fn stdin_and_environment_modes_are_explicit() {
        let temp = tempfile::tempdir().expect("tempdir");
        let mut environment = BTreeMap::new();
        environment.insert("MACO_PROCESS_TEST".to_string(), "present".to_string());
        let spec = ProcessSpec::shell(
            "stdin/env command",
            Shell::UnixSh,
            "read value; printf '%s:%s:%s' \"$MACO_PROCESS_TEST\" \"$value\" \"${HOME-unset}\"",
            temp.path(),
            1024,
        )
        .with_containment(ContainmentPolicy::TrustedBestEffort)
        .with_environment(EnvironmentMode::ClearAndSet(environment))
        .with_stdin(StdinMode::Bytes(b"payload\n".to_vec()))
        .with_timeout(Some(Duration::from_secs(1)));

        let output = run_process(spec).expect("run stdin/env command");

        assert!(output.status.is_some_and(|status| status.success()));
        assert_eq!(
            output.stdout.summarize_chars(1024).text,
            "present:payload:unset"
        );
        assert_eq!(output.stdin_error, None);
    }

    #[test]
    fn spawn_error_identifies_command_label_and_directory() {
        let temp = tempfile::tempdir().expect("tempdir");
        let missing_program = temp.path().join("missing-program");
        let spec = ProcessSpec::direct(
            "missing command",
            &missing_program,
            Vec::<OsString>::new(),
            temp.path(),
            128,
        );

        let error = run_process(spec).expect_err("missing command must fail to spawn");

        match &error {
            ProcessRunError::Spawn {
                label,
                command,
                current_dir,
                ..
            } => {
                assert_eq!(label, "missing command");
                assert!(command.contains(&missing_program.display().to_string()));
                assert_eq!(current_dir, temp.path());
            }
            other => panic!("expected spawn error, got {other:?}"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn invalid_tee_path_prevents_child_side_effects() {
        let temp = tempfile::tempdir().expect("tempdir");
        let marker = temp.path().join("child-ran");
        let missing_tee_parent = temp.path().join("missing").join("stdout.log");
        let command = format!("touch '{}'", marker.display());
        let spec = ProcessSpec::shell(
            "command with invalid tee",
            Shell::UnixSh,
            command,
            temp.path(),
            128,
        )
        .with_stdout(StreamCapture::bounded(128).tee_to(missing_tee_parent));

        let error = run_process(spec).expect_err("invalid tee must fail before spawn");

        assert!(matches!(error, ProcessRunError::OpenTee { .. }));
        assert!(!marker.exists());
    }

    #[cfg(unix)]
    #[test]
    fn new_tee_preflight_error_removes_only_created_inode() {
        const CHILD_ENV: &str = "MACO_TEST_NEW_TEE_PREFLIGHT_CHILD";
        if env::var_os(CHILD_ENV).is_some() {
            let root = PathBuf::from(env::var_os("MACO_TEST_TEE_ROOT").expect("tee root"));
            let tee = root.join("new-tee.log");
            let marker = root.join("target-ran");
            let error = run_process(
                ProcessSpec::shell(
                    "new tee preflight failure",
                    Shell::UnixSh,
                    format!("touch '{}'", marker.display()),
                    &root,
                    128,
                )
                .with_stdout(StreamCapture::bounded(128).tee_to(&tee)),
            )
            .expect_err("synthetic new tee preflight failure");
            assert!(matches!(error, ProcessRunError::OpenTee { .. }));
            assert!(!tee.exists());
            assert!(!marker.exists());
            return;
        }

        let temp = tempfile::tempdir().expect("tempdir");
        let status = Command::new(std::env::current_exe().expect("current test executable"))
            .args([
                "--exact",
                "process_runner::tests::new_tee_preflight_error_removes_only_created_inode",
            ])
            .env(CHILD_ENV, "1")
            .env("MACO_TEST_TEE_ROOT", temp.path())
            .env("MACO_TEST_FAIL_NEW_TEE_PREFLIGHT", "1")
            .status()
            .expect("run isolated new tee preflight failure");
        assert!(status.success());
        assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 0);
    }

    #[cfg(unix)]
    #[test]
    fn same_tee_file_is_rejected_before_child_spawn() {
        let temp = tempfile::tempdir().expect("tempdir");
        let tee_path = temp.path().join("combined.log");
        let marker = temp.path().join("child-ran");
        std::fs::write(&tee_path, "preserve me").expect("write existing tee");
        let command = format!("touch '{}'", marker.display());
        let spec = ProcessSpec::shell("same tee command", Shell::UnixSh, command, temp.path(), 128)
            .with_stdout(StreamCapture::bounded(128).tee_to(&tee_path))
            .with_stderr(StreamCapture::bounded(128).tee_to(&tee_path));

        let error = run_process(spec).expect_err("same tee must be rejected");

        assert!(matches!(error, ProcessRunError::TeeConflict { .. }));
        assert_eq!(
            std::fs::read_to_string(&tee_path).expect("read preserved tee"),
            "preserve me"
        );
        assert!(!marker.exists());
    }

    #[cfg(unix)]
    #[test]
    fn hard_linked_tee_files_are_rejected() {
        let temp = tempfile::tempdir().expect("tempdir");
        let stdout_path = temp.path().join("stdout.log");
        let stderr_path = temp.path().join("stderr.log");
        std::fs::write(&stdout_path, "preserve me").expect("write stdout tee");
        std::fs::hard_link(&stdout_path, &stderr_path).expect("hard link stderr tee");
        let spec = ProcessSpec::shell(
            "hard-linked tee command",
            Shell::UnixSh,
            ":",
            temp.path(),
            128,
        )
        .with_stdout(StreamCapture::bounded(128).tee_to(&stdout_path))
        .with_stderr(StreamCapture::bounded(128).tee_to(&stderr_path));

        let error = run_process(spec).expect_err("hard-linked tees must be rejected");

        assert!(matches!(error, ProcessRunError::OpenTee { .. }));
        assert_eq!(
            std::fs::read_to_string(&stdout_path).expect("read preserved tee"),
            "preserve me"
        );
    }

    #[cfg(unix)]
    #[test]
    fn second_tee_preflight_failure_preserves_first_file() {
        let temp = tempfile::tempdir().expect("tempdir");
        let stdout_path = temp.path().join("stdout.log");
        let invalid_stderr_path = temp.path().join("stderr-directory");
        let marker = temp.path().join("child-ran");
        std::fs::write(&stdout_path, "preserve me").expect("write stdout tee");
        std::fs::create_dir(&invalid_stderr_path).expect("create invalid stderr directory");
        let command = format!("touch '{}'", marker.display());
        let spec = ProcessSpec::shell(
            "transactional tee command",
            Shell::UnixSh,
            command,
            temp.path(),
            128,
        )
        .with_stdout(StreamCapture::bounded(128).tee_to(&stdout_path))
        .with_stderr(StreamCapture::bounded(128).tee_to(&invalid_stderr_path));

        let error = run_process(spec).expect_err("invalid second tee must fail preflight");

        assert!(matches!(error, ProcessRunError::OpenTee { .. }));
        assert_eq!(
            std::fs::read_to_string(&stdout_path).expect("read preserved stdout tee"),
            "preserve me"
        );
        assert!(!marker.exists());

        let new_stdout_path = temp.path().join("new-stdout.log");
        let second_spec = ProcessSpec::shell(
            "new tee rollback command",
            Shell::UnixSh,
            ":",
            temp.path(),
            128,
        )
        .with_stdout(StreamCapture::bounded(128).tee_to(&new_stdout_path))
        .with_stderr(StreamCapture::bounded(128).tee_to(&invalid_stderr_path));
        let second_error =
            run_process(second_spec).expect_err("new first tee must roll back on second failure");
        assert!(matches!(second_error, ProcessRunError::OpenTee { .. }));
        assert!(!new_stdout_path.exists());
    }

    #[cfg(unix)]
    #[test]
    fn tee_transaction_rolls_back_single_and_second_helper_start_failures() {
        const CHILD_ENV: &str = "MACO_TEST_TEE_TRANSACTION_CHILD";
        if let Some(case) = env::var_os(CHILD_ENV) {
            let root = PathBuf::from(env::var_os("MACO_TEST_TEE_ROOT").expect("tee root"));
            let stdout_path = root.join("stdout.log");
            let stderr_path = root.join("stderr.log");
            let marker = root.join("target-ran");
            let mut stdout_before = None;
            let mut spec = ProcessSpec::shell(
                "transactional helper failure",
                Shell::UnixSh,
                format!("touch '{}'", marker.display()),
                &root,
                128,
            )
            .with_stdout(StreamCapture::bounded(128).tee_to(&stdout_path));
            match case.to_string_lossy().as_ref() {
                "single" => {
                    fs::write(&stdout_path, "original stdout").expect("seed stdout");
                }
                "second" | "second-truncate" => {
                    use std::os::unix::fs::MetadataExt;
                    fs::write(&stdout_path, "original stdout").expect("seed stdout");
                    fs::write(&stderr_path, "original stderr").expect("seed stderr");
                    let metadata = fs::metadata(&stdout_path).expect("stdout metadata before");
                    stdout_before = Some((
                        metadata.ino(),
                        metadata.mtime(),
                        metadata.mtime_nsec(),
                        metadata.len(),
                    ));
                    spec = spec.with_stderr(StreamCapture::bounded(128).tee_to(&stderr_path));
                }
                "new-second" => {
                    spec = spec.with_stderr(StreamCapture::bounded(128).tee_to(&stderr_path));
                }
                other => panic!("unexpected tee transaction case {other}"),
            }

            let error = run_process(spec).expect_err("synthetic tee helper failure");
            assert!(matches!(error, ProcessRunError::OpenTee { .. }));
            assert!(!marker.exists());
            match case.to_string_lossy().as_ref() {
                "single" => {
                    assert_eq!(fs::read_to_string(&stdout_path).unwrap(), "original stdout");
                }
                "second" | "second-truncate" => {
                    use std::os::unix::fs::MetadataExt;
                    assert_eq!(fs::read_to_string(&stdout_path).unwrap(), "original stdout");
                    assert_eq!(fs::read_to_string(&stderr_path).unwrap(), "original stderr");
                    let metadata = fs::metadata(&stdout_path).expect("stdout metadata after");
                    if case == "second" {
                        assert_eq!(
                            stdout_before,
                            Some((
                                metadata.ino(),
                                metadata.mtime(),
                                metadata.mtime_nsec(),
                                metadata.len(),
                            )),
                            "pre-truncate helper failure rewrote untouched stdout"
                        );
                    }
                }
                "new-second" => {
                    assert!(!stdout_path.exists());
                    assert!(!stderr_path.exists());
                }
                _ => unreachable!(),
            }
            assert_eq!(
                fs::read_dir(&root)
                    .expect("tee root entries")
                    .filter_map(Result::ok)
                    .filter(|entry| entry.file_name().to_string_lossy().starts_with(".maco-tee"))
                    .count(),
                0
            );
            return;
        }

        for (case, failpoint, failed_stream) in [
            ("single", "MACO_TEST_FAIL_TEE_HELPER_STREAM", "stdout"),
            ("second", "MACO_TEST_FAIL_TEE_HELPER_STREAM", "stderr"),
            (
                "second-truncate",
                "MACO_TEST_FAIL_TEE_TRUNCATE_STREAM",
                "stderr",
            ),
            ("new-second", "MACO_TEST_FAIL_TEE_HELPER_STREAM", "stderr"),
        ] {
            let temp = tempfile::tempdir().expect("tempdir");
            let mut command =
                Command::new(std::env::current_exe().expect("current test executable"));
            command
                .args([
                    "--exact",
                    "process_runner::tests::tee_transaction_rolls_back_single_and_second_helper_start_failures",
                ])
                .env(CHILD_ENV, case)
                .env("MACO_TEST_TEE_ROOT", temp.path())
                .env(failpoint, failed_stream);
            if case == "second" {
                command.env("MACO_TEST_FAIL_TEE_RESTORE", "1");
            }
            let status = command.status().expect("run isolated tee transaction case");
            assert!(status.success(), "tee transaction child {case} failed");
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn tee_transaction_rolls_back_spawn_and_pre_release_io_failures() {
        const CHILD_ENV: &str = "MACO_TEST_TEE_SETUP_ROLLBACK_CHILD";
        if let Some(case) = env::var_os(CHILD_ENV) {
            let root = PathBuf::from(env::var_os("MACO_TEST_TEE_ROOT").expect("tee root"));
            let stdout_path = root.join("stdout.log");
            let stderr_path = root.join("stderr.log");
            let helper_pids = root.join("helper-pids");
            let marker = root.join("target-ran");
            fs::write(&stdout_path, "original stdout").expect("seed stdout");
            fs::write(&stderr_path, "original stderr").expect("seed stderr");
            let error = run_process(
                ProcessSpec::shell(
                    "tee setup rollback",
                    Shell::UnixSh,
                    format!("touch '{}'", marker.display()),
                    &root,
                    128,
                )
                .with_containment(ContainmentPolicy::TrustedBestEffort)
                .with_stdout(StreamCapture::bounded(128).tee_to(&stdout_path))
                .with_stderr(StreamCapture::bounded(128).tee_to(&stderr_path))
                .with_timeout(Some(Duration::from_secs(3))),
            )
            .expect_err("synthetic setup failure");
            match case.to_string_lossy().as_ref() {
                "spawn" => assert!(matches!(error, ProcessRunError::Spawn { .. })),
                "io" => assert!(matches!(error, ProcessRunError::IoSetup { .. })),
                other => panic!("unexpected setup rollback case {other}"),
            }
            assert!(!marker.exists());
            assert_eq!(fs::read_to_string(&stdout_path).unwrap(), "original stdout");
            assert_eq!(fs::read_to_string(&stderr_path).unwrap(), "original stderr");
            for pid in fs::read_to_string(helper_pids)
                .expect("helper pids")
                .lines()
            {
                let pid = pid.parse::<libc::pid_t>().expect("helper pid");
                // SAFETY: signal zero only probes a tee helper started by this isolated test.
                assert_eq!(unsafe { libc::kill(pid, 0) }, -1);
                assert_eq!(
                    std::io::Error::last_os_error().raw_os_error(),
                    Some(libc::ESRCH)
                );
            }
            assert_eq!(
                fs::read_dir(&root)
                    .unwrap()
                    .filter_map(Result::ok)
                    .filter(|entry| entry.file_name().to_string_lossy().starts_with(".maco-tee"))
                    .count(),
                0
            );
            return;
        }

        for (case, failpoint) in [
            ("spawn", "MACO_TEST_FAIL_BEFORE_CHILD_SPAWN"),
            ("io", "MACO_TEST_FAIL_PRE_RELEASE_IO_SETUP"),
        ] {
            let temp = tempfile::tempdir().expect("tempdir");
            let status = Command::new(std::env::current_exe().expect("current test executable"))
                .args([
                    "--exact",
                    "process_runner::tests::tee_transaction_rolls_back_spawn_and_pre_release_io_failures",
                ])
                .env(CHILD_ENV, case)
                .env("MACO_TEST_TEE_ROOT", temp.path())
                .env(
                    "MACO_TEST_TEE_HELPER_PID_FILE",
                    temp.path().join("helper-pids"),
                )
                .env(failpoint, "1")
                .status()
                .expect("run isolated tee setup rollback case");
            assert!(status.success(), "tee setup rollback child {case} failed");
        }
    }

    #[cfg(unix)]
    #[test]
    fn tee_preflight_rejects_symlink_without_touching_target() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().expect("tempdir");
        let target = temp.path().join("target.log");
        let link = temp.path().join("tee.log");
        let marker = temp.path().join("target-ran");
        fs::write(&target, "preserve target").expect("seed symlink target");
        symlink(&target, &link).expect("create tee symlink");
        let error = run_process(
            ProcessSpec::shell(
                "symlink tee",
                Shell::UnixSh,
                format!("touch '{}'", marker.display()),
                temp.path(),
                128,
            )
            .with_stdout(StreamCapture::bounded(128).tee_to(&link)),
        )
        .expect_err("symlink tee must fail before target start");

        assert!(matches!(error, ProcessRunError::OpenTee { .. }));
        assert_eq!(fs::read_to_string(target).unwrap(), "preserve target");
        assert!(!marker.exists());
    }

    #[cfg(unix)]
    #[test]
    fn tee_transaction_detects_path_swap_and_restores_pinned_inode() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("tee.log");
        let moved = temp.path().join("original-inode.log");
        fs::write(&path, "original contents").expect("seed tee");
        let capture = StreamCapture::bounded(128).tee_to(&path);
        let transaction = prepare_tees(
            "path swap",
            &capture,
            &StreamCapture::bounded(128),
            false,
            None,
            "test",
        )
        .expect("prepare tee transaction");
        let helper_pid = transaction
            .stdout
            .as_ref()
            .and_then(|tee| tee.writer.as_ref())
            .map(|writer| writer.helper.child.id())
            .expect("stdout helper pid");
        fs::rename(&path, &moved).expect("move pinned tee inode");
        fs::write(&path, "replacement contents").expect("install replacement path");

        let error = transaction
            .validate("path swap")
            .expect_err("path swap must invalidate tee transaction");
        assert!(matches!(error, ProcessRunError::OpenTee { .. }));
        drop(transaction);

        assert_eq!(fs::read_to_string(moved).unwrap(), "original contents");
        assert_eq!(fs::read_to_string(path).unwrap(), "replacement contents");
        let helper_pid = libc::pid_t::try_from(helper_pid).expect("helper pid_t");
        // SAFETY: signal zero only probes the helper PID captured above.
        assert_eq!(unsafe { libc::kill(helper_pid, 0) }, -1);
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ESRCH)
        );
        assert_eq!(
            fs::read_dir(temp.path())
                .unwrap()
                .filter_map(Result::ok)
                .filter(|entry| entry.file_name().to_string_lossy().starts_with(".maco-tee"))
                .count(),
            0
        );
    }

    #[cfg(unix)]
    #[test]
    fn created_tee_path_swap_never_unlinks_replacement() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("tee.log");
        let moved = temp.path().join("opened-inode.log");
        let capture = StreamCapture::bounded(128).tee_to(&path);
        let transaction = prepare_tees(
            "created path swap",
            &capture,
            &StreamCapture::bounded(128),
            false,
            None,
            "test",
        )
        .expect("prepare new tee transaction");
        let helper_pid = transaction
            .stdout
            .as_ref()
            .and_then(|tee| tee.writer.as_ref())
            .map(|writer| writer.helper.child.id())
            .expect("stdout helper pid");
        fs::rename(&path, &moved).expect("move opened tee inode");
        fs::write(&path, "replacement contents").expect("install replacement path");

        let error = transaction
            .validate("created path swap")
            .expect_err("created path swap must invalidate transaction");
        assert!(matches!(error, ProcessRunError::OpenTee { .. }));
        drop(transaction);

        assert_eq!(fs::read_to_string(&path).unwrap(), "replacement contents");
        assert_eq!(fs::metadata(&moved).unwrap().len(), 0);
        let helper_pid = libc::pid_t::try_from(helper_pid).expect("helper pid_t");
        // SAFETY: signal zero only probes the helper PID captured above.
        assert_eq!(unsafe { libc::kill(helper_pid, 0) }, -1);
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ESRCH)
        );
        assert_eq!(
            fs::read_dir(temp.path())
                .unwrap()
                .filter_map(Result::ok)
                .filter(|entry| entry.file_name().to_string_lossy().starts_with(".maco-tee"))
                .count(),
            0
        );
    }

    #[test]
    fn tee_backup_restores_content_and_removes_temporary_file() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("tee.log");
        std::fs::write(&path, "original tee contents").expect("write tee source");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                .expect("restrict tee source permissions");
        }
        let source = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .expect("open tee source");
        let backup = TeeBackup::create(&source, &path).expect("create tee backup");
        let backup_path = backup.path.clone();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&backup_path)
                    .expect("backup metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        let mut destination = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .expect("open tee destination");
        destination.set_len(0).expect("truncate destination");
        destination
            .write_all(b"partial")
            .expect("write partial tee");

        backup
            .restore(&mut destination)
            .expect("restore tee backup");
        drop(destination);
        drop(backup);

        assert_eq!(
            std::fs::read_to_string(&path).expect("read restored tee"),
            "original tee contents"
        );
        assert!(!backup_path.exists());
    }

    #[cfg(unix)]
    #[test]
    fn wait_error_evidence_retains_captured_output_and_cleanup_diagnostics() {
        let temp = tempfile::tempdir().expect("tempdir");
        let spec = ProcessSpec::shell(
            "evidence child",
            Shell::UnixSh,
            "printf retained-stdout; printf retained-stderr >&2; sleep 30",
            temp.path(),
            1024,
        )
        .with_stdin(StdinMode::Null)
        .with_containment(ContainmentPolicy::TrustedBestEffort);
        let cancellation = ProcessCancellation::new();
        let mut prepared_tree = PreparedProcessTree::prepare(
            spec.containment,
            &spec.side_effects,
            "evidence child",
            "sh",
            None,
            &cancellation,
        )
        .expect("prepare evidence containment");
        let mut command = prepared_tree
            .build_command(&spec)
            .expect("build evidence child");
        command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command.spawn().expect("spawn evidence child");
        let attached_tree = prepared_tree
            .attach(&mut child, "evidence child", "sh", None, &cancellation)
            .expect("attach evidence child");
        let prepared = PreparedChildIo::take(&mut child, &StdinMode::Null)
            .expect("prepare evidence child I/O");
        let mut process_tree = attached_tree
            .release(&mut child, "evidence child", "sh", None, &cancellation)
            .expect("release evidence child");
        let (input_writer, mut output_drainers) =
            prepared.start("evidence child", StdinMode::Null, 1024, 1024, None, None);
        // Real pipe-reader delivery is part of this integration test. Sixty seconds is a harness
        // fuse for two tiny writes; expiry means the owned reader threads made no observable
        // progress, not that a loaded host scheduled them a few milliseconds late.
        let deadline = Instant::now() + Duration::from_secs(60);
        while output_drainers.stdout.capture.bytes.is_empty()
            || output_drainers.stderr.capture.bytes.is_empty()
        {
            output_drainers.drain_ready();
            assert!(Instant::now() < deadline, "child output was not captured");
            thread::sleep(IO_CANCEL_POLL_INTERVAL);
        }

        let evidence = cleanup_after_wait_error(
            &mut child,
            &mut process_tree,
            "evidence child",
            output_drainers,
            input_writer,
        );

        assert_eq!(evidence.stdout.as_bytes(), b"retained-stdout");
        assert_eq!(evidence.stderr.as_bytes(), b"retained-stderr");
        let error = ProcessRunError::Wait {
            label: "evidence child".to_string(),
            command: "sh".to_string(),
            evidence: Box::new(evidence),
            source: std::io::Error::other("synthetic wait failure"),
        };
        assert!(error.to_string().contains("retained-stdout"));
        assert!(error.to_string().contains("retained-stderr"));
    }

    #[test]
    fn platform_shell_is_concrete() {
        #[cfg(target_os = "windows")]
        assert_eq!(Shell::for_current_platform(), Shell::WindowsCmd);

        #[cfg(not(target_os = "windows"))]
        assert_eq!(Shell::for_current_platform(), Shell::UnixSh);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_children_start_suspended_in_a_new_process_group() {
        const CREATE_SUSPENDED: u32 = 0x0000_0004;
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
        assert_ne!(WINDOWS_PROCESS_CREATION_FLAGS & CREATE_SUSPENDED, 0);
        assert_ne!(WINDOWS_PROCESS_CREATION_FLAGS & CREATE_NEW_PROCESS_GROUP, 0);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_tee_identity_uses_volume_and_file_index() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("tee.log");
        let hard_link = temp.path().join("tee-hardlink.log");
        let replacement = temp.path().join("replacement.log");
        fs::write(&path, "tee").expect("write tee");
        fs::hard_link(&path, &hard_link).expect("hard-link tee");
        fs::write(&replacement, "replacement").expect("write replacement");
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .expect("open tee");

        assert!(tee_path_matches_file(&hard_link, &file).expect("hard-link identity"));
        assert!(!tee_path_matches_file(&replacement, &file).expect("replacement identity"));
    }

    #[test]
    fn bounded_buffer_never_grows_past_limit() {
        let mut buffer = BoundedBuffer::new(3);
        buffer.push(b"abcdef");
        buffer.push(b"ghij");
        let captured = buffer.into_captured();
        assert_eq!(captured.as_bytes(), b"abc");
        assert!(captured.is_truncated());
    }

    #[test]
    fn direct_command_constructor_preserves_arguments() {
        let spec = ProcessSpec::direct(
            "direct",
            PathBuf::from("program"),
            ["one", "two"],
            PathBuf::from("."),
            128,
        );
        assert_eq!(
            spec.command,
            ProcessCommand::Direct {
                program: PathBuf::from("program"),
                args: vec![OsString::from("one"), OsString::from("two")],
            }
        );
        assert!(spec.pinned_direct.is_none());
    }

    #[cfg(unix)]
    #[test]
    fn agent_lifecycle_metadata_stamps_environment_and_registers_running_process() {
        let temp = tempfile::tempdir().expect("tempdir");
        git2::Repository::init(temp.path()).expect("init repository");
        let metadata = AgentLaunchMetadata::new(temp.path(), "worker", "runner-run", "runner-task")
            .expect("lifecycle metadata");
        let sleep = [
            "/run/current-system/sw/bin/sleep",
            "/usr/bin/sleep",
            "/bin/sleep",
        ]
        .into_iter()
        .map(Path::new)
        .find(|path| path.is_file())
        .expect("sleep executable")
        .to_path_buf();
        let spec = ProcessSpec::direct("lifecycle sleep", sleep, ["60"], temp.path(), 128)
            .with_environment(EnvironmentMode::ClearAndSet(BTreeMap::from([(
                "PATH".to_string(),
                "/run/current-system/sw/bin:/usr/bin:/bin".to_string(),
            )])))
            .with_agent_lifecycle(metadata);
        let EnvironmentMode::ClearAndSet(environment) = &spec.environment else {
            panic!("expected clear-and-set environment");
        };
        assert_eq!(
            environment.get(MACO_RUN_ID_ENV).map(String::as_str),
            Some("runner-run")
        );
        assert_eq!(
            environment.get(MACO_TASK_ID_ENV).map(String::as_str),
            Some("runner-task")
        );

        let registry = AgentRegistry::open(temp.path()).expect("agent registry");
        let runner = thread::spawn(move || run_process(spec));
        let registered = loop {
            let processes = registry
                .list(&crate::agent_lifecycle::AgentListFilter::default())
                .expect("list lifecycle processes");
            if let Some(process) = processes.first() {
                break process.clone();
            }
            assert!(
                !runner.is_finished(),
                "process runner completed before registering its agent lifecycle identity"
            );
            thread::sleep(Duration::from_millis(10));
        };
        assert_eq!(registered.run_id, "runner-run");
        assert_eq!(registered.task_id, "runner-task");
        assert_eq!(registered.argv.last().map(String::as_str), Some("60"));

        // This is the one real signal-delivery deadline in the test. Thirty seconds is a liveness
        // margin for stopping one local sleep process; expiry means lifecycle termination made no
        // progress, not that registration ordering was scheduled a few milliseconds late.
        let stopped = registry
            .stop_selector("runner-task", Duration::from_secs(30))
            .expect("stop lifecycle process");
        assert_eq!(stopped.stopped.len(), 1);
        let output = runner
            .join()
            .unwrap_or_else(|_| panic!("process runner thread panicked"))
            .expect("process runner result");
        assert!(output.status.is_some_and(|status| !status.success()));
    }

    #[test]
    fn shell_constructor_preserves_general_unpinned_behavior() {
        let spec = ProcessSpec::shell(
            "shell",
            Shell::for_current_platform(),
            "echo unchanged",
            PathBuf::from("."),
            128,
        );
        assert!(matches!(spec.command, ProcessCommand::Shell { .. }));
        assert!(spec.pinned_direct.is_none());
        assert!(spec.command_display().contains("echo unchanged"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn pinned_guardian_bootstraps_helper_with_an_empty_environment() {
        assert!(SYSTEMD_GUARDIAN_SCRIPT
            .contains("if [ \"$target_environment_mode\" = descriptor ]; then"));
        assert!(SYSTEMD_GUARDIAN_SCRIPT.contains("exec \"$env_program\" -i \"$@\" || exit 125"));
        let descriptor_branch = SYSTEMD_GUARDIAN_SCRIPT
            .split("if [ \"$target_environment_mode\" = descriptor ]; then")
            .nth(1)
            .and_then(|text| text.split("fi").next())
            .expect("descriptor guardian branch");
        assert!(!descriptor_branch.contains(". \"$1\""));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn pinned_direct_capability_is_direct_only_and_detects_command_drift() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().expect("tempdir");
        let program = temp.path().join("program");
        fs::write(&program, b"native executable fixture").expect("write program");
        fs::set_permissions(&program, fs::Permissions::from_mode(0o755)).expect("chmod program");
        let capability = PinnedDirectExecutable::capture_for_test(&program).expect("capture");

        let spec = ProcessSpec::direct("pinned", &program, ["--fixed"], temp.path(), 128)
            .with_pinned_direct_executable(capability.clone())
            .expect("attach capability");
        assert!(spec.pinned_direct.is_some());
        assert!(spec.command_display().contains("arguments redacted"));
        assert!(!spec.command_display().contains("--fixed"));

        let mut drifted = spec.clone();
        let ProcessCommand::Direct { args, .. } = &mut drifted.command else {
            panic!("direct command");
        };
        args.push(OsString::from("--drifted"));
        let error = drifted
            .pinned_direct
            .as_ref()
            .expect("pinned binding")
            .validate_command(&drifted.command)
            .expect_err("argv drift must fail");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);

        let shell_error = ProcessSpec::shell("shell", Shell::UnixSh, ":", temp.path(), 128)
            .with_pinned_direct_executable(capability)
            .expect_err("shell pinning must fail");
        assert_eq!(shell_error.kind(), io::ErrorKind::InvalidInput);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn real_pinned_capability_refuses_untrusted_development_helper() {
        use std::os::unix::fs::PermissionsExt;

        if pinned_exec::validated_current_helper_path().is_ok() {
            return;
        }
        let temp = tempfile::tempdir().expect("tempdir");
        let program = temp.path().join("program");
        fs::write(&program, b"native executable fixture").expect("write program");
        fs::set_permissions(&program, fs::Permissions::from_mode(0o755)).expect("chmod program");
        let error = PinnedDirectExecutable::capture(&program)
            .expect_err("development helper must fail closed");
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires a root-owned installed maco helper and trusted user-systemd runtime"]
    fn pinned_direct_strict_runtime_executes_only_after_helper_bootstrap() {
        let program = trusted_system_executable(
            "true",
            &[
                "/usr/bin/true",
                "/bin/true",
                "/run/current-system/sw/bin/true",
            ],
        )
        .expect("trusted true");
        let capability = PinnedDirectExecutable::capture(&program).expect("capture true");
        let output = run_process(
            ProcessSpec::direct(
                "pinned true",
                &program,
                Vec::<OsString>::new(),
                Path::new("/"),
                128,
            )
            .with_pinned_direct_executable(capability)
            .expect("pin true")
            .with_environment(EnvironmentMode::ClearAndSet(BTreeMap::new()))
            .with_stdin(StdinMode::Null),
        )
        .expect("run pinned true");
        assert!(output.safety_sensitive_succeeded());
    }

    #[cfg(unix)]
    #[test]
    fn trusted_best_effort_is_explicit_and_never_reported_as_verified() {
        let temp = tempfile::tempdir().expect("tempdir");
        let output = run_process(
            ProcessSpec::shell(
                "trusted compatibility command",
                Shell::UnixSh,
                ":",
                temp.path(),
                128,
            )
            .with_containment(ContainmentPolicy::TrustedBestEffort),
        )
        .expect("run trusted compatibility command");
        assert_eq!(
            output.process_tree,
            ContainmentEvidence::TrustedBestEffort(ContainmentBackend::UnixProcessGroup)
        );
        assert!(!output.process_tree.is_verified_empty());
    }

    #[test]
    fn ownership_setup_errors_preserve_cleanup_diagnostics() {
        let error = ProcessRunError::ProcessOwnership {
            label: "child".to_string(),
            command: "command".to_string(),
            source: std::io::Error::other("attach failed"),
        };
        let error =
            append_process_run_error_cleanup(error, Some("kill failed; reap failed".to_string()));
        let rendered = error.to_string();
        assert!(rendered.contains("attach failed"));
        assert!(rendered.contains("kill failed; reap failed"));
    }
}
