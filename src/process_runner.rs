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

mod nested_usage;
pub use nested_usage::{
    encode_nested_usage_record, harvest_nested_usage_journal, parent_span_id,
    prepare_nested_usage_journal, reconcile_nested_usage, stamp_nested_usage_environment,
    NestedUsageCompleteness, NestedUsageObservation, NestedUsageReconciliation, NestedUsageRequest,
    NestedUsageRuntimeKind, NestedWorkerUsageRecord, MACO_NESTED_USAGE_JOURNAL_ENV,
    MACO_PARENT_SPAN_ID_ENV, NESTED_USAGE_SCHEMA_V1,
};

const PIPE_READ_CHUNK_SIZE: usize = 8 * 1024;
const PIPE_CHANNEL_CAPACITY: usize = 8;
const MAX_PIPE_EVENTS_PER_POLL: usize = PIPE_CHANNEL_CAPACITY * 2;
const DEFAULT_MAX_STDIN_BYTES: usize = 8 * 1024 * 1024;
const DEFAULT_MAX_TEE_BYTES: usize = 8 * 1024 * 1024;
const DEFAULT_NETWORK_BOUND_CHILDREN: usize = 4;
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

/// CPU-aware process capacity used by strict containment, plus a separate conservative default
/// for the network-bound supervise scheduler.
///
/// Production uses `available_parallelism`, which reflects the runtime's effective CPU
/// quota/affinity where the standard library can observe it. A failed production measurement
/// degrades to one usable lane instead of removing the containment bound. Unit tests pin the
/// containment capacity. Supervise admission separately composes its configured provider quota
/// and measured memory, file-descriptor, and disk inputs.
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
        DEFAULT_NETWORK_BOUND_CHILDREN
    }

    pub(crate) fn supervisor_resources(
        repo: &Path,
        inputs: HostResourceInputs,
    ) -> HostResourceCapacity {
        let memory_available_mib = inputs
            .memory_available_mib
            .or_else(measured_available_memory_mib);
        let fd_available = inputs.fd_available.or_else(measured_available_fds);
        let disk_available_mib = inputs
            .disk_available_mib
            .or_else(|| measured_available_disk_mib(repo));
        let memory_bound =
            memory_available_mib.map(|available| (available / inputs.memory_per_child_mib).max(1));
        let fd_bound = fd_available.map(|available| (available / inputs.fds_per_child).max(1));
        let disk_bound =
            disk_available_mib.map(|available| (available / inputs.disk_per_child_mib).max(1));
        let resolved_children = [memory_bound, fd_bound, disk_bound]
            .into_iter()
            .flatten()
            .min()
            .unwrap_or(inputs.fallback_children)
            .max(1);
        HostResourceCapacity {
            resolved_children,
            memory_available_mib,
            memory_per_child_mib: inputs.memory_per_child_mib,
            memory_bound,
            fd_available,
            fds_per_child: inputs.fds_per_child,
            fd_bound,
            disk_available_mib,
            disk_per_child_mib: inputs.disk_per_child_mib,
            disk_bound,
            fallback_children: inputs.fallback_children,
        }
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct HostResourceInputs {
    pub(crate) memory_available_mib: Option<usize>,
    pub(crate) memory_per_child_mib: usize,
    pub(crate) fd_available: Option<usize>,
    pub(crate) fds_per_child: usize,
    pub(crate) disk_available_mib: Option<usize>,
    pub(crate) disk_per_child_mib: usize,
    pub(crate) fallback_children: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct HostResourceCapacity {
    pub(crate) resolved_children: usize,
    pub(crate) memory_available_mib: Option<usize>,
    pub(crate) memory_per_child_mib: usize,
    pub(crate) memory_bound: Option<usize>,
    pub(crate) fd_available: Option<usize>,
    pub(crate) fds_per_child: usize,
    pub(crate) fd_bound: Option<usize>,
    pub(crate) disk_available_mib: Option<usize>,
    pub(crate) disk_per_child_mib: usize,
    pub(crate) disk_bound: Option<usize>,
    pub(crate) fallback_children: usize,
}

fn measured_available_memory_mib() -> Option<usize> {
    let contents = fs::read_to_string("/proc/meminfo").ok()?;
    let kib = contents.lines().find_map(|line| {
        let value = line.strip_prefix("MemAvailable:")?.trim();
        value.strip_suffix(" kB")?.trim().parse::<usize>().ok()
    })?;
    Some((kib / 1024).max(1))
}

#[cfg(unix)]
fn measured_available_fds() -> Option<usize> {
    let mut limit = std::mem::MaybeUninit::<libc::rlimit>::uninit();
    // SAFETY: getrlimit initializes the provided rlimit on success.
    let status = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, limit.as_mut_ptr()) };
    if status != 0 {
        return None;
    }
    // SAFETY: the successful getrlimit call initialized `limit`.
    let limit = unsafe { limit.assume_init() };
    let limit = usize::try_from(limit.rlim_cur).ok()?;
    let open = fs::read_dir("/proc/self/fd").ok()?.count();
    Some(limit.saturating_sub(open).max(1))
}

#[cfg(not(unix))]
fn measured_available_fds() -> Option<usize> {
    None
}

#[cfg(unix)]
fn measured_available_disk_mib(path: &Path) -> Option<usize> {
    use std::os::unix::ffi::OsStrExt;
    let path = std::ffi::CString::new(path.as_os_str().as_bytes()).ok()?;
    let mut status = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    // SAFETY: statvfs reads a valid NUL-terminated path and initializes `status` on success.
    let result = unsafe { libc::statvfs(path.as_ptr(), status.as_mut_ptr()) };
    if result != 0 {
        return None;
    }
    // SAFETY: the successful statvfs call initialized `status`.
    let status = unsafe { status.assume_init() };
    let bytes = u128::from(status.f_bavail).checked_mul(u128::from(status.f_frsize))?;
    usize::try_from(bytes / (1024 * 1024)).ok()
}

#[cfg(not(unix))]
fn measured_available_disk_mib(_path: &Path) -> Option<usize> {
    None
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

#[cfg(all(test, target_os = "linux"))]
std::thread_local! {
    static TEST_SYSTEMD_UNIT_NAMES: std::cell::RefCell<Option<Vec<String>>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(all(test, target_os = "linux"))]
struct TestSystemdUnitNameCapture {
    active: bool,
}

#[cfg(all(test, target_os = "linux"))]
impl TestSystemdUnitNameCapture {
    fn start() -> Self {
        TEST_SYSTEMD_UNIT_NAMES.with(|names| {
            let mut names = names.borrow_mut();
            assert!(
                names.is_none(),
                "systemd unit-name captures cannot be nested"
            );
            *names = Some(Vec::new());
        });
        Self { active: true }
    }

    fn finish(mut self) -> Vec<String> {
        let names = TEST_SYSTEMD_UNIT_NAMES.with(|names| names.borrow_mut().take());
        self.active = false;
        names.unwrap_or_else(|| panic!("systemd unit-name capture was not active"))
    }
}

#[cfg(all(test, target_os = "linux"))]
impl Drop for TestSystemdUnitNameCapture {
    fn drop(&mut self) {
        if self.active {
            TEST_SYSTEMD_UNIT_NAMES.with(|names| {
                names.borrow_mut().take();
            });
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
fn record_systemd_unit_name_for_test(name: &str) {
    TEST_SYSTEMD_UNIT_NAMES.with(|names| {
        if let Some(names) = names.borrow_mut().as_mut() {
            names.push(name.to_owned());
        }
    });
}

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
/// A required run fails before releasing the requested command when the host cannot provide a
/// reviewed backend. The only reviewed writable-runtime profile is Linux user-systemd on cgroup
/// v2; macOS, Windows, and other Unix hosts refuse Required admission with a typed cause rather
/// than treating a process group, Job Object, or Git worktree as verified side-effect
/// confinement. TrustedBestEffort remains the explicit compatibility path for Fake/simulation
/// and other trusted commands: Unix process groups and Windows Job Objects never upgrade that
/// path to verified confinement. The Linux service also has an orphan-only runtime fuse: the
/// requested timeout plus 30 seconds, or 24 hours when no command timeout is requested. This
/// finite fuse is a last-resort cleanup boundary, not the command timeout reported by
/// [`ProcessOutput::timed_out`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ContainmentPolicy {
    /// Require a reviewed backend that places the child before execution and proves the complete
    /// subtree empty before success. Hosts without a reviewed profile fail closed before spawn.
    #[default]
    Required,
    /// Explicit compatibility mode for trusted commands. Unix process groups do not contain
    /// descendants that deliberately call `setsid` or move to another process group, and a
    /// Windows Job Object is not verified side-effect confinement.
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
    ExternalGrok,
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
#[derive(Clone)]
struct ExternalGrokReadOnlyFileCapability {
    path: PathBuf,
    held_file: Arc<File>,
    identity: ExternalGrokReadOnlyFileIdentity,
}

#[cfg(target_os = "linux")]
impl ExternalGrokReadOnlyFileCapability {
    fn new(path: PathBuf, held_file: Arc<File>) -> std::io::Result<Self> {
        verify_external_grok_file_descriptor_is_read_only(&held_file)?;
        let identity = external_grok_read_only_file_identity(&held_file.metadata()?)?;
        let capability = Self {
            path,
            held_file,
            identity,
        };
        capability.verify_path()?;
        Ok(capability)
    }

    fn with_resolved_path(&self, path: PathBuf) -> Self {
        Self {
            path,
            held_file: Arc::clone(&self.held_file),
            identity: self.identity,
        }
    }

    fn verify_path(&self) -> std::io::Result<()> {
        verify_external_grok_file_descriptor_is_read_only(&self.held_file)?;
        let held_identity = external_grok_read_only_file_identity(&self.held_file.metadata()?)?;
        let observed_identity =
            external_grok_read_only_file_identity(&fs::symlink_metadata(&self.path)?)?;
        if held_identity != self.identity || observed_identity != self.identity {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "ExternalGrok read-only file capability identity changed: {}",
                    self.path.display()
                ),
            ));
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
impl fmt::Debug for ExternalGrokReadOnlyFileCapability {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExternalGrokReadOnlyFileCapability")
            .field("path", &self.path)
            .field("identity", &self.identity)
            .finish_non_exhaustive()
    }
}

#[cfg(target_os = "linux")]
impl PartialEq for ExternalGrokReadOnlyFileCapability {
    fn eq(&self, other: &Self) -> bool {
        self.path == other.path && self.identity == other.identity
    }
}

#[cfg(target_os = "linux")]
impl Eq for ExternalGrokReadOnlyFileCapability {}

#[cfg(target_os = "linux")]
fn verify_external_grok_file_descriptor_is_read_only(file: &File) -> std::io::Result<()> {
    use std::os::unix::io::AsRawFd;

    // SAFETY: F_GETFL only reads status flags from this live descriptor.
    let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
    if flags < 0 {
        return Err(std::io::Error::last_os_error());
    }
    if flags & libc::O_ACCMODE != libc::O_RDONLY {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "ExternalGrok read-only file capability requires a read-only held descriptor",
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ExternalGrokReadOnlyFileIdentity {
    device: u64,
    inode: u64,
    owner: u32,
    mode: u32,
    links: u64,
}

#[cfg(target_os = "linux")]
fn external_grok_read_only_file_identity(
    metadata: &fs::Metadata,
) -> std::io::Result<ExternalGrokReadOnlyFileIdentity> {
    use std::os::unix::fs::MetadataExt;

    if !metadata.file_type().is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "ExternalGrok read-only file capability is not a regular file",
        ));
    }
    Ok(ExternalGrokReadOnlyFileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        owner: metadata.uid(),
        mode: metadata.mode(),
        links: metadata.nlink(),
    })
}

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
    #[cfg(target_os = "linux")]
    external_grok_read_only_file_capabilities: Vec<ExternalGrokReadOnlyFileCapability>,
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
            #[cfg(target_os = "linux")]
            external_grok_read_only_file_capabilities: Vec::new(),
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

    #[cfg(target_os = "linux")]
    fn with_external_grok_read_only_file_capability(
        mut self,
        file: impl Into<PathBuf>,
        held_file: Arc<File>,
    ) -> std::io::Result<Self> {
        let path = file.into();
        let capability = ExternalGrokReadOnlyFileCapability::new(path.clone(), held_file)?;
        self.visible_read_only_files.push(path);
        self.external_grok_read_only_file_capabilities
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

    pub fn with_visible_read_write_root(mut self, root: impl Into<PathBuf>) -> Self {
        self.config = self.config.with_visible_read_write_root(root);
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
    pub(crate) fn visible_read_write_roots(&self) -> &[PathBuf] {
        &self.config.visible_read_write_roots
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
    pub(crate) fn workspace_access(&self) -> WorkspaceAccess {
        self.config.workspace_access
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
    pub(crate) fn visible_read_write_roots(&self) -> &[PathBuf] {
        &self.config.visible_read_write_roots
    }

    #[cfg(test)]
    pub(crate) fn visible_read_write_files(&self) -> &[PathBuf] {
        &self.config.visible_read_write_files
    }
}

/// Outer Linux profile for an admitted Grok runtime. Grok may use local Unix streams while the
/// parent CLI reaches its provider, but it retains namespace and mount restrictions and the exact
/// workspace path boundary enforced for external-agent launches.
///
/// This is an opaque capability. External callers cannot construct one directly; the crate's
/// validated Grok launch path is the only authority that may create it.
///
/// ```compile_fail
/// use multi_agent_coding_orchestrator::process_runner::ExternalGrokProfile;
/// let _profile = ExternalGrokProfile::read_write(".");
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalGrokProfile {
    config: WorkspaceSandboxConfig,
}

impl ExternalGrokProfile {
    pub(crate) fn read_only(workspace_root: impl Into<PathBuf>) -> Self {
        Self {
            config: WorkspaceSandboxConfig::new(workspace_root, WorkspaceAccess::ReadOnly),
        }
    }

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

    #[cfg(target_os = "linux")]
    pub(crate) fn with_visible_read_only_file_capability(
        mut self,
        file: impl Into<PathBuf>,
        held_file: Arc<File>,
    ) -> std::io::Result<Self> {
        self.config = self
            .config
            .with_external_grok_read_only_file_capability(file, held_file)?;
        Ok(self)
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
    pub(crate) fn workspace_access(&self) -> WorkspaceAccess {
        self.config.workspace_access
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
    ExternalGrok(ExternalGrokProfile),
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
            Self::ExternalGrok(_) => SideEffectConfinementProfileKind::ExternalGrok,
            Self::TrustedCompatibility => SideEffectConfinementProfileKind::TrustedCompatibility,
        }
    }

    fn workspace_config(&self) -> Option<&WorkspaceSandboxConfig> {
        match self {
            Self::StrictOfflineWorkspace(profile) => Some(&profile.config),
            Self::TrustedFixedNetwork(profile) => Some(&profile.config),
            Self::ExternalCodex(profile) => Some(&profile.config),
            Self::ExternalGrok(profile) => Some(&profile.config),
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
    /// Optional nested-worker usage journal harvested after the child returns. When set, the
    /// runner stamps [`MACO_NESTED_USAGE_JOURNAL_ENV`] and [`MACO_PARENT_SPAN_ID_ENV`] so a nested
    /// Fake or CLI worker can emit role-tagged usage across the process boundary.
    pub nested_usage: Option<NestedUsageRequest>,
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
            nested_usage: None,
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
            nested_usage: None,
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

    /// Observe nested-worker usage through a parent-owned journal after the child returns.
    pub fn with_nested_usage(mut self, request: NestedUsageRequest) -> Self {
        stamp_nested_usage_environment(&mut self.environment, &request);
        self.nested_usage = Some(request);
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

impl ProcessRunError {
    /// Typed pre-spawn failure when Required Linux containment cannot find a
    /// delegated systemd user manager.
    ///
    /// GitHub-hosted runners typically land in
    /// `/system.slice/hosted-compute-agent.service`. Callers that can honestly
    /// continue under [`ContainmentPolicy::TrustedBestEffort`] should branch on
    /// this instead of skipping the requested body.
    pub fn is_missing_delegated_user_manager(&self) -> bool {
        missing_delegated_user_manager_failure(self).is_some()
    }
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
    if let Some(request) = &spec.nested_usage {
        stamp_nested_usage_environment(&mut spec.environment, request);
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
    if let Some(request) = &spec.nested_usage {
        if request.parent_span_id.is_empty()
            || request.parent_span_id.len() > MAX_PROCESS_LABEL_BYTES
            || contains_ascii_control(request.parent_span_id.as_bytes())
        {
            return Err(std::io::Error::new(
                io::ErrorKind::InvalidInput,
                "nested usage parent span is empty or exceeds its safety bound",
            ));
        }
        validate_bounded_path(&request.journal_path, "nested usage journal path")?;
        if !request.journal_path.is_absolute() {
            return Err(std::io::Error::new(
                io::ErrorKind::InvalidInput,
                "nested usage journal path must be absolute",
            ));
        }
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
        if config.external_grok_read_only_file_capabilities.len() > MAX_SANDBOX_PATHS_PER_CLASS {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "ExternalGrok read-only file capabilities exceed their vector limit",
            ));
        }
        let mut grok_capability_paths = BTreeSet::new();
        for capability in &config.external_grok_read_only_file_capabilities {
            validate_bounded_path(&capability.path, "ExternalGrok read-only file capability")?;
            if !config.visible_read_only_files.contains(&capability.path)
                || !grok_capability_paths.insert(&capability.path)
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "ExternalGrok read-only file capability is duplicate or lacks an exact read-only file",
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
        source
            .get_ref()
            .and_then(|source| source.downcast_ref::<EnvironmentFailureSource>())
            .map(|source| (source.failure.clone(), source.target_process_started))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = source;
        None
    }
}

#[cfg(test)]
pub(crate) fn is_verified_backend_unavailable(error: &ProcessRunError) -> bool {
    if missing_delegated_user_manager_failure(error).is_some() {
        return true;
    }
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

fn missing_delegated_user_manager_failure(error: &ProcessRunError) -> Option<&EnvironmentFailure> {
    match error {
        ProcessRunError::EnvironmentFailure {
            failure,
            target_process_started: false,
            ..
        } if failure.category
            == crate::external_agent::EnvironmentFailureCategory::SandboxUnavailable
            && failure
                .summary
                .contains("is not inside a delegated systemd user manager") =>
        {
            Some(failure)
        }
        _ => None,
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

include!("process_runner/part2.rs");
include!("process_runner/part3.rs");

#[cfg(all(test, target_os = "linux"))]
pub(crate) fn external_codex_systemd_properties_for_test(
    profile: ExternalCodexProfile,
    program: &Path,
    current_dir: &Path,
) -> io::Result<Vec<String>> {
    let spec = ProcessSpec::direct(
        "external Codex systemd profile projection",
        program,
        std::iter::empty::<OsString>(),
        current_dir,
        8 * 1024,
    )
    .with_side_effect_confinement(SideEffectConfinementProfile::ExternalCodex(profile));
    let sandbox = resolve_systemd_sandbox(&spec)?.ok_or_else(|| {
        io::Error::other("external Codex test profile did not resolve a systemd sandbox")
    })?;
    let mut command = Command::new("systemd-run");
    apply_systemd_sandbox_properties(&mut command, &sandbox);
    Ok(command
        .get_args()
        .map(|argument| argument.to_string_lossy().into_owned())
        .collect())
}

#[cfg(all(test, target_os = "linux"))]
pub(crate) fn external_grok_systemd_properties_for_test(
    profile: ExternalGrokProfile,
    program: &Path,
    current_dir: &Path,
) -> io::Result<Vec<String>> {
    let spec = ProcessSpec::direct(
        "external Grok systemd profile projection",
        program,
        std::iter::empty::<OsString>(),
        current_dir,
        8 * 1024,
    )
    .with_side_effect_confinement(SideEffectConfinementProfile::ExternalGrok(profile));
    let sandbox = resolve_systemd_sandbox(&spec)?.ok_or_else(|| {
        io::Error::other("external Grok test profile did not resolve a systemd sandbox")
    })?;
    let mut command = Command::new("systemd-run");
    apply_systemd_sandbox_properties(&mut command, &sandbox);
    Ok(command
        .get_args()
        .map(|argument| argument.to_string_lossy().into_owned())
        .collect())
}

#[cfg(test)]
mod tests;
