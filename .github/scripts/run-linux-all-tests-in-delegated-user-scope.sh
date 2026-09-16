#!/usr/bin/env bash
# Run the Linux CI test command inside a delegated systemd user scope.
# Confined to the ephemeral GitHub-hosted runner; do not use on developer hosts.
set -euo pipefail

if [[ "$#" -eq 0 ]]; then
  printf '%s\n' "usage: $0 <command> [args...]" >&2
  exit 1
fi

script_dir="$(cd "$(dirname -- "$0")" && pwd)"
script_path="${script_dir}/$(basename -- "$0")"

uid="$(id -u)"
user_name="$(id -un)"
runtime_dir="/run/user/${uid}"

read_readonly_sysctl() {
  local key="$1"
  local value=""
  value="$(sysctl -n "${key}" 2>/dev/null || true)"
  if [[ -z "${value}" ]]; then
    printf 'unknown'
  else
    printf '%s' "${value}"
  fi
}

capture_probe_sysctls() {
  local key
  for key in \
    kernel.unprivileged_userns_clone \
    user.max_user_namespaces \
    kernel.apparmor_restrict_unprivileged_userns
  do
    printf 'maco-ci-inner-probe sysctl %s=%s\n' "${key}" "$(read_readonly_sysctl "${key}")"
  done
}

capture_probe_apparmor_denied() {
  local unit="$1"
  local pid=""
  local start_ts=""
  local end_ts=""
  local invocation=""
  local start_epoch=""
  local end_epoch=""
  local denied_output=""
  pid="$(systemctl --user show "${unit}" -p ExecMainPID --value 2>/dev/null || true)"
  start_ts="$(systemctl --user --timestamp=us show "${unit}" -p ExecMainStartTimestamp --value 2>/dev/null || true)"
  end_ts="$(systemctl --user --timestamp=us show "${unit}" -p ExecMainExitTimestamp --value 2>/dev/null || true)"
  invocation="$(systemctl --user show "${unit}" -p InvocationID --value 2>/dev/null || true)"
  printf 'maco-ci-inner-probe ExecMainPID=%s\n' "${pid}"
  printf 'maco-ci-inner-probe ExecMainStartTimestamp=%s\n' "${start_ts}"
  printf 'maco-ci-inner-probe ExecMainExitTimestamp=%s\n' "${end_ts}"
  printf 'maco-ci-inner-probe InvocationID=%s\n' "${invocation}"
  if [[ ! "${pid}" =~ ^[1-9][0-9]*$ ]]; then
    printf 'maco-ci-inner-probe apparmor denied mapping unavailable: ExecMainPID not a positive numeric PID\n'
    return 0
  fi
  case "${start_ts}" in
    ''|n/a|N/A|-)
      printf 'maco-ci-inner-probe apparmor denied mapping unavailable: execution interval not recorded\n'
      return 0
      ;;
  esac
  case "${end_ts}" in
    ''|n/a|N/A|-)
      printf 'maco-ci-inner-probe apparmor denied mapping unavailable: execution interval not recorded\n'
      return 0
      ;;
  esac
  start_epoch="$(date -u -d "${start_ts}" +%s%6N 2>/dev/null || true)"
  end_epoch="$(date -u -d "${end_ts}" +%s%6N 2>/dev/null || true)"
  if [[ -z "${start_epoch}" || -z "${end_epoch}" ]]; then
    printf 'maco-ci-inner-probe apparmor denied mapping unavailable: timestamps not parseable\n'
    return 0
  fi
  if [[ "${start_epoch}" -gt "${end_epoch}" ]]; then
    printf 'maco-ci-inner-probe apparmor denied mapping unavailable: execution interval not bounded\n'
    return 0
  fi
  printf 'maco-ci-inner-probe apparmor denied pid=%s since=%s until=%s\n' \
    "${pid}" "${start_ts}" "${end_ts}"
  if ! denied_output="$(sudo -n journalctl --no-pager --quiet -o short-iso -n 80 \
      -k --since="${start_ts}" --until="${end_ts}" \
      -g 'apparmor="DENIED"' 2>&1)"; then
    printf 'maco-ci-inner-probe apparmor denied unavailable for pid=%s\n' "${pid}"
    return 0
  fi
  denied_output="$(printf '%s\n' "${denied_output}" | grep -E "(^|[[:space:]])pid=${pid}([[:space:]]|$)" || true)"
  if [[ -z "${denied_output}" ]]; then
    printf 'maco-ci-inner-probe apparmor denied unavailable: no matching records\n'
  else
    printf '%s\n' "${denied_output}" | head -c 4096 || true
    printf '\n'
  fi
}

capture_probe_unit_journal() {
  local unit="$1"
  local probe_uid
  local journal_output=""
  probe_uid="$(id -u)"
  printf 'maco-ci-inner-probe journal unit=%s uid=%s\n' "${unit}" "${probe_uid}"
  # Include executor and user-manager records for this exact probe only.
  # Extra invocation matches can exclude the manager's startup error.
  if ! journal_output="$(sudo -n journalctl --no-pager --quiet -o short-iso -n 80 \
      "_UID=${probe_uid}" "_SYSTEMD_USER_UNIT=${unit}" + \
      "_UID=${probe_uid}" "USER_UNIT=${unit}" 2>&1)"; then
    printf 'maco-ci-inner-probe journal unavailable for unit=%s uid=%s\n' "${unit}" "${probe_uid}"
    return 0
  fi
  if [[ -z "${journal_output}" ]]; then
    printf 'maco-ci-inner-probe journal unavailable: no matching records\n'
  else
    printf '%s\n' "${journal_output}" | head -c 4096 || true
    printf '\n'
  fi
}

run_inner_transient_probe() {
  local unit="maco-ci-inner-probe-$$.service"
  local true_bin=""
  local status=0
  local controllers=""
  local load_state=""
  printf 'maco-ci-inner-probe unit=%s uid=%s\n' "${unit}" "$(id -u)"
  printf 'maco-ci-inner-probe cgroup=%s\n' "$(sed -n 's/^0:://p' /proc/self/cgroup)"
  controllers="$(tr '\n' ' ' <"/sys/fs/cgroup/user.slice/user-$(id -u).slice/user@$(id -u).service/cgroup.controllers" 2>/dev/null || true)"
  printf 'maco-ci-inner-probe user-manager-cgroup.controllers=%s\n' "${controllers}"
  if [[ -x /usr/bin/true ]]; then
    true_bin=/usr/bin/true
  elif [[ -x /bin/true ]]; then
    true_bin=/bin/true
  else
    printf 'maco-ci-inner-probe missing /usr/bin/true\n' >&2
    return 1
  fi
  set +e
  systemd-run --user --pipe --wait --service-type=exec --slice=app.slice \
    --unit="${unit}" \
    --working-directory=/ \
    --expand-environment=no \
    --property=KillMode=control-group \
    --property=KillSignal=SIGKILL \
    --property=FinalKillSignal=SIGKILL \
    --property=ProtectControlGroups=yes \
    --property=TimeoutStopSec=100ms \
    --property=RuntimeDirectoryPreserve=no \
    --property=RuntimeDirectoryMode=0700 \
    --property=ProtectSystem=strict \
    --property=ProtectHome=tmpfs \
    --property=NoNewPrivileges=yes \
    --property=RestrictSUIDSGID=yes \
    --property=LockPersonality=yes \
    --property=PrivateTmp=yes \
    --property=PrivateDevices=yes \
    --property=PrivateUsers=yes \
    --property=PrivateIPC=yes \
    --property=ProtectKernelTunables=yes \
    --property=ProtectKernelModules=yes \
    --property=ProtectKernelLogs=yes \
    --property=ProtectClock=yes \
    --property=ProtectProc=invisible \
    --property=ProcSubset=pid \
    --property=SystemCallArchitectures=native \
    --property=SystemCallErrorNumber=EPERM \
    --property=RestrictRealtime=yes \
    --property=KeyringMode=private \
    --property=UMask=0077 \
    --property=MemorySwapMax=0 \
    --property=LimitCORE=0 \
    --property=OOMPolicy=kill \
    --property=RestrictNamespaces=yes \
    --property=PrivateNetwork=yes \
    --property=RestrictAddressFamilies=AF_UNIX \
    '--property=SystemCallFilter=~@clock @debug @module @mount @obsolete @raw-io @reboot @swap bpf fanotify_init fanotify_mark ipc mq_getsetattr mq_notify mq_open mq_timedreceive mq_timedreceive_time64 mq_timedsend mq_timedsend_time64 mq_unlink msgctl msgget msgrcv msgsnd open_by_handle_at process_madvise process_vm_readv process_vm_writev quotactl quotactl_fd semctl semget semop semtimedop semtimedop_time64 shmat shmctl shmdt shmget link linkat mknod mknodat socket socketpair socketcall' \
    --property=MemoryMax=4294967296 \
    --property=TasksMax=256 \
    --property=CPUQuota=400% \
    --property=LimitNOFILE=8192 \
    --property=LimitFSIZE=2147483648 \
    -- "${true_bin}" >"/tmp/${unit}.out" 2>"/tmp/${unit}.err"
  status=$?
  set -e
  printf 'maco-ci-inner-probe systemd-run-exit=%s\n' "${status}"
  printf 'maco-ci-inner-probe stdout-bytes=%s stderr-bytes=%s\n' \
    "$(wc -c <"/tmp/${unit}.out" | tr -d ' ')" \
    "$(wc -c <"/tmp/${unit}.err" | tr -d ' ')"
  printf 'maco-ci-inner-probe stdout-head=\n'
  head -c 4096 "/tmp/${unit}.out" || true
  printf '\nmaco-ci-inner-probe stderr-head=\n'
  head -c 4096 "/tmp/${unit}.err" || true
  load_state="$(systemctl --user show "${unit}" -p LoadState --value 2>/dev/null || true)"
  printf '\nmaco-ci-inner-probe LoadState=%s\n' "${load_state}"
  if [[ "${load_state}" == loaded ]]; then
    systemctl --user show "${unit}" \
      -p Id -p LoadState -p ActiveState -p SubState -p Result -p ExecMainStatus -p ExecMainCode \
      -p ExecMainPID -p ExecMainStartTimestamp -p ExecMainExitTimestamp -p InvocationID \
      -p StatusErrno -p StatusText -p NoNewPrivileges -p PrivateDevices -p PrivateUsers \
      -p ProtectControlGroups -p CapabilityBoundingSet -p AmbientCapabilities \
      -p RestrictNamespaces -p ProtectSystem -p PrivateTmp || true
  else
    printf 'maco-ci-inner-probe unit properties unavailable after collection\n'
  fi
  if command -v systemd-analyze >/dev/null && [[ "${status}" -ne 0 ]]; then
    printf 'maco-ci-inner-probe systemd-analyze-exit-status=\n'
    systemd-analyze exit-status "${status}" || true
  fi
  if [[ "${status}" -ne 0 ]]; then
    capture_probe_unit_journal "${unit}"
    capture_probe_sysctls
    if [[ "${load_state}" == loaded ]]; then
      capture_probe_apparmor_denied "${unit}"
    fi
  fi
  systemctl --user stop "${unit}" >/dev/null 2>&1 || true
  systemctl --user reset-failed "${unit}" >/dev/null 2>&1 || true
  rm -f "/tmp/${unit}.out" "/tmp/${unit}.err"
  return "${status}"
}

if [[ "${1:-}" == "--inside-scope" ]]; then
  shift
  if [[ "$#" -eq 0 ]]; then
    printf '%s\n' "usage: $0 --inside-scope <command> [args...]" >&2
    exit 1
  fi
  cgroup="$(sed -n 's/^0:://p' /proc/self/cgroup)"
  case "${cgroup}" in
    *user@[0-9]*.service*) ;;
    *)
      printf "CI cargo test is not inside a delegated systemd user manager: %s\n" "${cgroup}" >&2
      exit 1
      ;;
  esac
  run_inner_transient_probe
  exec "$@"
fi

if ! systemctl is-active --quiet "user@${uid}.service"; then
  sudo loginctl enable-linger "${user_name}"
  sudo systemctl start "user@${uid}.service"
fi

export XDG_RUNTIME_DIR="${runtime_dir}"
if [[ -S "${XDG_RUNTIME_DIR}/bus" ]]; then
  export DBUS_SESSION_BUS_ADDRESS="unix:path=${XDG_RUNTIME_DIR}/bus"
fi

exec systemd-run --user --scope --quiet -p Delegate=yes --working-directory="${PWD}" -- \
  bash "${script_path}" --inside-scope "$@"
