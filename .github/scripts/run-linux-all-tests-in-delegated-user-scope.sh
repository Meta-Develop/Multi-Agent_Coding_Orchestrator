#!/usr/bin/env bash
# Run the Linux CI test command inside a delegated systemd user scope.
# Confined to the ephemeral GitHub-hosted runner; do not use on developer hosts.
set -euo pipefail

if [[ "$#" -eq 0 ]]; then
  printf '%s\n' "usage: $0 <command> [args...]" >&2
  exit 1
fi

uid="$(id -u)"
user_name="$(id -un)"
runtime_dir="/run/user/${uid}"

if ! systemctl is-active --quiet "user@${uid}.service"; then
  sudo loginctl enable-linger "${user_name}"
  sudo systemctl start "user@${uid}.service"
fi

export XDG_RUNTIME_DIR="${runtime_dir}"
if [[ -S "${XDG_RUNTIME_DIR}/bus" ]]; then
  export DBUS_SESSION_BUS_ADDRESS="unix:path=${XDG_RUNTIME_DIR}/bus"
fi

exec systemd-run --user --scope --quiet -p Delegate=yes --working-directory="${PWD}" -- \
  bash -c '
    set -euo pipefail
    cgroup="$(sed -n "s/^0:://p" /proc/self/cgroup)"
    case "${cgroup}" in
      *user@[0-9]*.service*) ;;
      *)
        printf "CI cargo test is not inside a delegated systemd user manager: %s\n" "${cgroup}" >&2
        exit 1
        ;;
    esac
    exec "$@"
  ' bash "$@"
