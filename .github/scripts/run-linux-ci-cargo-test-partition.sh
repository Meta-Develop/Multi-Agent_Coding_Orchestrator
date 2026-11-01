#!/usr/bin/env bash
# Run one Linux CI cargo test partition inside the delegated systemd user scope.
set -euo pipefail

if [[ "$#" -lt 1 || "$#" -gt 2 ]]; then
  printf '%s\n' "usage: $0 lib <shard> | non-lib [merge|other] | doc" >&2
  exit 1
fi

partition="$1"
case "${partition}:${2:-}" in
  lib:autopilot | lib:supervise-core | lib:supervise-bound | lib:supervise-decomposition | lib:supervise-parent | \
  lib:supervise-nested | lib:supervise-fixtures | lib:supervise-fixtures-budget | \
  lib:supervise-fixtures-licensed | lib:supervise-fixtures-runtime | \
  lib:external-agent | lib:worktree | lib:rest | \
  non-lib: | non-lib:merge | non-lib:other | doc:) ;;
  *)
    printf '%s\n' "invalid partition: ${partition}" >&2
    exit 1
    ;;
esac

script_dir="$(cd "$(dirname -- "$0")" && pwd)"
repo_root="$(cd "${script_dir}/../.." && pwd)"
partition_py="${script_dir}/linux_ci_cargo_test_partition.py"
delegated="${script_dir}/run-linux-all-tests-in-delegated-user-scope.sh"

python3 "${partition_py}" verify --manifest-dir "${repo_root}"

partition_argv_output=""
argv_status=0
shard_args=()
if [[ "${partition}" == non-lib && -n "${2:-}" ]]; then
  shard_args=(--shard "$2")
fi
partition_argv_output="$(
  python3 "${partition_py}" argv "${partition}" "${shard_args[@]}" --manifest-dir "${repo_root}"
)" || argv_status=$?
if [[ "${argv_status}" -ne 0 ]]; then
  exit "${argv_status}"
fi

if [[ -z "${partition_argv_output}" ]]; then
  printf '%s\n' "partition produced no cargo test flags: ${partition}" >&2
  exit 1
fi

partition_args=()
while IFS= read -r arg; do
  if [[ -z "${arg}" ]]; then
    printf '%s\n' "partition argv contained an empty line" >&2
    exit 1
  fi
  partition_args+=("${arg}")
done <<< "${partition_argv_output}"

if [[ "${#partition_args[@]}" -eq 0 ]]; then
  printf '%s\n' "partition produced no cargo test flags: ${partition}" >&2
  exit 1
fi

if [[ "${partition}" == lib ]]; then
  exec bash "${delegated}" python3 "${script_dir}/linux_ci_library_shards.py" \
    "$2" --manifest-dir "${repo_root}"
fi

exec bash "${delegated}" cargo test --locked "${partition_args[@]}"
