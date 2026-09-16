#!/usr/bin/env bash
# GitHub-hosted Ubuntu only: ADD a unique maco-ci AppArmor userns profile for
# /usr/lib/systemd/systemd-executor. Do not run on developer or self-hosted hosts.
set -euo pipefail

if [[ "$#" -ne 0 ]]; then
  printf '%s\n' "usage: $0" >&2
  exit 1
fi

readonly EXECUTABLE=/usr/lib/systemd/systemd-executor
readonly PARSER=/usr/sbin/apparmor_parser
readonly ABI_FILE=/etc/apparmor.d/abi/4.0
readonly PROFILE_NAME=maco-ci-github-hosted-systemd-executor
readonly PROFILES_FS=/sys/kernel/security/apparmor/profiles

die() {
  printf '%s\n' "$*" >&2
  exit 1
}

os_release_id() {
  awk -F= '$1=="ID" { gsub(/"/, "", $2); print $2; exit }' /etc/os-release
}

kernel_profiles() {
  if [[ -r "${PROFILES_FS}" ]]; then
    cat -- "${PROFILES_FS}"
  else
    sudo -n cat -- "${PROFILES_FS}"
  fi
}

profile_name_loaded() {
  local listing="$1"
  awk -v name="${PROFILE_NAME}" '$1==name { found=1 } END { exit found ? 0 : 1 }' \
    <<<"${listing}"
}

[[ "${GITHUB_ACTIONS:-}" == true ]] || \
  die "refusing: GITHUB_ACTIONS is not true"
[[ "${RUNNER_ENVIRONMENT:-}" == github-hosted ]] || \
  die "refusing: RUNNER_ENVIRONMENT is not github-hosted; self-hosted is unsupported"
[[ "$(uname -s)" == Linux ]] || die "refusing: host is not Linux"
[[ -r /etc/os-release ]] || die "refusing: /etc/os-release is unreadable"
[[ "$(os_release_id)" == ubuntu ]] || die "refusing: host is not Ubuntu"

[[ -x "${PARSER}" && -f "${PARSER}" && ! -L "${PARSER}" ]] || \
  die "refusing: AppArmor parser is not available at ${PARSER}"
[[ -f "${ABI_FILE}" && ! -L "${ABI_FILE}" ]] || \
  die "refusing: AppArmor abi file is missing at ${ABI_FILE}"

[[ -e "${EXECUTABLE}" ]] || die "refusing: ${EXECUTABLE} does not exist"
[[ ! -L "${EXECUTABLE}" ]] || die "refusing: ${EXECUTABLE} is a symlink"
[[ -f "${EXECUTABLE}" && -x "${EXECUTABLE}" ]] || \
  die "refusing: ${EXECUTABLE} is not a regular executable"
canonical="$(realpath -e "${EXECUTABLE}")"
[[ "${canonical}" == "${EXECUTABLE}" ]] || \
  die "refusing: ${EXECUTABLE} is not the canonical path (${canonical})"
[[ "$(stat -c '%u' "${EXECUTABLE}")" == 0 ]] || \
  die "refusing: ${EXECUTABLE} is not root-owned"
mode="$(stat -c '%a' "${EXECUTABLE}")"
(( (8#${mode} & 8#022) == 0 )) || \
  die "refusing: ${EXECUTABLE} is group- or world-writable"
dpkg_owner="$(dpkg-query -S "${EXECUTABLE}")"
[[ "${dpkg_owner}" == "systemd: ${EXECUTABLE}" ]] || \
  die "refusing: ${EXECUTABLE} is not dpkg-owned by systemd (${dpkg_owner})"

[[ -n "${RUNNER_TEMP:-}" && -d "${RUNNER_TEMP}" ]] || \
  die "refusing: RUNNER_TEMP is not a usable directory"

profile_file="$(mktemp "${RUNNER_TEMP}/maco-ci-userns.XXXXXX")"
trap 'rm -f -- "${profile_file}"' EXIT

cat >"${profile_file}" <<'EOF'
abi <abi/4.0>,

profile maco-ci-github-hosted-systemd-executor /usr/lib/systemd/systemd-executor flags=(default_allow) {
  userns,
}
EOF

"${PARSER}" --skip-kernel-load --skip-cache --skip-read-cache -- "${profile_file}"

listing="$(kernel_profiles)"
if profile_name_loaded "${listing}"; then
  die "refusing: kernel already has profile ${PROFILE_NAME}; ADD would conflict"
fi

sudo -n "${PARSER}" --add --skip-cache --skip-read-cache -- "${profile_file}"

listing="$(kernel_profiles)"
profile_name_loaded "${listing}" || \
  die "AppArmor profile ${PROFILE_NAME} was not present after parser add"

printf 'configured %s userns for %s\n' "${PROFILE_NAME}" "${EXECUTABLE}"
