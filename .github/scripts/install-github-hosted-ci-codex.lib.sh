# shellcheck shell=bash
# Shared guards for install-github-hosted-ci-codex.sh (source only).
install_github_hosted_ci_codex_die() {
  printf '%s\n' "$*" >&2
  exit 1
}

install_github_hosted_ci_codex_sha256_file() {
  sha256sum -- "$1" | awk '{ print $1; exit }'
}

install_github_hosted_ci_codex_refuse_path_symlink() {
  local target="$1"
  if [[ -L "${target}" ]]; then
    install_github_hosted_ci_codex_die "refusing: ${target} is a symlink"
  fi
}

install_github_hosted_ci_codex_refuse_destination_symlink() {
  install_github_hosted_ci_codex_refuse_path_symlink "${INSTALL_PATH}"
}

install_github_hosted_ci_codex_verify_install_bin_dir() {
  [[ -d "${INSTALL_BIN_DIR}" ]] || \
    install_github_hosted_ci_codex_die "refusing: ${INSTALL_BIN_DIR} is not a directory"
  [[ ! -L "${INSTALL_BIN_DIR}" ]] || \
    install_github_hosted_ci_codex_die "refusing: ${INSTALL_BIN_DIR} is a symlink"
  local canonical_bin_dir
  canonical_bin_dir="$(realpath -e "${INSTALL_BIN_DIR}")"
  [[ "${canonical_bin_dir}" == "${INSTALL_BIN_DIR}" ]] || \
    install_github_hosted_ci_codex_die \
      "refusing: ${INSTALL_BIN_DIR} is not the canonical path (${canonical_bin_dir})"
  [[ "$(stat -c '%u' "${INSTALL_BIN_DIR}")" == 0 ]] || \
    install_github_hosted_ci_codex_die "refusing: ${INSTALL_BIN_DIR} is not root-owned"
  local bin_mode
  bin_mode="$(stat -c '%a' "${INSTALL_BIN_DIR}")"
  (( (8#${bin_mode} & 8#022) == 0 )) || \
    install_github_hosted_ci_codex_die \
      "refusing: ${INSTALL_BIN_DIR} is group- or world-writable"
}

install_github_hosted_ci_codex_verify_resource_parent_dir() {
  local resource_dir="$1"
  [[ "${resource_dir}" == "${INSTALL_BIN_DIR}/codex-resources" ]] || \
    install_github_hosted_ci_codex_die \
      "refusing: resource parent ${resource_dir} is outside ${INSTALL_BIN_DIR}"
  install_github_hosted_ci_codex_verify_install_bin_dir
  install_github_hosted_ci_codex_refuse_path_symlink "${resource_dir}"
  if [[ -e "${resource_dir}" ]]; then
    [[ -d "${resource_dir}" ]] || \
      install_github_hosted_ci_codex_die \
        "refusing: ${resource_dir} exists but is not a directory"
    local canonical_resource
    canonical_resource="$(realpath -e "${resource_dir}")"
    [[ "${canonical_resource}" == "${resource_dir}" ]] || \
      install_github_hosted_ci_codex_die \
        "refusing: ${resource_dir} is not the canonical path (${canonical_resource})"
    [[ "$(stat -c '%u' "${resource_dir}")" == 0 ]] || \
      install_github_hosted_ci_codex_die "refusing: ${resource_dir} is not root-owned"
    local resource_mode
    resource_mode="$(stat -c '%a' "${resource_dir}")"
    [[ "${resource_mode}" == 755 ]] || \
      install_github_hosted_ci_codex_die \
        "refusing: ${resource_dir} mode is ${resource_mode}, expected 755"
    (( (8#${resource_mode} & 8#022) == 0 )) || \
      install_github_hosted_ci_codex_die \
        "refusing: ${resource_dir} is group- or world-writable"
    return 0
  fi
  sudo -n install -d -m 0755 -o root -g root -- "${resource_dir}"
  install_github_hosted_ci_codex_verify_resource_parent_dir "${resource_dir}"
}

install_github_hosted_ci_codex_verify_install_path_metadata() {
  [[ -e "${INSTALL_PATH}" ]] || \
    install_github_hosted_ci_codex_die "refusing: ${INSTALL_PATH} is missing after install"
  install_github_hosted_ci_codex_refuse_destination_symlink
  [[ -f "${INSTALL_PATH}" && -x "${INSTALL_PATH}" ]] || \
    install_github_hosted_ci_codex_die \
      "refusing: ${INSTALL_PATH} is not a regular executable"
  local canonical
  canonical="$(realpath -e "${INSTALL_PATH}")"
  [[ "${canonical}" == "${INSTALL_PATH}" ]] || \
    install_github_hosted_ci_codex_die \
      "refusing: ${INSTALL_PATH} is not the canonical path (${canonical})"
  [[ "$(stat -c '%u' "${INSTALL_PATH}")" == 0 ]] || \
    install_github_hosted_ci_codex_die "refusing: ${INSTALL_PATH} is not root-owned"
  local mode
  mode="$(stat -c '%a' "${INSTALL_PATH}")"
  [[ "${mode}" == 755 ]] || \
    install_github_hosted_ci_codex_die \
      "refusing: ${INSTALL_PATH} mode is ${mode}, expected 755"
  (( (8#${mode} & 8#022) == 0 )) || \
    install_github_hosted_ci_codex_die \
      "refusing: ${INSTALL_PATH} is group- or world-writable"
}

install_github_hosted_ci_codex_verify_installed_version() {
  local version_output expected
  expected="codex-cli ${CODEX_VERSION}"
  version_output="$("${INSTALL_PATH}" --version 2>&1 | tr -d '\r')"
  [[ "${version_output}" == "${expected}" ]] || \
    install_github_hosted_ci_codex_die \
      "refusing: ${INSTALL_PATH} --version is not exactly ${expected} (${version_output})"
}

install_github_hosted_ci_codex_verify_digest_matches() {
  local label digest
  label="$1"
  digest="$2"
  [[ "$(install_github_hosted_ci_codex_sha256_file "${label}")" == "${digest}" ]] || \
    install_github_hosted_ci_codex_die \
      "refusing: ${label} digest does not match authenticated release binary"
}

install_github_hosted_ci_codex_destination_digest_state() {
  local source_digest="$1"
  install_github_hosted_ci_codex_refuse_destination_symlink
  if [[ ! -e "${INSTALL_PATH}" ]]; then
    printf '%s\n' absent
    return 0
  fi
  if [[ ! -f "${INSTALL_PATH}" ]]; then
    install_github_hosted_ci_codex_die \
      "refusing: ${INSTALL_PATH} exists but is not a regular file"
  fi
  install_github_hosted_ci_codex_verify_digest_matches "${INSTALL_PATH}" "${source_digest}"
  printf '%s\n' present
}

install_github_hosted_ci_codex_install_verified_artifact() {
  local extracted="$1"
  local source_digest="$2"
  local verify_version="$3"

  if [[ -e "${INSTALL_PATH}" || -L "${INSTALL_PATH}" ]]; then
    install_github_hosted_ci_codex_refuse_destination_symlink
    local destination_state
    destination_state="$(
      install_github_hosted_ci_codex_destination_digest_state "${source_digest}"
    )"
    if [[ "${destination_state}" == present ]]; then
      install_github_hosted_ci_codex_verify_install_path_metadata
      if [[ "${verify_version}" == true ]]; then
        install_github_hosted_ci_codex_verify_installed_version
      fi
      return 0
    fi
  fi

  sudo -n install -m 0755 -o root -g root -- "${extracted}" "${INSTALL_PATH}"
  install_github_hosted_ci_codex_verify_install_path_metadata
  install_github_hosted_ci_codex_verify_digest_matches "${INSTALL_PATH}" "${source_digest}"
  if [[ "${verify_version}" == true ]]; then
    install_github_hosted_ci_codex_verify_installed_version
  fi
}
