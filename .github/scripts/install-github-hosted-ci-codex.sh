#!/usr/bin/env bash
# GitHub-hosted Ubuntu x86_64 only: install pinned official Codex CLI at /usr/bin/codex
# for Linux CI sandbox integration tests. Do not run on developer or self-hosted hosts.
set -euo pipefail

if [[ "$#" -ne 0 ]]; then
  printf '%s\n' "usage: $0" >&2
  exit 1
fi

# Provenance: openai/codex release rust-v0.144.4 (native musl binary, not npm).
readonly CODEX_VERSION=0.144.4
readonly RELEASE_TAG=rust-v0.144.4
readonly DOWNLOAD_URL="https://github.com/openai/codex/releases/download/${RELEASE_TAG}/codex-x86_64-unknown-linux-musl.tar.gz"
readonly EXPECTED_SHA256=37c985be9d89e8c4f43b3aa0594c1213eac212d30ae2b95221f08fec807515d1
readonly EXPECTED_BYTES=109377995
readonly ARCHIVE_MEMBER=codex-x86_64-unknown-linux-musl
readonly INSTALL_BIN_DIR=/usr/bin
readonly INSTALL_PATH=/usr/bin/codex
readonly VALIDATE_PY=scripts/install_github_hosted_ci_codex_validate.py

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/../.." && pwd)"
# shellcheck source=install-github-hosted-ci-codex.lib.sh
source "${SCRIPT_DIR}/install-github-hosted-ci-codex.lib.sh"
die() { install_github_hosted_ci_codex_die "$@"; }

os_release_id() {
  awk -F= '$1=="ID" { gsub(/"/, "", $2); print $2; exit }' /etc/os-release
}

cleanup_scratch() {
  rm -f -- "${archive}" "${extracted}"
  rmdir -- "${staging}" 2>/dev/null || true
  rmdir -- "${scratch}" 2>/dev/null || true
}

ensure_authenticated_archive() {
  if [[ -f "${archive}" ]]; then
    [[ "$(stat -c '%s' "${archive}")" == "${EXPECTED_BYTES}" ]] || \
      die "refusing: cached archive size does not match pinned release asset"
    printf '%s  %s\n' "${EXPECTED_SHA256}" "${archive}" | sha256sum -c --status || \
      die "refusing: cached archive SHA256 does not match pinned release asset"
    return 0
  fi
  curl -fsSL --proto '=https' --tlsv1.2 -o "${archive}" "${DOWNLOAD_URL}"
  [[ "$(stat -c '%s' "${archive}")" == "${EXPECTED_BYTES}" ]] || \
    die "refusing: downloaded archive size does not match pinned release asset"
  printf '%s  %s\n' "${EXPECTED_SHA256}" "${archive}" | sha256sum -c --status || \
    die "refusing: downloaded archive SHA256 does not match pinned release asset"
}

extract_authenticated_member() {
  python3 "${REPO_ROOT}/${VALIDATE_PY}" validate-tar "${archive}" "${ARCHIVE_MEMBER}"
  tar -xzf "${archive}" -C "${staging}" --no-same-owner --no-same-permissions -- \
    "${ARCHIVE_MEMBER}"
  [[ -f "${extracted}" && ! -L "${extracted}" ]] || \
    die "refusing: extracted member is not a regular file"
  [[ "$(realpath -e "${extracted}")" == "${extracted}" ]] || \
    die "refusing: extracted member path escaped staging"
  install_github_hosted_ci_codex_sha256_file "${extracted}"
}

[[ "${GITHUB_ACTIONS:-}" == true ]] || \
  die "refusing: GITHUB_ACTIONS is not true"
[[ "${RUNNER_ENVIRONMENT:-}" == github-hosted ]] || \
  die "refusing: RUNNER_ENVIRONMENT is not github-hosted; self-hosted is unsupported"
[[ "$(uname -s)" == Linux ]] || die "refusing: host is not Linux"
[[ "$(uname -m)" == x86_64 ]] || die "refusing: host is not x86_64"
[[ -r /etc/os-release ]] || die "refusing: /etc/os-release is unreadable"
[[ "$(os_release_id)" == ubuntu ]] || die "refusing: host is not Ubuntu"

[[ -n "${RUNNER_TEMP:-}" && -d "${RUNNER_TEMP}" ]] || \
  die "refusing: RUNNER_TEMP is not a usable directory"

scratch="$(mktemp -d "${RUNNER_TEMP}/maco-ci-codex.XXXXXX")"
archive="${scratch}/codex-x86_64-unknown-linux-musl.tar.gz"
staging="${scratch}/staging"
extracted="${staging}/${ARCHIVE_MEMBER}"
trap cleanup_scratch EXIT
mkdir -- "${staging}"

install_github_hosted_ci_codex_verify_install_bin_dir
ensure_authenticated_archive
source_digest="$(extract_authenticated_member)"

if [[ -e "${INSTALL_PATH}" || -L "${INSTALL_PATH}" ]]; then
  install_github_hosted_ci_codex_refuse_destination_symlink
  destination_state="$(
    install_github_hosted_ci_codex_destination_digest_state "${source_digest}"
  )"
  if [[ "${destination_state}" == present ]]; then
    install_github_hosted_ci_codex_verify_install_path_metadata
    install_github_hosted_ci_codex_verify_installed_version
    printf 'already installed verified %s at %s\n' "${CODEX_VERSION}" "${INSTALL_PATH}"
    exit 0
  fi
fi

sudo -n install -m 0755 -o root -g root -- "${extracted}" "${INSTALL_PATH}"

install_github_hosted_ci_codex_verify_install_path_metadata
install_github_hosted_ci_codex_verify_digest_matches "${INSTALL_PATH}" "${source_digest}"
install_github_hosted_ci_codex_verify_installed_version

printf 'installed verified %s at %s\n' "${CODEX_VERSION}" "${INSTALL_PATH}"
