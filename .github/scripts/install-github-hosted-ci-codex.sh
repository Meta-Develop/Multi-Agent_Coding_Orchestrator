#!/usr/bin/env bash
# GitHub-hosted Ubuntu x86_64 only: install pinned official Codex CLI at /usr/bin/codex
# and bundled bubblewrap at /usr/bin/codex-resources/bwrap for Linux CI sandbox tests.
set -euo pipefail

if [[ "$#" -ne 0 ]]; then
  printf '%s\n' "usage: $0" >&2
  exit 1
fi

# Provenance: openai/codex release rust-v0.144.4 (native musl binaries, not npm).
readonly CODEX_VERSION=0.144.4
readonly RELEASE_TAG=rust-v0.144.4
readonly CODEX_DOWNLOAD_URL="https://github.com/openai/codex/releases/download/${RELEASE_TAG}/codex-x86_64-unknown-linux-musl.tar.gz"
readonly CODEX_EXPECTED_SHA256=37c985be9d89e8c4f43b3aa0594c1213eac212d30ae2b95221f08fec807515d1
readonly CODEX_EXPECTED_BYTES=109377995
readonly CODEX_ARCHIVE_MEMBER=codex-x86_64-unknown-linux-musl
readonly BWRAP_DOWNLOAD_URL="https://github.com/openai/codex/releases/download/${RELEASE_TAG}/bwrap-x86_64-unknown-linux-musl.tar.gz"
readonly BWRAP_EXPECTED_SHA256=bf821348773e12a8c10b901759679824d0bb96482c9fcf2cc1eb6f866ec614d7
readonly BWRAP_EXPECTED_BYTES=261563
readonly BWRAP_ARCHIVE_MEMBER=bwrap-x86_64-unknown-linux-musl
readonly INSTALL_BIN_DIR=/usr/bin
readonly CODEX_INSTALL_PATH=/usr/bin/codex
readonly CODEX_RESOURCES_DIR=/usr/bin/codex-resources
readonly BWRAP_INSTALL_PATH=/usr/bin/codex-resources/bwrap
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
  rm -f -- "${codex_archive}" "${bwrap_archive}" \
    "${codex_extracted}" "${bwrap_extracted}"
  rmdir -- "${codex_staging}" "${bwrap_staging}" 2>/dev/null || true
  rmdir -- "${scratch}" 2>/dev/null || true
}

ensure_authenticated_archive() {
  local archive="$1"
  local download_url="$2"
  local expected_bytes="$3"
  local expected_sha256="$4"
  if [[ -f "${archive}" ]]; then
    [[ "$(stat -c '%s' "${archive}")" == "${expected_bytes}" ]] || \
      die "refusing: cached archive size does not match pinned release asset"
    printf '%s  %s\n' "${expected_sha256}" "${archive}" | sha256sum -c --status || \
      die "refusing: cached archive SHA256 does not match pinned release asset"
    return 0
  fi
  curl -fsSL --proto '=https' --tlsv1.2 --retry 5 --retry-delay 2 --retry-all-errors -o "${archive}" "${download_url}"
  [[ "$(stat -c '%s' "${archive}")" == "${expected_bytes}" ]] || \
    die "refusing: downloaded archive size does not match pinned release asset"
  printf '%s  %s\n' "${expected_sha256}" "${archive}" | sha256sum -c --status || \
    die "refusing: downloaded archive SHA256 does not match pinned release asset"
}

extract_authenticated_member() {
  local archive="$1"
  local archive_member="$2"
  local staging="$3"
  local extracted="$4"
  python3 "${REPO_ROOT}/${VALIDATE_PY}" validate-tar "${archive}" "${archive_member}"
  tar -xzf "${archive}" -C "${staging}" --no-same-owner --no-same-permissions -- \
    "${archive_member}"
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
codex_archive="${scratch}/codex-x86_64-unknown-linux-musl.tar.gz"
bwrap_archive="${scratch}/bwrap-x86_64-unknown-linux-musl.tar.gz"
codex_staging="${scratch}/codex-staging"
bwrap_staging="${scratch}/bwrap-staging"
codex_extracted="${codex_staging}/${CODEX_ARCHIVE_MEMBER}"
bwrap_extracted="${bwrap_staging}/${BWRAP_ARCHIVE_MEMBER}"
trap cleanup_scratch EXIT
mkdir -- "${codex_staging}" "${bwrap_staging}"

install_github_hosted_ci_codex_verify_install_bin_dir
ensure_authenticated_archive "${codex_archive}" "${CODEX_DOWNLOAD_URL}" \
  "${CODEX_EXPECTED_BYTES}" "${CODEX_EXPECTED_SHA256}"
ensure_authenticated_archive "${bwrap_archive}" "${BWRAP_DOWNLOAD_URL}" \
  "${BWRAP_EXPECTED_BYTES}" "${BWRAP_EXPECTED_SHA256}"

codex_digest="$(
  extract_authenticated_member "${codex_archive}" "${CODEX_ARCHIVE_MEMBER}" \
    "${codex_staging}" "${codex_extracted}"
)"
bwrap_digest="$(
  extract_authenticated_member "${bwrap_archive}" "${BWRAP_ARCHIVE_MEMBER}" \
    "${bwrap_staging}" "${bwrap_extracted}"
)"

INSTALL_PATH="${CODEX_INSTALL_PATH}"
install_github_hosted_ci_codex_install_verified_artifact \
  "${codex_extracted}" "${codex_digest}" true

install_github_hosted_ci_codex_verify_resource_parent_dir "${CODEX_RESOURCES_DIR}"

INSTALL_PATH="${BWRAP_INSTALL_PATH}"
install_github_hosted_ci_codex_install_verified_artifact \
  "${bwrap_extracted}" "${bwrap_digest}" false

printf 'installed verified %s at %s with bundled bwrap at %s\n' \
  "${CODEX_VERSION}" "${CODEX_INSTALL_PATH}" "${BWRAP_INSTALL_PATH}"
