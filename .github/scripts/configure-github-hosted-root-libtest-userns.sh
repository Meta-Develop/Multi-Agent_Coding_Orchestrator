#!/usr/bin/env bash
# GitHub-hosted Ubuntu only: ADD a unique maco-ci AppArmor userns profile for
# the source-built root libtest ELF. Do not run on developer or self-hosted hosts.
set -euo pipefail

if [[ "$#" -ne 0 ]]; then
  printf '%s\n' "usage: $0" >&2
  exit 1
fi

readonly PARSER=/usr/sbin/apparmor_parser
readonly ABI_FILE=/etc/apparmor.d/abi/4.0
readonly PROFILE_NAME=maco-ci-github-hosted-root-libtest
readonly PROFILES_FS=/sys/kernel/security/apparmor/profiles
readonly PYTHON=/usr/bin/python3
readonly ROOT_PACKAGE_NAME=multi-agent-coding-orchestrator
readonly ROOT_LIB_TARGET_NAME=multi_agent_coding_orchestrator

die() {
  printf '%s\n' "$*" >&2
  exit 1
}

os_release_id() {
  awk -F= '$1=="ID" { gsub(/"/, "", $2); print $2; exit }' /etc/os-release
}

kernel_profiles() {
  # securityfs may report readable mode bits while still requiring privilege.
  sudo -n cat -- "${PROFILES_FS}"
}

profile_name_loaded() {
  local listing="$1"
  awk -v name="${PROFILE_NAME}" '$1==name { found=1 } END { exit found ? 0 : 1 }' \
    <<<"${listing}"
}

artifact_fingerprint() {
  stat -c 'uid=%u gid=%g mode=%a inode=%i size=%s' -- "$1"
  sha256sum -- "$1"
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

[[ -x "${PYTHON}" && -f "${PYTHON}" ]] || \
  die "refusing: python3 is not available at ${PYTHON}"

if [[ -n "${CARGO_TARGET_DIR+x}" ]]; then
  die "refusing: CARGO_TARGET_DIR override is set; default target/debug/deps is required"
fi

[[ -n "${GITHUB_WORKSPACE:-}" && -d "${GITHUB_WORKSPACE}" ]] || \
  die "refusing: GITHUB_WORKSPACE is not a usable directory"
workspace="$(realpath -e "${GITHUB_WORKSPACE}")"
[[ "${workspace}" == "${GITHUB_WORKSPACE}" ]] || \
  die "refusing: GITHUB_WORKSPACE is not canonical"
root_manifest="${workspace}/Cargo.toml"
[[ -f "${root_manifest}" && ! -L "${root_manifest}" ]] || \
  die "refusing: root manifest is not a regular file at ${root_manifest}"
[[ "$(realpath -e "${root_manifest}")" == "${root_manifest}" ]] || \
  die "refusing: root manifest is not the canonical path"

[[ -n "${RUNNER_TEMP:-}" && -d "${RUNNER_TEMP}" ]] || \
  die "refusing: RUNNER_TEMP is not a usable directory"

cd -- "${workspace}"

metadata_out="$(mktemp "${RUNNER_TEMP}/maco-ci-root-libtest-metadata.XXXXXX")"
metadata_err="$(mktemp "${RUNNER_TEMP}/maco-ci-root-libtest-metadata-err.XXXXXX")"
discover_out="$(mktemp "${RUNNER_TEMP}/maco-ci-root-libtest-discover.XXXXXX")"
discover_err="$(mktemp "${RUNNER_TEMP}/maco-ci-root-libtest-discover-err.XXXXXX")"
remove_cargo_temps() {
  rm -f -- "${metadata_out}" "${metadata_err}" "${discover_out}" "${discover_err}"
}

set +e
cargo +1.94.1 metadata --locked --no-deps --format-version 1 \
  >"${metadata_out}" 2>"${metadata_err}"
metadata_status=$?
set -e
if [[ "${metadata_status}" -ne 0 ]]; then
  cat -- "${metadata_err}" >&2
  remove_cargo_temps
  die "cargo +1.94.1 metadata failed with status ${metadata_status}"
fi
printf 'cargo +1.94.1 metadata status=%s\n' "${metadata_status}"

set +e
cargo +1.94.1 test --locked --lib --no-run --message-format=json \
  -p multi-agent-coding-orchestrator \
  >"${discover_out}" 2>"${discover_err}"
discover_status=$?
set -e
if [[ "${discover_status}" -ne 0 ]]; then
  cat -- "${discover_err}" >&2
  remove_cargo_temps
  die "cargo +1.94.1 test --no-run failed with status ${discover_status}"
fi
printf 'cargo +1.94.1 test --locked --lib --no-run --message-format=json -p %s status=%s\n' \
  "${ROOT_PACKAGE_NAME}" "${discover_status}"

set +e
artifact="$("${PYTHON}" -I -B - "${metadata_out}" "${discover_out}" "${workspace}" \
  "${ROOT_PACKAGE_NAME}" "${ROOT_LIB_TARGET_NAME}" <<'PY'
import json
import pathlib
import re
import sys

metadata_path, discover_path, workspace, package_name, target_name = sys.argv[1:6]
ws = pathlib.Path(workspace)
if not ws.is_absolute():
    raise SystemExit("refusing: workspace is not absolute")
ws = ws.resolve(strict=True)
meta = json.loads(pathlib.Path(metadata_path).read_text(encoding="utf-8"))
meta_ws = pathlib.Path(meta["workspace_root"]).resolve(strict=True)
if meta_ws != ws:
    raise SystemExit(f"refusing: metadata workspace_root is not the owned root repo ({meta_ws})")
manifest = (ws / "Cargo.toml").resolve(strict=True)
if manifest != ws / "Cargo.toml":
    raise SystemExit("refusing: root manifest is not canonical")
root = None
for pkg in meta["packages"]:
    mp = pathlib.Path(pkg["manifest_path"]).resolve(strict=True)
    if mp != manifest:
        continue
    if root is not None:
        raise SystemExit("refusing: multiple packages share the canonical root manifest")
    root = pkg
if root is None:
    raise SystemExit("refusing: canonical root manifest has no metadata package")
if root.get("name") != package_name:
    raise SystemExit(
        f"refusing: root package name is {root.get('name')!r}, expected {package_name!r}"
    )
package_id = root.get("id")
if not isinstance(package_id, str) or not package_id or "\n" in package_id:
    raise SystemExit("refusing: root package id is not a single-line string")
members = meta.get("workspace_members")
if not isinstance(members, list) or package_id not in members:
    raise SystemExit("refusing: root package id is not an exact workspace member")
target_directory = pathlib.Path(meta["target_directory"])
if not target_directory.is_absolute() or target_directory != ws / "target":
    raise SystemExit(
        f"refusing: CARGO_TARGET_DIR override/nondefault path {target_directory}"
    )

matches = []
for raw in pathlib.Path(discover_path).read_text(encoding="utf-8").splitlines():
    if not raw:
        continue
    try:
        msg = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"refusing: cargo json line is not an object: {exc}") from exc
    if not isinstance(msg, dict):
        raise SystemExit("refusing: cargo json line is not an object")
    if msg.get("reason") != "compiler-artifact":
        continue
    profile = msg.get("profile")
    if not isinstance(profile, dict) or profile.get("test") is not True:
        continue
    executable = msg.get("executable")
    if not isinstance(executable, str) or executable == "":
        continue
    target = msg.get("target")
    if not isinstance(target, dict):
        continue
    kind = target.get("kind")
    if not isinstance(kind, list) or "lib" not in kind:
        continue
    if target.get("name") != target_name:
        continue
    if msg.get("package_id") != package_id:
        continue
    matches.append(executable)
if len(matches) != 1:
    raise SystemExit(
        f"refusing: expected exactly one root libtest compiler-artifact, found {len(matches)}"
    )
exe = matches[0]
if not re.fullmatch(r"(?:/[A-Za-z0-9._+-]+)+", exe):
    raise SystemExit("refusing: artifact path is not a single safe AppArmor path token")
print(f"root libtest package_id={package_id}", file=sys.stderr)
print(exe)
PY
)"
parse_status=$?
set -e
if [[ "${parse_status}" -ne 0 || -z "${artifact}" ]]; then
  cat -- "${discover_err}" >&2
  remove_cargo_temps
  die "root libtest compiler-artifact parse failed with status ${parse_status}"
fi
remove_cargo_temps

[[ "${artifact}" == /* ]] || die "refusing: artifact path is not absolute"
[[ -e "${artifact}" ]] || die "refusing: ${artifact} does not exist"
[[ ! -L "${artifact}" ]] || die "refusing: ${artifact} is a symlink"
[[ -f "${artifact}" && -x "${artifact}" ]] || \
  die "refusing: ${artifact} is not a regular executable"
canonical="$(realpath -e "${artifact}")"
[[ "${canonical}" == "${artifact}" ]] || \
  die "refusing: ${artifact} is not the canonical path (${canonical})"

deps_dir="${workspace}/target/debug/deps"
[[ "$(dirname -- "${canonical}")" == "${deps_dir}" ]] || \
  die "refusing: artifact is not under default ${deps_dir}"
cur="${canonical}"
while :; do
  [[ ! -L "${cur}" ]] || die "refusing: ${cur} is a symlink"
  [[ "${cur}" == "${workspace}" ]] && break
  [[ "${cur}" != "/" ]] || die "refusing: ${canonical} is not under ${workspace}"
  cur="$(dirname -- "${cur}")"
done

[[ "$(stat -c '%u' "${canonical}")" == "$(id -u)" ]] || \
  die "refusing: ${canonical} is not owned by the current runner uid"
mode="$(stat -c '%a' "${canonical}")"
(( (8#${mode} & 8#022) == 0 )) || \
  die "refusing: ${canonical} is group- or world-writable"
"${PYTHON}" -I -B -c 'import sys; f=open(sys.argv[1],"rb"); sys.exit(0 if f.read(4)==b"\x7fELF" else 1)' \
  "${canonical}" || die "refusing: ${canonical} is not an ELF"

fingerprint_before="$(artifact_fingerprint "${canonical}")"
printf 'root libtest artifact path=%s\n' "${canonical}"
printf 'root libtest artifact identity before add:\n%s\n' "${fingerprint_before}"

profile_file="$(mktemp "${RUNNER_TEMP}/maco-ci-root-libtest-userns.XXXXXX")"
trap 'rm -f -- "${profile_file}"' EXIT
[[ "$(stat -c '%u %a' "${profile_file}")" == "$(id -u) 600" ]] || \
  die "refusing: profile tempfile is not exclusively owned"

cat >"${profile_file}" <<EOF
abi <abi/4.0>,

profile maco-ci-github-hosted-root-libtest ${canonical} flags=(default_allow) {
  userns,
}
EOF

"${PARSER}" --skip-kernel-load --skip-cache --skip-read-cache -- "${profile_file}"

listing="$(kernel_profiles)"
if profile_name_loaded "${listing}"; then
  die "refusing: kernel already has profile ${PROFILE_NAME}; ADD would conflict"
fi
printf 'AppArmor profile %s loaded_before_add=no\n' "${PROFILE_NAME}"

sudo -n "${PARSER}" --add --skip-cache --skip-read-cache -- "${profile_file}"

listing="$(kernel_profiles)"
profile_name_loaded "${listing}" || \
  die "AppArmor profile ${PROFILE_NAME} was not present after parser add"
printf 'AppArmor profile %s loaded_after_add=yes\n' "${PROFILE_NAME}"

fingerprint_after="$(artifact_fingerprint "${canonical}")"
[[ "${fingerprint_before}" == "${fingerprint_after}" ]] || \
  die "refusing: root libtest artifact changed after profile add"
printf 'root libtest artifact identity after add:\n%s\n' "${fingerprint_after}"

printf 'configured %s userns for %s\n' "${PROFILE_NAME}" "${canonical}"
