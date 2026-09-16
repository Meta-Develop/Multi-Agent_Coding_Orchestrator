import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
HELPER = ROOT / ".github" / "scripts" / "install-github-hosted-ci-codex.sh"
LIB = ROOT / ".github" / "scripts" / "install-github-hosted-ci-codex.lib.sh"
WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"

PINNED_SHA256 = (
    "37c985be9d89e8c4f43b3aa0594c1213eac212d30ae2b95221f08fec807515d1"
)
ARCHIVE_MEMBER = "codex-x86_64-unknown-linux-musl"


class InstallGithubHostedCiCodexGuardTests(unittest.TestCase):
    def setUp(self) -> None:
        self.assertTrue(HELPER.is_file())
        self.source = HELPER.read_text(encoding="utf-8")

    def _fake_sudo(self, directory: Path) -> Path:
        sudo = directory / "sudo"
        sudo.write_text("#!/bin/sh\necho SUDO_INVOKED >&2\nexit 97\n", encoding="utf-8")
        sudo.chmod(sudo.stat().st_mode | stat.S_IXUSR)
        return sudo

    def _run(self, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["bash", str(HELPER)],
            check=False,
            capture_output=True,
            text=True,
            env=env,
        )

    def test_pinned_provenance_constants(self) -> None:
        self.assertIn(f"readonly EXPECTED_SHA256={PINNED_SHA256}", self.source)
        self.assertIn("readonly RELEASE_TAG=rust-v0.144.4", self.source)
        self.assertIn(
            'DOWNLOAD_URL="https://github.com/openai/codex/releases/download/${RELEASE_TAG}/codex-x86_64-unknown-linux-musl.tar.gz"',
            self.source,
        )
        self.assertIn(f"readonly ARCHIVE_MEMBER={ARCHIVE_MEMBER}", self.source)
        self.assertIn("readonly CODEX_VERSION=0.144.4", self.source)
        lib = LIB.read_text(encoding="utf-8")
        self.assertIn(
            'version_output="$("${INSTALL_PATH}" --version 2>&1 | tr -d \'\\r\')"',
            lib,
        )
        self.assertNotIn("head -n1", lib)
        self.assertIn('rm -f -- "${archive}" "${extracted}"', self.source)
        self.assertNotIn("rm -rf", self.source)
        self.assertIn('[[ -e "${INSTALL_PATH}" || -L "${INSTALL_PATH}" ]]', self.source)
        self.assertIn("readonly EXPECTED_BYTES=109377995", self.source)
        self.assertIn('validate-tar "${archive}" "${ARCHIVE_MEMBER}"', self.source)
        self.assertIn('"${ARCHIVE_MEMBER}"', self.source)
        self.assertNotIn("--wildcards", self.source)
        self.assertNotIn("--strip-components", self.source)

    def test_refuses_without_github_actions_before_sudo(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            self._fake_sudo(tmp_path)
            env = {
                "PATH": f"{tmp_path}{os.pathsep}{os.environ.get('PATH', '/usr/bin:/bin')}",
                "HOME": tmp,
                "RUNNER_TEMP": tmp,
            }
            result = self._run(env)
            combined = result.stdout + result.stderr
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("GITHUB_ACTIONS is not true", result.stderr)
            self.assertNotIn("SUDO_INVOKED", combined)

    def test_self_hosted_runner_refuses_before_download(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            self._fake_sudo(tmp_path)
            env = {
                "PATH": f"{tmp_path}{os.pathsep}{os.environ.get('PATH', '/usr/bin:/bin')}",
                "HOME": tmp,
                "RUNNER_TEMP": tmp,
                "GITHUB_ACTIONS": "true",
                "RUNNER_ENVIRONMENT": "self-hosted",
            }
            result = self._run(env)
            combined = result.stdout + result.stderr
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("self-hosted is unsupported", result.stderr)
            self.assertNotIn("SUDO_INVOKED", combined)

    def _run_lib(self, env: dict[str, str], snippet: str) -> subprocess.CompletedProcess[str]:
        script = f"""
set -euo pipefail
CODEX_VERSION=0.144.4
source "{LIB}"
{snippet}
"""
        return subprocess.run(
            ["bash", "-c", script],
            check=False,
            capture_output=True,
            text=True,
            env=env,
        )

    def test_lib_refuses_dangling_destination_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            destination = Path(tmp) / "codex"
            destination.symlink_to("/missing/codex-target")
            result = self._run_lib(
                {"INSTALL_PATH": str(destination)},
                "install_github_hosted_ci_codex_refuse_destination_symlink",
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("is a symlink", result.stderr)

    def test_lib_refuses_existing_file_with_authenticated_digest_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            destination = Path(tmp) / "codex"
            destination.write_bytes(b"wrong-bytes")
            result = self._run_lib(
                {
                    "INSTALL_PATH": str(destination),
                    "CODEX_VERSION": "0.144.4",
                },
                'install_github_hosted_ci_codex_destination_digest_state "deadbeef"',
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("digest does not match", result.stderr)

    def test_linux_job_invokes_helper_before_cargo_test(self) -> None:
        source = WORKFLOW.read_text(encoding="utf-8")
        install = "bash .github/scripts/install-github-hosted-ci-codex.sh"
        tests = (
            "bash .github/scripts/run-linux-all-tests-in-delegated-user-scope.sh \\\n"
            "            cargo test --locked --all-targets"
        )
        self.assertIn(install, source)
        self.assertIn(tests, source)
        self.assertLess(source.index(install), source.index(tests))
