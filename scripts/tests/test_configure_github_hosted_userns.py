import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
HELPER = ROOT / ".github" / "scripts" / "configure-github-hosted-userns.sh"
WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"


class ConfigureGithubHostedUsernsGuardTests(unittest.TestCase):
    def setUp(self) -> None:
        self.assertTrue(HELPER.is_file())

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

    def test_refuses_without_github_actions_before_sudo(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            self._fake_sudo(tmp_path)
            env = {
                "PATH": f"{tmp_path}{os.pathsep}{os.environ.get('PATH', '/usr/bin:/bin')}",
                "HOME": tmp,
            }
            result = self._run(env)
            combined = result.stdout + result.stderr
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("GITHUB_ACTIONS is not true", result.stderr)
            self.assertNotIn("SUDO_INVOKED", combined)

    def test_self_hosted_runner_refuses_before_sudo(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            self._fake_sudo(tmp_path)
            env = {
                "PATH": f"{tmp_path}{os.pathsep}{os.environ.get('PATH', '/usr/bin:/bin')}",
                "HOME": tmp,
                "GITHUB_ACTIONS": "true",
                "RUNNER_ENVIRONMENT": "self-hosted",
            }
            result = self._run(env)
            combined = result.stdout + result.stderr
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("self-hosted is unsupported", result.stderr)
            self.assertNotIn("SUDO_INVOKED", combined)

    def test_linux_job_invokes_helper_before_existing_probe(self) -> None:
        source = WORKFLOW.read_text(encoding="utf-8")
        setup = "bash .github/scripts/configure-github-hosted-userns.sh"
        probe = "bash .github/scripts/run-linux-all-tests-in-delegated-user-scope.sh /usr/bin/true"
        self.assertIn(setup, source)
        self.assertIn(probe, source)
        self.assertLess(source.index(setup), source.index(probe))
