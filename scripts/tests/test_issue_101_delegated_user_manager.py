from __future__ import annotations

import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

from scripts.run_in_delegated_user_manager import (
    DelegationError,
    current_cgroup_path,
    delegated_user_manager_available,
    main,
    run_command,
)


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "run_in_delegated_user_manager.py"
WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"


class CgroupDetectionTests(unittest.TestCase):
    def test_delegated_user_manager_matches_exact_user_service(self) -> None:
        self.assertTrue(
            delegated_user_manager_available(
                "0::/user.slice/user-1000.slice/user@1000.service/app.slice/test.scope\n"
            )
        )
        self.assertFalse(
            delegated_user_manager_available(
                "0::/system.slice/hosted-compute-agent.service\n"
            )
        )
        self.assertFalse(
            delegated_user_manager_available(
                "0::/system.slice/not-user@1000.service/test.scope\n"
            )
        )
        self.assertFalse(
            delegated_user_manager_available(
                "0::/system.slice/user@1000.service.scope/test.scope\n"
            )
        )
        self.assertFalse(delegated_user_manager_available("1:name=systemd:/\n"))

    def test_current_cgroup_path_reports_missing_unified_entry(self) -> None:
        self.assertEqual(
            current_cgroup_path("1:name=systemd:/\n"),
            "<unified cgroup v2 entry absent>",
        )
        self.assertEqual(
            current_cgroup_path("0::/system.slice/hosted-compute-agent.service\n"),
            "/system.slice/hosted-compute-agent.service",
        )


class FailClosedRunnerTests(unittest.TestCase):
    def test_missing_command_is_usage_error(self) -> None:
        with self.assertRaises(SystemExit) as raised:
            main([])
        self.assertEqual(raised.exception.code, 2)

    def test_probe_failure_is_nonzero_and_mentions_cgroup(self) -> None:
        with mock.patch(
            "scripts.run_in_delegated_user_manager.prepare_environment"
        ), mock.patch(
            "scripts.run_in_delegated_user_manager.delegated_user_manager_available",
            return_value=False,
        ), mock.patch(
            "scripts.run_in_delegated_user_manager.probe_user_manager_cgroup",
            return_value="0::/system.slice/hosted-compute-agent.service\n",
        ):
            with self.assertRaisesRegex(
                DelegationError,
                r"hosted-compute-agent\.service is not inside a delegated systemd user manager",
            ):
                run_command([sys.executable, "-c", "raise SystemExit('should not run')"])

        with mock.patch(
            "scripts.run_in_delegated_user_manager.run_command",
            side_effect=DelegationError(
                "current cgroup /system.slice/hosted-compute-agent.service "
                "is not inside a delegated systemd user manager"
            ),
        ):
            self.assertEqual(
                main(["--", sys.executable, "-c", "raise SystemExit(99)"]),
                1,
            )

    def test_already_delegated_environment_executes_the_command(self) -> None:
        completed = subprocess.run(
            [sys.executable, str(SCRIPT), "--", sys.executable, "-c", "print('delegated-ok')"],
            check=False,
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if not delegated_user_manager_available(Path("/proc/self/cgroup").read_text()):
            self.skipTest("host is not inside a delegated systemd user manager")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout.strip(), "delegated-ok")


class LinuxWorkflowContainmentTests(unittest.TestCase):
    def test_linux_job_runs_tests_inside_the_delegated_runner(self) -> None:
        source = WORKFLOW.read_text(encoding="utf-8")
        active = "\n".join(
            line
            for line in source.splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        )
        self.assertIn(
            "python3 scripts/run_in_delegated_user_manager.py -- \\",
            active,
        )
        self.assertIn("cargo test --locked --all-targets", active)
        self.assertNotIn("CONTAINMENT_DEPENDENT_TESTS", active)
        self.assertNotRegex(active, r"--skip\s")
        self.assertIn("compiles the test suite (--no-run) and does not execute it.", active)


if __name__ == "__main__":
    unittest.main()
