from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"


class ContainmentSkipListRemovalTests(unittest.TestCase):
    def test_linux_job_runs_plain_cargo_test_without_a_name_list(self) -> None:
        source = WORKFLOW.read_text(encoding="utf-8")
        active = "\n".join(
            line
            for line in source.splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        )

        self.assertIn("cargo test --locked --all-targets", active)
        self.assertNotIn("CONTAINMENT_DEPENDENT_TESTS", active)
        self.assertNotIn("test_harness_args", active)
        self.assertNotIn("--exact --show-output", active)
        self.assertIsNone(
            re.search(r"--skip\s", active),
            "linux CI must not maintain an exact-name --skip list",
        )
        self.assertNotIn("::notice title=Containment test skipped::", active)
        self.assertIn(
            "python3 scripts/run_in_delegated_user_manager.py -- \\",
            active,
        )

    def test_commented_skip_list_is_not_an_active_gate(self) -> None:
        source = """
jobs:
  linux:
    steps:
      - run: |
          # CONTAINMENT_DEPENDENT_TESTS
          # cargo test --locked --lib -- --skip some::test
          cargo test --locked --all-targets
"""
        active = "\n".join(
            line
            for line in source.splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        )
        self.assertNotIn("CONTAINMENT_DEPENDENT_TESTS", active)
        self.assertNotIn("--skip", active)
        self.assertIn("cargo test --locked --all-targets", active)


if __name__ == "__main__":
    unittest.main()
