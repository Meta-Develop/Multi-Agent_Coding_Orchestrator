#!/usr/bin/env python3
"""Regression coverage for package-fileset fixture failure classification."""

from __future__ import annotations

import contextlib
import importlib.util
import io
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock


spec = importlib.util.spec_from_file_location(
    "nix_package_fileset", Path(__file__).with_name("test_nix_package_fileset.py")
)
assert spec is not None and spec.loader is not None
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)


def result(code: int, stdout: str = "", stderr: str = ""):
    return subprocess.CompletedProcess([], code, stdout, stderr)


class PackageFilesetChecks(unittest.TestCase):
    def run_fixture(self, evaluations):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "build.rs").write_text("fn main() {}\n")
            (root / "flake.lock").write_bytes(b"locked\n")
            listing = subprocess.CompletedProcess([], 0, b"build.rs\0flake.lock\0")
            with (
                mock.patch.object(fixture.shutil, "which", return_value="/bin/nix"),
                mock.patch.object(fixture.subprocess, "run", return_value=listing),
                mock.patch.object(fixture, "evaluate", side_effect=evaluations),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                try:
                    fixture.check_fileset(root)
                finally:
                    self.assertEqual((root / "build.rs").read_text(), "fn main() {}\n")
                    self.assertEqual((root / "flake.lock").read_bytes(), b"locked\n")

    def test_positive_then_missing_input_uses_disposable_copy(self):
        def evaluate(_nix, source):
            if (source / "build.rs").exists():
                return result(0, "/nix/store/complete-source.drv")
            return result(1, stderr="error: The path source/build.rs does not exist.")

        self.run_fixture(evaluate)

    def test_missing_nix_is_a_prerequisite_failure(self):
        with mock.patch.object(fixture.shutil, "which", return_value=None):
            with self.assertRaisesRegex(RuntimeError, "Nix is required"):
                fixture.check_fileset(Path("unused"))

    def test_failed_positive_cannot_count_as_expected_negative(self):
        with self.assertRaisesRegex(RuntimeError, "Complete source evaluation failed"):
            self.run_fixture([result(1, stderr="build.rs does not exist")])

    def test_positive_requires_derivation_output(self):
        with self.assertRaisesRegex(RuntimeError, "did not return a derivation"):
            self.run_fixture([result(0)])

    def test_missing_input_must_fail_with_its_own_diagnostic(self):
        for negative in (
            result(0),
            result(1, stderr="cannot connect to daemon"),
            result(1, stderr="flake.lock does not exist"),
            result(1, stderr="cannot download dependency for build.rs"),
            result(-15, stderr="build.rs does not exist"),
        ):
            with self.subTest(negative=negative):
                with self.assertRaises(RuntimeError):
                    self.run_fixture([result(0, "/nix/store/complete.drv"), negative])

    def test_copied_lockfile_mutation_fails(self):
        def evaluate(_nix, source):
            (source / "flake.lock").write_bytes(b"changed\n")
            return result(0, "/nix/store/complete.drv")

        with self.assertRaisesRegex(RuntimeError, "changed flake.lock"):
            self.run_fixture(evaluate)

    def test_evaluation_timeout_is_a_failure(self):
        with self.assertRaises(subprocess.TimeoutExpired):
            self.run_fixture(subprocess.TimeoutExpired("nix", 300))


if __name__ == "__main__":
    unittest.main()
