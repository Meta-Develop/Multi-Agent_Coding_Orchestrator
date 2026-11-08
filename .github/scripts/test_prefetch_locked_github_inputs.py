#!/usr/bin/env python3
"""Regression coverage for exact locked GitHub source preparation."""

from __future__ import annotations

import contextlib
import copy
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock


spec = importlib.util.spec_from_file_location(
    "prefetch_locked_github_inputs",
    Path(__file__).with_name("prefetch_locked_github_inputs.py"),
)
assert spec is not None and spec.loader is not None
prefetch = importlib.util.module_from_spec(spec)
spec.loader.exec_module(prefetch)

ROOT = Path(__file__).resolve().parents[2]
PIN = {
    "type": "github", "owner": "oxalica", "repo": "rust-overlay",
    "rev": "b6916ba032e02122d6ed3064f40cabe937363d43",
    "narHash": "sha256-sZXy8mzUMi2cOGulhoW4HWAZB6JhXOAx1x8J4auZFWk=",
}
STORE = "/nix/store/afsckw7mm8bl4f96994picw0rgjdn2jf-source"


def locked(pin):
    return json.dumps({"version": 7, "nodes": {"input": {"locked": pin}}}).encode()


class PrefetchLockedGithubInputsChecks(unittest.TestCase):
    def run_prefetch(self, raw, effect):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            lock = root / "flake.lock"
            lock.write_bytes(raw)
            with (
                mock.patch.object(prefetch.subprocess, "run", side_effect=effect) as run,
                contextlib.redirect_stdout(io.StringIO()),
            ):
                try:
                    prefetch.prefetch_locked_inputs(root, "/bin/nix")
                finally:
                    self.assertEqual(lock.read_bytes(), raw)
                    self.assertEqual(list(root.iterdir()), [lock])
            return run

    def success(self, command, **kwargs):
        self.assertEqual(
            command,
            ["/bin/nix", "store", "prefetch-file", "--unpack", "--name", "source",
             "--expected-hash", PIN["narHash"], "--json",
             "https://codeload.github.com/oxalica/rust-overlay/tar.gz/" + PIN["rev"]],
        )
        self.assertEqual(kwargs, {
            "capture_output": True, "text": True, "check": True, "timeout": 300,
        })
        return subprocess.CompletedProcess(command, 0, json.dumps({
            "hash": PIN["narHash"], "storePath": STORE,
        }), "")

    def test_exact_expected_nar_and_official_url_command(self):
        self.run_prefetch(locked(PIN), self.success).assert_called_once()

    def test_repository_lock_and_all_github_pins_work_without_writes_or_overrides(self):
        raw = (ROOT / "flake.lock").read_bytes()
        pins = json.loads(raw)["nodes"]
        expected = {
            f"https://codeload.github.com/{node['locked']['owner']}/"
            f"{node['locked']['repo']}/tar.gz/{node['locked']['rev']}":
            node["locked"]["narHash"]
            for node in pins.values()
            if node.get("locked", {}).get("type") == "github"
        }
        self.assertTrue(expected)

        def success(command, **kwargs):
            self.assertEqual(command[:7], [
                "/bin/nix", "store", "prefetch-file", "--unpack", "--name",
                "source", "--expected-hash",
            ])
            self.assertEqual(command[7:9], [expected[command[-1]], "--json"])
            self.assertEqual(len(command), 10)
            self.assertTrue(kwargs["check"])
            return subprocess.CompletedProcess(command, 0, json.dumps({
                "hash": expected[command[-1]], "storePath": STORE,
            }), "")

        run = self.run_prefetch(raw, success)
        self.assertEqual(run.call_count, len(expected))

    def test_malformed_pins_and_uri_components_fail_before_any_fetch(self):
        cases = [
            ("owner", "https://github.com/oxalica"), ("owner", "a/b"),
            ("owner", "-owner"), ("owner", "a" * 40), ("owner", None),
            ("repo", "../repo"), ("repo", ".."), ("repo", "repo?x"),
            ("repo", "repo#x"), ("repo", "repo%2frepo"), ("repo", "repo;echo"),
            ("repo", "repo\n"), ("repo", ""),
            ("rev", "main"), ("rev", "a" * 39), ("rev", "a" * 41),
            ("rev", "g" * 40), ("rev", PIN["rev"] + "?x"),
            ("narHash", "sha512-" + "A" * 44), ("narHash", "sha256-???"),
            ("narHash", "sha256-YQ=="), ("narHash", PIN["narHash"] + "\n"),
            ("narHash", PIN["narHash"][:-2] + "l="), ("narHash", None),
            ("host", "evil.example"), ("url", "http://evil.example/source"),
            ("dir", "subdirectory"),
        ]
        for key, value in cases:
            with self.subTest(key=key, value=value):
                pin = copy.deepcopy(PIN)
                pin[key] = value
                with self.assertRaises(ValueError):
                    self.run_prefetch(locked(pin), AssertionError("must not fetch"))

    def test_all_pins_validated_before_download(self):
        raw = json.dumps({"version": 7, "nodes": {
            "valid": {"locked": PIN},
            "invalid": {"locked": {**PIN, "rev": "main"}},
        }}).encode()
        with self.assertRaises(ValueError):
            self.run_prefetch(raw, AssertionError("must not fetch"))

    def test_bounded_and_structured_lock_required(self):
        for raw in (
            b" " * (prefetch.MAX_LOCK_BYTES + 1), b"{", b"[]",
            b'{"version": 6, "nodes": {}}', b'{"version": 7, "nodes": []}',
            b'{"version": 7, "nodes": {"bad": null}}',
            b'{"version": 7, "nodes": {"bad": {"locked": "github:owner/repo"}}}',
        ):
            with self.subTest(raw=raw[:80]):
                with self.assertRaises(ValueError):
                    self.run_prefetch(raw, AssertionError("must not fetch"))

    def test_no_relevant_inputs_does_not_invoke_nix(self):
        raw = json.dumps({"version": 7, "nodes": {
            "root": {"inputs": {}},
            "other": {"locked": {"type": "path", "path": "./local"}},
        }}).encode()
        self.run_prefetch(raw, AssertionError("must not fetch")).assert_not_called()

    def test_prefetch_nonzero_including_nar_mismatch_is_fatal(self):
        for stderr in ("network failure", "hash mismatch in file downloaded"):
            failure = subprocess.CalledProcessError(1, ["nix"], stderr=stderr)
            with self.subTest(stderr=stderr):
                with self.assertRaises(subprocess.CalledProcessError):
                    self.run_prefetch(locked(PIN), failure)

    def test_timeout_and_missing_nix_are_fatal(self):
        for failure in (subprocess.TimeoutExpired("nix", 300), FileNotFoundError("nix")):
            with self.subTest(failure=failure):
                with self.assertRaises(type(failure)):
                    self.run_prefetch(locked(PIN), failure)

    def test_unverified_or_malformed_receipts_are_fatal(self):
        for receipt in (
            "not json", "[]", "{}",
            json.dumps({"hash": "sha256-wrong", "storePath": STORE}),
            json.dumps({"hash": PIN["narHash"], "storePath": STORE + ".drv"}),
            json.dumps({"hash": PIN["narHash"], "storePath": "https://evil/source"}),
        ):
            with self.subTest(receipt=receipt):
                response = subprocess.CompletedProcess([], 0, receipt, "")
                with self.assertRaises((RuntimeError, ValueError)):
                    self.run_prefetch(locked(PIN), lambda *args, **kw: response)

    def test_main_reports_failure_and_exits_nonzero(self):
        with (
            mock.patch.object(prefetch, "prefetch_locked_inputs", side_effect=RuntimeError("bad NAR")),
            contextlib.redirect_stderr(io.StringIO()) as stderr,
        ):
            self.assertEqual(prefetch.main(), 1)
        self.assertIn("FAIL: bad NAR", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
