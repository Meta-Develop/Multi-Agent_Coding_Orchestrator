import importlib.util
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[2]
SCRIPT = ROOT / ".github/scripts/linux_ci_library_shards.py"
WORKFLOW = ROOT / ".github/workflows/ci.yml"
spec = importlib.util.spec_from_file_location("linux_ci_library_shards", SCRIPT)
shards = importlib.util.module_from_spec(spec)
spec.loader.exec_module(shards)

INVENTORY = [
    "autopilot::tests::first",
    "autopilot::tests::first_longer",
    "supervise::tests::first",
    "supervise::tests::ignored",
    "future::autopilot::test",
    "future::tests::supervise_lookalike",
    "supervise_extra::test",
    "new_module::test",
]


def listing(names):
    return "".join(f"{name}: test\n" for name in names)


class LibraryShardTests(unittest.TestCase):
    def test_partition_is_disjoint_complete_stable_and_includes_new_modules(self):
        partitions = shards.partition_inventory(INVENTORY)
        self.assertEqual(partitions, shards.partition_inventory(list(reversed(INVENTORY))))
        self.assertEqual(partitions["autopilot"], sorted(INVENTORY[:2]))
        self.assertEqual(partitions["supervise"], sorted(INVENTORY[2:4]))
        self.assertEqual(partitions["rest"], sorted(INVENTORY[4:]))
        union = []
        for group in partitions.values():
            union.extend(group)
        self.assertCountEqual(union, INVENTORY)
        self.assertEqual(len(union), len(set(union)))

    def test_inventory_refuses_malformed_duplicate_and_empty_inputs(self):
        for output in ["running 12 tests\n", "test: unknown\n", "x: test\nx: test\n"]:
            with self.subTest(output=output), self.assertRaises(ValueError):
                shards.parse_inventory(output)
        for names in [[], ["a", "a"]]:
            with self.assertRaises(ValueError):
                shards.partition_inventory(names)
        with self.assertRaises(ValueError):
            shards.test_command(["harness"], [])

    def test_empty_shard_never_invokes_unfiltered_execution(self):
        with mock.patch.object(shards.subprocess, "run") as run:
            run.return_value = subprocess.CompletedProcess([], 0, "future::test: test\n")
            with self.assertRaises(ValueError):
                shards.run_shard(["harness"], "autopilot")
            self.assertEqual(run.call_count, 1)

    def test_filter_gap_or_overlap_refuses_execution(self):
        for selected in [INVENTORY[:1], INVENTORY[:3]]:
            with self.subTest(selected=selected), mock.patch.object(shards.subprocess, "run") as run:
                run.side_effect = [
                    subprocess.CompletedProcess([], 0, listing(INVENTORY)),
                    subprocess.CompletedProcess([], 0, listing(selected)),
                ]
                with self.assertRaises(ValueError):
                    shards.run_shard(["harness"], "autopilot")
                self.assertEqual(run.call_count, 2)

    def test_enumeration_failure_and_test_failure_cannot_pass(self):
        with mock.patch.object(shards.subprocess, "run") as run:
            run.side_effect = subprocess.CalledProcessError(101, ["cargo"])
            with self.assertRaises(subprocess.CalledProcessError):
                shards.run_shard(["harness"], "rest")
            self.assertEqual(run.call_count, 1)
        with mock.patch.object(shards.subprocess, "run") as run:
            run.side_effect = [
                subprocess.CompletedProcess([], 0, listing(INVENTORY)),
                subprocess.CompletedProcess([], 0, listing(INVENTORY[:2])),
                subprocess.CompletedProcess([], 101),
            ]
            self.assertEqual(shards.run_shard(["harness"], "autopilot"), 101)
            self.assertEqual(
                run.call_args.args[0],
                ["harness", "--exact", "--", *INVENTORY[:2]],
            )

    def test_workflow_matrix_matches_shards_and_preserves_limits_and_gate(self):
        source = WORKFLOW.read_text(encoding="utf-8")
        library = source.split("  linux-library:", 1)[1].split("  linux-integration:", 1)[0]
        matrix = re.search(r"shard: \[([^]]+)\]", library).group(1)
        self.assertEqual(tuple(item.strip() for item in matrix.split(",")), shards.SHARDS)
        self.assertIn("fail-fast: false", library)
        self.assertIn("timeout-minutes: 45", library)
        self.assertNotIn("continue-on-error", library)
        self.assertIn('run-linux-ci-cargo-test-partition.sh lib "${{ matrix.shard }}"', library)
        self.assertEqual(library.count("if: matrix.shard == 'rest'"), 4)
        gate = source.split("  linux-gate:", 1)[1].split("  portable-build:", 1)[0]
        self.assertIn("if: always()", gate)
        self.assertIn("needs.linux-library.result", gate)
        self.assertIn("needs.linux-integration.result", gate)

    def test_gate_rejects_failed_cancelled_and_skipped_matrix_or_integration(self):
        source = WORKFLOW.read_text(encoding="utf-8")
        gate = source.split("  linux-gate:", 1)[1].split("  portable-build:", 1)[0]
        script = textwrap.dedent(gate.split("        run: |\n", 1)[1])
        for library in ["success", "failure", "cancelled", "skipped"]:
            for integration in ["success", "failure", "cancelled", "skipped"]:
                env = dict(os.environ, LIBRARY_RESULT=library, INTEGRATION_RESULT=integration)
                result = subprocess.run(["bash", "-c", script], env=env, capture_output=True)
                self.assertEqual(result.returncode == 0, library == integration == "success")

    def test_wrapper_keeps_metadata_verification_and_delegation(self):
        with tempfile.TemporaryDirectory() as directory:
            scripts = pathlib.Path(directory) / ".github/scripts"
            scripts.mkdir(parents=True)
            wrapper = scripts / "run-linux-ci-cargo-test-partition.sh"
            wrapper.write_bytes((ROOT / ".github/scripts" / wrapper.name).read_bytes())
            (scripts / "linux_ci_cargo_test_partition.py").write_text(
                "import pathlib, sys\n"
                "marker = pathlib.Path(__file__).with_name('verified')\n"
                "if sys.argv[1] == 'verify':\n"
                "    marker.touch()\n"
                "else:\n"
                "    assert marker.exists()\n"
                "    print('--lib' if sys.argv[2] == 'lib' else '--bin\\nmaco')\n",
                encoding="utf-8",
            )
            (scripts / "run-linux-all-tests-in-delegated-user-scope.sh").write_text(
                '#!/usr/bin/env bash\nprintf "%s\\n" "$@"\n', encoding="utf-8"
            )
            for shard in shards.SHARDS:
                result = subprocess.run(
                    ["bash", str(wrapper), "lib", shard], capture_output=True, text=True
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.splitlines(), [
                    "python3", str(scripts / SCRIPT.name), shard, "--manifest-dir", directory
                ])
            result = subprocess.run(
                ["bash", str(wrapper), "non-lib"], capture_output=True, text=True
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.splitlines(), ["cargo", "test", "--locked", "--bin", "maco"])
            for args in [["lib"], ["lib", "unknown"], ["non-lib", "rest"]]:
                result = subprocess.run(["bash", str(wrapper), *args], capture_output=True)
                self.assertNotEqual(result.returncode, 0)


@unittest.skipUnless(shutil.which("rustc") and shutil.which("cargo"), "real libtest enumeration requires Rust")
class RealLibtestShardTests(unittest.TestCase):
    def test_exact_shards_cover_real_harness_and_preserve_ignored_tests(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            fixture = root / "fixture.rs"
            fixture.write_text("""
mod autopilot {
    #[test] fn first() {}
    #[test] fn first_longer() {}
}
mod supervise {
    #[test] fn first() {}
    #[test] #[ignore] fn ignored() { panic!("must remain ignored"); }
}
mod future {
    mod autopilot { #[test] fn nested() {} }
    #[test] fn supervise_lookalike() {}
}
#[test] fn root_test() {}
""", encoding="utf-8")
            binary = root / ("fixture.exe" if os.name == "nt" else "fixture")
            subprocess.run(["rustc", "--test", str(fixture), "-o", str(binary)], check=True)
            runner = [str(binary)]
            inventory = shards.enumerate_tests(runner)
            self.assertEqual(len(inventory), 7)
            partitions = shards.partition_inventory(inventory)
            observed = []
            for shard, names in partitions.items():
                observed.extend(shards.enumerate_tests(runner, names))
                result = subprocess.run(shards.test_command(runner, names), capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                if shard == "supervise":
                    self.assertIn("1 ignored", result.stdout)
            self.assertCountEqual(observed, inventory)
            self.assertEqual(len(observed), len(set(observed)))
            # Exercise the production CLI through Cargo too, not only the pure
            # partition function or a mock of libtest's multiple exact filters.
            (root / "Cargo.toml").write_text(
                '[package]\nname="ci-shard-fixture"\nversion="0.0.0"\nedition="2021"\n'
                '[lib]\npath="fixture.rs"\n', encoding="utf-8"
            )
            env = dict(os.environ, CARGO_TARGET_DIR=str(root / "target"))
            subprocess.run(["cargo", "generate-lockfile", "--offline"], cwd=root, env=env, check=True)
            for shard in shards.SHARDS:
                result = subprocess.run(
                    [sys.executable, str(SCRIPT), shard, "--manifest-dir", str(root)],
                    env=env, capture_output=True, text=True,
                )
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn(f'"selected": "{shard}"', result.stdout)
                self.assertIn('"total": 7', result.stdout)


if __name__ == "__main__":
    unittest.main()
