import importlib.util
from collections import Counter
import pathlib
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[2]
PARTITION_PY = ROOT / ".github" / "scripts" / "linux_ci_cargo_test_partition.py"
PARTITION_SH = ROOT / ".github" / "scripts" / "run-linux-ci-cargo-test-partition.sh"
WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"


def load_partition_module():
    name = "linux_ci_cargo_test_partition"
    spec = importlib.util.spec_from_file_location(name, PARTITION_PY)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


partition = load_partition_module()


def sample_package() -> dict:
    return {
        "targets": [
            {"kind": ["custom-build"], "name": "build-script-build"},
            {"kind": ["lib"], "name": "multi-agent-coding-orchestrator"},
            {"kind": ["bin"], "name": "maco"},
            {"kind": ["test"], "name": "merge_cli"},
            {"kind": ["bench"], "name": "coordination"},
        ]
    }


class LinuxCiCargoTestPartitionTests(unittest.TestCase):
    def test_collect_and_verify_sample_metadata(self) -> None:
        targets = partition.collect_testable_targets(sample_package())
        partition.verify_partition(targets)
        self.assertEqual(partition.partition_argv(targets, "lib"), ["--lib"])
        self.assertEqual(partition.partition_argv(targets, "doc"), ["--doc"])
        self.assertEqual(
            partition.partition_argv(targets, "non-lib"),
            ["--bench", "coordination", "--bin", "maco", "--test", "merge_cli"],
        )

    def test_custom_build_target_is_excluded(self) -> None:
        package = {
            "targets": [
                {"kind": ["custom-build"], "name": "build-script-build"},
                {"kind": ["lib"], "name": "crate"},
            ]
        }
        targets = partition.collect_testable_targets(package)
        self.assertEqual([target.kind for target in targets], ["doc", "lib"])

    def test_explicitly_disabled_doctest_target_is_excluded(self) -> None:
        package = {"targets": [{"kind": ["lib"], "name": "crate", "doctest": False}]}
        targets = partition.collect_testable_targets(package)
        partition.verify_partition(targets)
        self.assertEqual(partition.partition_argv(targets, "doc"), [])

    def test_doc_target_omission_fails_metadata_coverage(self) -> None:
        targets = partition.collect_testable_targets(sample_package())
        original = partition.partition_argv
        with mock.patch.object(partition, "partition_argv", side_effect=lambda targets, group, shard=None: [] if group == "doc" else original(targets, group, shard)):
            with self.assertRaisesRegex(ValueError, "does not cover metadata"):
                partition.verify_partition(targets)

    def test_inventory_includes_doctests_and_retains_explicit_benchmarks(self) -> None:
        full = partition.parse_test_listing("unit: test\nshared: test\nshared: test\nsrc/lib.rs - api (line 1): test\n\n4 tests, 0 benchmarks\n")
        groups = {
            "lib": Counter({("test", "unit"): 1}),
            "non-lib": Counter({("test", "shared"): 2, ("benchmark", "speed"): 1}),
            "doc": Counter({("test", "src/lib.rs - api (line 1)"): 1}),
        }
        result = partition.verify_test_inventory(full, groups)
        self.assertEqual((result["full_tests"], result["partition_tests"]), (4, 4))
        self.assertEqual(result["additional_benchmarks"], ["speed"])
        del groups["doc"]
        with self.assertRaisesRegex(ValueError, "src/lib.rs - api"):
            partition.verify_test_inventory(full, groups)

    def test_inventory_rejects_future_missing_duplicate_or_extra_doctest(self) -> None:
        current = ("test", "src/lib.rs - api (line 1)")
        future = ("test", "src/new.rs - api (line 2)")
        for full, observed in (
            (Counter({current: 1, future: 1}), Counter({current: 1})),
            (Counter({current: 1}), Counter({current: 2})),
            (Counter({current: 1}), Counter({current: 1, future: 1})),
        ):
            with self.subTest(full=full, observed=observed), self.assertRaisesRegex(ValueError, "inventory differs"):
                partition.verify_test_inventory(full, {"doc": observed})

    def test_inventory_rejects_malformed_listing(self) -> None:
        with self.assertRaisesRegex(ValueError, "unexpected Cargo test listing"):
            partition.parse_test_listing("src/lib.rs: unknown\n")

    def test_full_inventory_queries_doctests_and_exact_library_selection(self) -> None:
        spec = importlib.util.spec_from_file_location("inventory_library", PARTITION_PY.with_name("linux_ci_library_shards.py"))
        library = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(library)
        doc = "src/lib.rs - api (line 1)"

        def listing(command, **kwargs):
            if "--doc" in command:
                output = f"{doc}: test\n\n1 test, 0 benchmarks\n"
            elif "--lib" in command:
                output = "unit: test\n"
                if "--format" not in command:
                    output += "\n1 test, 0 benchmarks\n"
            elif "--test" in command:
                output = "integration: test\n\n1 test, 0 benchmarks\n"
            elif "--bench" in command:
                output = "speed: benchmark\n"
            else:
                output = f"unit: test\nintegration: test\n{doc}: test\n\n3 tests, 0 benchmarks\n"
            return subprocess.CompletedProcess(command, 0, output, "")

        with mock.patch.dict(sys.modules, {"linux_ci_library_shards": library}), mock.patch.object(library, "partition_inventory", return_value={"autopilot": ["unit"]}), mock.patch.object(library, "validate_mandatory_supervise_ownership"), mock.patch.object(partition.subprocess, "run", side_effect=listing) as run:
            result = partition.verify_full_inventory(partition.collect_testable_targets(sample_package()), ROOT)
        self.assertEqual(result["full_tests"], 3)
        self.assertEqual(result["doctests"], [doc])
        self.assertIn(["cargo", "test", "--locked", "--doc", "--", "--list"], [call.args[0] for call in run.call_args_list])
        self.assertIn(["cargo", "test", "--locked", "--lib", "--", "--list", "--exact", "--", "unit"], [call.args[0] for call in run.call_args_list])

    def test_doctests_and_full_inventory_are_required_after_source_bound_build(self) -> None:
        source = WORKFLOW.read_text(encoding="utf-8")
        library = source.split("  linux-library:\n", 1)[1].split("  linux-integration:\n", 1)[0]
        self.assertIn("needs: nix-package", library)
        self.assertIn("shard: [autopilot, supervise-core, supervise-bound, supervise-decomposition,", library)
        inventory = (
            "- name: Verify full test inventory including doctests\n"
            "        if: matrix.shard == 'supervise-decomposition'\n"
            "        run: bash .github/scripts/run-linux-all-tests-in-delegated-user-scope.sh python3 .github/scripts/linux_ci_cargo_test_partition.py verify-inventory"
        )
        doctests = (
            "- name: Run doctests\n"
            "        if: matrix.shard == 'supervise-decomposition'\n"
            "        run: bash .github/scripts/run-linux-ci-cargo-test-partition.sh doc"
        )
        self.assertEqual(library.count(inventory), 1)
        self.assertEqual(library.count(doctests), 1)
        self.assertLess(library.index("Verify independent bindings, import, and qualify"), library.index("Run library tests"))
        self.assertLess(library.index("Run library tests"), library.index(inventory))
        self.assertLess(library.index(inventory), library.index(doctests))
        self.assertNotIn("continue-on-error", library)

    def test_non_lib_shards_cover_original_targets_once_including_future_targets(self) -> None:
        package = sample_package()
        package["targets"].extend([
            {"kind": ["test"], "name": "pr_issue_cli"},
            {"kind": ["test"], "name": "future_integration"},
            {"kind": ["example"], "name": "merge_cli"},
        ])
        targets = partition.collect_testable_targets(package)
        partition.verify_partition(targets)
        old = partition.argv_to_keys(partition.partition_argv(targets, "non-lib"))
        groups = {
            shard: partition.argv_to_keys(partition.partition_argv(targets, "non-lib", shard))
            for shard in partition.NON_LIB_SHARDS
        }
        self.assertEqual(groups["merge"], [("test", "merge_cli"), ("test", "pr_issue_cli")])
        self.assertIn(("example", "merge_cli"), groups["other"])
        self.assertIn(("test", "future_integration"), groups["other"])
        flattened = [key for group in groups.values() for key in group]
        self.assertCountEqual(flattened, old)
        self.assertEqual(len(flattened), len(set(flattened)))

    def test_invalid_non_lib_shard_refused(self) -> None:
        targets = partition.collect_testable_targets(sample_package())
        for group, shard in (("non-lib", "unknown"), ("lib", "merge")):
            with self.subTest(group=group, shard=shard), self.assertRaises(ValueError):
                partition.partition_argv(targets, group, shard)

    def test_integration_matrix_requires_every_target_shard(self) -> None:
        source = WORKFLOW.read_text(encoding="utf-8")
        job = source.split("  linux-integration:", 1)[1].split("  linux-gate:", 1)[0]
        self.assertIn("shard: [merge, other]", job)
        self.assertIn("fail-fast: false", job)
        self.assertIn("timeout-minutes: 45", job)
        self.assertNotIn("continue-on-error", job)
        self.assertIn('non-lib "${{ matrix.shard }}"', job)

    def test_unsupported_target_kind_fails_closed(self) -> None:
        package = {
            "targets": [
                {"kind": ["proc-macro"], "name": "helper"},
            ]
        }
        with self.assertRaises(ValueError):
            partition.collect_testable_targets(package)

    def test_malformed_target_entry_fails_closed(self) -> None:
        package = {"targets": ["not-a-mapping"]}
        with self.assertRaises(ValueError):
            partition.collect_testable_targets(package)

    def test_duplicate_metadata_target_key_fails_closed(self) -> None:
        package = {
            "targets": [
                {"kind": ["bin"], "name": "maco"},
                {"kind": ["bin"], "name": "maco"},
            ]
        }
        with self.assertRaises(ValueError):
            partition.collect_testable_targets(package)

    def test_duplicate_partition_argv_key_fails_closed(self) -> None:
        with self.assertRaises(ValueError):
            partition.argv_to_keys(["--bin", "maco", "--bin", "maco"])

    def test_unsupported_partition_flag_fails_closed(self) -> None:
        with self.assertRaises(ValueError):
            partition.argv_to_keys(["--tests"])

    def test_unsafe_target_name_rejected(self) -> None:
        with self.assertRaises(ValueError):
            partition.validate_target_name("bad;name")

    def test_missing_lib_target_fails(self) -> None:
        package = {
            "targets": [
                {"kind": ["bin"], "name": "maco"},
            ]
        }
        targets = partition.collect_testable_targets(package)
        with self.assertRaises(ValueError):
            partition.partition_argv(targets, "lib")

    def test_workflow_gate_requires_both_linux_jobs(self) -> None:
        source = WORKFLOW.read_text(encoding="utf-8")
        gate = source.split("linux-gate:", 1)[1].split("portable-build:", 1)[0]
        self.assertIn("name: Linux fmt, check, clippy, and test", gate)
        self.assertIn("if: always()", gate)
        self.assertIn("needs.linux-library.result", gate)
        self.assertIn("needs.linux-integration.result", gate)
        self.assertIn('!= "success"', gate)

    def test_partition_wrapper_is_valid_bash(self) -> None:
        result = subprocess.run(
            ["bash", "-n", str(PARTITION_SH)],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr)

    def test_production_wrapper_argv_failure_skips_delegated_runner(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            scripts = pathlib.Path(directory) / ".github" / "scripts"
            scripts.mkdir(parents=True)
            wrapper = scripts / PARTITION_SH.name
            wrapper.write_bytes(PARTITION_SH.read_bytes())
            (scripts / PARTITION_PY.name).write_text(
                "import sys\n"
                "if sys.argv[1] == 'verify':\n"
                "    sys.exit(0)\n"
                "print('--lib', flush=True)\n"
                "sys.exit(2)\n",
                encoding="utf-8",
            )
            marker = scripts / "delegated-was-called"
            (scripts / "run-linux-all-tests-in-delegated-user-scope.sh").write_text(
                '#!/usr/bin/env bash\n'
                'touch "$(dirname -- "$0")/delegated-was-called"\n'
                'exit 0\n',
                encoding="utf-8",
            )
            result = subprocess.run(
                ["bash", str(wrapper), "lib", "rest"],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 2, msg=result.stderr)
            self.assertFalse(marker.exists(), msg=result.stderr)


if __name__ == "__main__":
    unittest.main()
