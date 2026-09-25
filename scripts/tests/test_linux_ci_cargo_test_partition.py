import importlib.util
import pathlib
import subprocess
import sys
import tempfile
import unittest


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
        self.assertEqual([target.kind for target in targets], ["lib"])

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
