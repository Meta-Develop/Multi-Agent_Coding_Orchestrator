import importlib.util
import io
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

    def test_rest_preflights_run_exactly_before_full_shard_without_full_nocapture(self):
        inventory = sorted([*INVENTORY, *shards.REST_SAFETY_PREFLIGHTS])
        selected = shards.partition_inventory(inventory)["rest"]
        summary = "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 9 filtered out; finished in 0.01s\n"
        with mock.patch.object(shards.subprocess, "run") as run:
            responses = [
                subprocess.CompletedProcess([], 0, listing(inventory)),
                subprocess.CompletedProcess([], 0, listing(selected)),
            ]
            for name in shards.REST_SAFETY_PREFLIGHTS:
                responses.extend([
                    subprocess.CompletedProcess([], 0, listing([name])),
                    subprocess.CompletedProcess([], 0, summary, ""),
                ])
            responses.append(subprocess.CompletedProcess([], 0))
            run.side_effect = responses
            self.assertEqual(shards.run_shard(["harness"], "rest"), 0)
            self.assertEqual(run.call_count, 3 + 2 * len(shards.REST_SAFETY_PREFLIGHTS))
            for index, name in enumerate(shards.REST_SAFETY_PREFLIGHTS):
                self.assertEqual(run.call_args_list[3 + 2 * index].args[0], ["harness", "--exact", "--nocapture", "--", name])
            self.assertEqual(run.call_args.args[0], shards.test_command(["harness"], selected))
            self.assertNotIn("--nocapture", run.call_args.args[0])

    def test_rest_preflight_failure_stops_before_full_shard(self):
        inventory = sorted([*INVENTORY, *shards.REST_SAFETY_PREFLIGHTS])
        selected = shards.partition_inventory(inventory)["rest"]
        for failed_index in range(len(shards.REST_SAFETY_PREFLIGHTS)):
            with self.subTest(failed_index=failed_index), mock.patch.object(shards.subprocess, "run") as run:
                responses = [
                    subprocess.CompletedProcess([], 0, listing(inventory)),
                    subprocess.CompletedProcess([], 0, listing(selected)),
                ]
                for index, name in enumerate(shards.REST_SAFETY_PREFLIGHTS):
                    responses.append(subprocess.CompletedProcess([], 0, listing([name])))
                    responses.append(subprocess.CompletedProcess(
                        [], 101 if index == failed_index else 0,
                        "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s\n",
                        "typed failure boundary\n" if index == failed_index else "",
                    ))
                    if index == failed_index:
                        break
                run.side_effect = responses
                self.assertEqual(shards.run_shard(["harness"], "rest"), 101)
                self.assertEqual(run.call_count, 2 + 2 * (failed_index + 1))
                self.assertNotIn(shards.test_command(["harness"], selected), [call.args[0] for call in run.call_args_list])

    def test_rest_preflight_refuses_missing_or_overlapping_exact_selection(self):
        name = shards.REST_SAFETY_PREFLIGHTS[0]
        with mock.patch.object(shards.subprocess, "run") as run:
            with self.assertRaises(ValueError):
                shards.run_safety_preflights(["harness"], [], "rest")
            run.assert_not_called()
        for observed in [[], [name + "_longer"], [name, name + "_longer"]]:
            with self.subTest(observed=observed), mock.patch.object(shards.subprocess, "run") as run:
                run.return_value = subprocess.CompletedProcess([], 0, listing(observed))
                with self.assertRaises(ValueError):
                    shards.run_safety_preflights(["harness"], shards.REST_SAFETY_PREFLIGHTS, "rest")
                self.assertEqual(run.call_count, 1)

    def test_rest_preflight_refuses_zero_ignored_missing_or_duplicate_execution_summaries(self):
        good = "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s\n"
        for output in [good.replace("1 passed", "0 passed"), good.replace("0 ignored", "1 ignored"), "", good + good]:
            with self.subTest(output=output), mock.patch.object(shards.subprocess, "run") as run:
                run.side_effect = [
                    subprocess.CompletedProcess([], 0, listing(shards.REST_SAFETY_PREFLIGHTS[:1])),
                    subprocess.CompletedProcess([], 0, output, ""),
                ]
                with self.assertRaises(ValueError):
                    shards.run_safety_preflights(["harness"], shards.REST_SAFETY_PREFLIGHTS, "rest")
                self.assertEqual(run.call_count, 2)

    def test_rest_preflight_refuses_positive_harness_summary_after_fixture_skip(self):
        with mock.patch.object(shards.subprocess, "run") as run:
            run.side_effect = [
                subprocess.CompletedProcess([], 0, listing(shards.REST_SAFETY_PREFLIGHTS[:1])),
                subprocess.CompletedProcess([], 0,
                    "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s\n",
                    "skipping Nix-store-dependent Gemini online profile test\n"),
            ]
            with self.assertRaises(ValueError):
                shards.run_safety_preflights(["harness"], shards.REST_SAFETY_PREFLIGHTS, "rest")
            self.assertEqual(run.call_count, 2)

    def test_supervise_preflight_runs_exactly_once_and_stops_full_shard_on_failure(self):
        names = shards.SAFETY_PREFLIGHTS["supervise"]
        self.assertEqual(names, (
            "supervise::selection_bridge::tests::account_observe_unknown_models_fail_closed",
            "supervise::selection_bridge::tests::automatic_empty_role_models_resolve_all_roles_from_eligible_catalog",
            "supervise::assignment_execution::attached_parent_capture_tests::attached_capture_bookkeeping_and_shutdown_errors_retain_owners",
        ))
        inventory = sorted([*INVENTORY, *names])
        selected = shards.partition_inventory(inventory)["supervise"]
        summary = "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 9 filtered out; finished in 0.01s\n"
        for failed_index in [None, 0, 1, 2]:
            with self.subTest(failed_index=failed_index), mock.patch.object(shards.subprocess, "run") as run, mock.patch.object(shards, "run_supervise_diagnostics", return_value=0) as diagnostics:
                responses = [
                    subprocess.CompletedProcess([], 0, listing(inventory)),
                    subprocess.CompletedProcess([], 0, listing(selected)),
                ]
                for index, name in enumerate(names):
                    responses.append(subprocess.CompletedProcess([], 0, listing([name])))
                    responses.append(subprocess.CompletedProcess(
                        [], 101 if index == failed_index else 0, summary, "",
                    ))
                    if index == failed_index:
                        break
                if failed_index is None:
                    responses.append(subprocess.CompletedProcess([], 0))
                run.side_effect = responses
                status = 0 if failed_index is None else 101
                self.assertEqual(shards.run_shard(["harness"], "supervise"), status)
                completed_preflights = len(names) if failed_index is None else failed_index + 1
                self.assertEqual(run.call_count, 2 + 2 * completed_preflights + (1 if failed_index is None else 0))
                for index, name in enumerate(names[:completed_preflights]):
                    self.assertEqual(
                        run.call_args_list[2 + 2 * index].args[0],
                        ["harness", "--list", "--format", "terse", "--exact", "--", name],
                    )
                    self.assertEqual(
                        run.call_args_list[3 + 2 * index].args[0],
                        ["harness", "--exact", "--nocapture", "--", name],
                    )
                full_command = shards.test_command(["harness"], selected)
                if failed_index is None:
                    self.assertEqual(run.call_args.args[0], full_command)
                    self.assertNotIn("--nocapture", run.call_args.args[0])
                    diagnostics.assert_called_once_with(["harness"], selected)
                else:
                    diagnostics.assert_not_called()
                    self.assertNotIn(full_command, [call.args[0] for call in run.call_args_list])

    def test_supervise_diagnostics_collect_all_three_before_blocking_full_shard(self):
        names = shards.SUPERVISE_DIAGNOSTICS
        self.assertEqual(names, (
            "supervise::tests::plan_runtime::no_override_selects_single_slug_effort_profile_for_every_role",
            "supervise::assignment_execution::decomposition_tests::auditor_runtime_override_preserves_active_heterogeneous_lens_contract",
            "supervise::selection_bridge::tests::runtime_reselection_returns_matching_executable_runtime_binding",
        ))
        inventory = sorted([*INVENTORY, *shards.SAFETY_PREFLIGHTS["supervise"], *names])
        selected = shards.partition_inventory(inventory)["supervise"]
        good = "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 9 filtered out; finished in 0.01s\n"
        bad = "test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 9 filtered out; finished in 0.01s\n"
        for statuses in [(0, 0, 0), (101, 0, 0), (0, 101, 0), (0, 0, 101), (101, 101, 101), (124, 0, 0)]:
            out, err = io.StringIO(), io.StringIO()
            with self.subTest(statuses=statuses), mock.patch.object(shards, "enumerate_tests", side_effect=[inventory, selected]), mock.patch.object(shards, "run_safety_preflights", return_value=0) as safety, mock.patch.object(shards, "_capture_supervise_diagnostic") as capture, mock.patch.object(shards.subprocess, "run") as run, mock.patch("sys.stdout", out), mock.patch("sys.stderr", err):
                responses = []
                for name, status in zip(names, statuses):
                    responses.extend([
                        subprocess.CompletedProcess([], 0, listing([name]), ""),
                        subprocess.CompletedProcess([], status, "partial output" if status == 124 else bad if status else good,
                                                    "fixture panic boundary\n" if status else ""),
                    ])
                capture.side_effect = responses
                run.return_value = subprocess.CompletedProcess([], 0)
                self.assertEqual(shards.run_shard(["harness"], "supervise"), int(any(statuses)))
                safety.assert_called_once_with(["harness"], selected, "supervise")
                self.assertEqual(capture.call_count, 6)
                for i, name in enumerate(names):
                    self.assertEqual(capture.call_args_list[2 * i].args[0],
                                     ["harness", "--list", "--format", "terse", "--exact", "--", name])
                    self.assertEqual(capture.call_args_list[2 * i + 1].args[0],
                                     ["harness", "--exact", "--nocapture", "--", name])
                    self.assertIn(name, out.getvalue())
                if any(statuses):
                    run.assert_not_called()
                    self.assertIn("fixture panic boundary", err.getvalue())
                else:
                    run.assert_called_once_with(shards.test_command(["harness"], selected), check=False)
                    self.assertNotIn("--nocapture", run.call_args.args[0])

    def test_supervise_diagnostics_refuse_non_single_body_and_continue_remaining_cases(self):
        names = shards.SUPERVISE_DIAGNOSTICS
        good = "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 9 filtered out; finished in 0.01s\n"
        for output in ["", good.replace("1 passed", "0 passed"), good.replace("0 ignored", "1 ignored"), good.replace("1 passed", "2 passed"), good + good]:
            with self.subTest(output=output), mock.patch.object(shards, "_capture_supervise_diagnostic") as capture, mock.patch("sys.stdout", io.StringIO()), mock.patch("sys.stderr", io.StringIO()):
                capture.side_effect = [
                    result for i, name in enumerate(names) for result in [
                        subprocess.CompletedProcess([], 0, listing([name]), ""),
                        subprocess.CompletedProcess([], 0, output if i == 0 else good, ""),
                    ]
                ]
                self.assertEqual(shards.run_supervise_diagnostics(["harness"], names), 1)
                self.assertEqual(capture.call_count, 6)

    def test_supervise_diagnostics_refuse_inexact_inventory_without_running_that_body(self):
        names = shards.SUPERVISE_DIAGNOSTICS
        good = "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 9 filtered out; finished in 0.01s\n"
        for observed in [[], [names[0] + "_longer"], [names[0], names[0] + "_longer"], [names[0], names[0]]]:
            with self.subTest(observed=observed), mock.patch.object(shards, "_capture_supervise_diagnostic") as capture, mock.patch("sys.stdout", io.StringIO()), mock.patch("sys.stderr", io.StringIO()):
                capture.side_effect = [subprocess.CompletedProcess([], 0, listing(observed), "")] + [
                    result for name in names[1:] for result in [
                        subprocess.CompletedProcess([], 0, listing([name]), ""),
                        subprocess.CompletedProcess([], 0, good, ""),
                    ]
                ]
                self.assertEqual(shards.run_supervise_diagnostics(["harness"], names), 1)
                self.assertEqual(capture.call_count, 5)
                self.assertNotIn(["harness", "--exact", "--nocapture", "--", names[0]],
                                 [call.args[0] for call in capture.call_args_list])
        with mock.patch.object(shards, "_capture_supervise_diagnostic") as capture, mock.patch("sys.stdout", io.StringIO()):
            self.assertEqual(shards.run_supervise_diagnostics(["harness"], []), 1)
            capture.assert_not_called()

    def test_supervise_diagnostic_timeout_kills_only_its_new_process_group_without_retry(self):
        command = ["harness", "--exact", "--nocapture", "--", shards.SUPERVISE_DIAGNOSTICS[0]]
        with mock.patch.object(shards.subprocess, "Popen") as popen, mock.patch.object(shards.os, "killpg", create=True) as killpg, mock.patch.object(shards.signal, "SIGKILL", 9, create=True):
            process = popen.return_value.__enter__.return_value
            process.pid = 1234
            process.communicate.side_effect = [subprocess.TimeoutExpired(command, 30), ("partial stdout", "partial stderr")]
            result = shards._capture_supervise_diagnostic(command)
            self.assertEqual(shards.SUPERVISE_DIAGNOSTIC_TIMEOUT_SECONDS, 30)
            popen.assert_called_once_with(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                         stderr=subprocess.PIPE, text=True, start_new_session=True)
            self.assertEqual(process.communicate.call_args_list, [mock.call(timeout=30), mock.call()])
            killpg.assert_called_once_with(1234, 9)
            self.assertEqual((result.returncode, result.stdout, result.stderr),
                             (124, "partial stdout", "partial stderr"))

    def test_gate_rejects_failed_cancelled_and_skipped_package_matrix_or_integration(self):
        bash = shutil.which("bash")
        self.assertIsNotNone(bash)
        self.assertTrue(pathlib.Path(bash).is_absolute())
        creationflags = (
            subprocess.CREATE_NO_WINDOW | subprocess.BELOW_NORMAL_PRIORITY_CLASS
            if os.name == "nt" else 0
        )
        source = WORKFLOW.read_text(encoding="utf-8")
        gate = source.split("  linux-gate:", 1)[1].split("  portable-build:", 1)[0]
        script = textwrap.dedent(gate.split("        run: |\n", 1)[1])
        for package in ["success", "failure", "cancelled", "skipped"]:
            for library in ["success", "failure", "cancelled", "skipped"]:
                for integration in ["success", "failure", "cancelled", "skipped"]:
                    with self.subTest(package=package, library=library, integration=integration):
                        env = dict(
                            os.environ,
                            PACKAGE_RESULT=package,
                            LIBRARY_RESULT=library,
                            INTEGRATION_RESULT=integration,
                        )
                        result = subprocess.run(
                            [bash, "-c", script],
                            env=env,
                            capture_output=True,
                            stdin=subprocess.DEVNULL,
                            creationflags=creationflags,
                        )
                        self.assertEqual(
                            result.returncode == 0,
                            package == library == integration == "success",
                        )

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
    mod selection_bridge {
        mod tests {
            // Empty bodies verify wrapper selection only, not real selector semantics.
            #[test] fn account_observe_unknown_models_fail_closed() {}
            #[test] fn automatic_empty_role_models_resolve_all_roles_from_eligible_catalog() {}
            #[test] fn runtime_reselection_returns_matching_executable_runtime_binding() {}
        }
    }
    mod tests {
        mod plan_runtime {
            #[test] fn no_override_selects_single_slug_effort_profile_for_every_role() {}
        }
    }
    mod assignment_execution {
        mod decomposition_tests {
            #[test] fn auditor_runtime_override_preserves_active_heterogeneous_lens_contract() {}
        }
        mod attached_parent_capture_tests {
            // Empty body verifies wrapper selection only, not real ownership semantics.
            #[test] fn attached_capture_bookkeeping_and_shutdown_errors_retain_owners() {}
        }
    }
}
mod future {
    mod autopilot { #[test] fn nested() {} }
    #[test] fn supervise_lookalike() {}
}
mod process_runner {
    mod tests {
        #[test] fn gemini_online_profile_projects_only_the_trusted_resolver_file() {}
    }
}
mod runtime_adapter {
    mod cursor_managed_parent {
        mod tests {
            // Empty bodies verify wrapper selection only, not privacy/authority semantics.
            #[test] fn offline_check_failure_diagnostic_keeps_untrusted_output_private() {}
            #[test] fn assignment_authority_admits_exact_write_read_and_parent_owned_check() {}
        }
    }
}
#[test] fn root_test() {}
""", encoding="utf-8")
            binary = root / ("fixture.exe" if os.name == "nt" else "fixture")
            subprocess.run(["rustc", "--test", str(fixture), "-o", str(binary)], check=True)
            runner = [str(binary)]
            inventory = shards.enumerate_tests(runner)
            self.assertEqual(len(inventory), 16)
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
                self.assertIn('"total": 16', result.stdout)


if __name__ == "__main__":
    unittest.main()
