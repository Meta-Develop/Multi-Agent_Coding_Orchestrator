import importlib.util
import io
import json
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


def mandatory_supervise_inventory():
    return (*shards.SUPERVISE_DIAGNOSTICS, *shards.SUPERVISE_CAUSAL_DIAGNOSTICS)


def owned_supervise_diagnostics(selected):
    return [name for name in shards.SUPERVISE_DIAGNOSTICS if name in selected]


def owned_supervise_causal(selected):
    return [name for name in shards.SUPERVISE_CAUSAL_DIAGNOSTICS if name in selected]



def causal_output(name, failed=False):
    status = "FAILED" if failed else "ok"
    passed, failures = (0, 1) if failed else (1, 0)
    return (
        f"running 1 test\ntest {name} ... {status}\n\n"
        f"test result: {status}. {passed} passed; {failures} failed; "
        "0 ignored; 0 measured; 9 filtered out; finished in 0.01s\n"
    )

# Actual job115111506303 stdout, log lines1269-1274; only transport timestamps removed.
# This is a parser fixture, not a rerun or a claim about other Rust cases.
CAPTURED_MANAGED_CYCLE_STDOUT = 'running 1 test\ntest supervise::assignment_execution::managed_parent_controller_tests::managed_cycle_isolated_workers_overlap_and_import_exact_union has been running for over 60 seconds\ntest supervise::assignment_execution::managed_parent_controller_tests::managed_cycle_isolated_workers_overlap_and_import_exact_union ... ok\n\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 4534 filtered out; finished in 70.73s\n\n'

class LibraryShardTests(unittest.TestCase):
    def test_partition_is_disjoint_complete_stable_and_includes_new_modules(self):
        partitions = shards.partition_inventory(INVENTORY)
        self.assertEqual(partitions, shards.partition_inventory(list(reversed(INVENTORY))))
        self.assertEqual(partitions["autopilot"], sorted(INVENTORY[:2]))
        self.assertEqual(partitions["supervise-fixtures"], sorted(INVENTORY[2:4]))
        self.assertEqual(partitions["supervise-core"], [])
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

    def test_list_mode_checks_real_selection_without_executing_bodies(self):
        selected = sorted(INVENTORY[:2])
        with mock.patch.object(shards, "enumerate_tests", side_effect=[INVENTORY, selected]) as enumerate_tests, mock.patch.object(shards.subprocess, "run") as run, mock.patch("sys.stdout", io.StringIO()) as output:
            self.assertEqual(shards.run_shard(["harness"], "autopilot", list_only=True), 0)
            self.assertEqual(enumerate_tests.call_count, 2)
            run.assert_not_called()
            records = [json.loads(line) for line in output.getvalue().splitlines()]
            self.assertEqual(records[-1], {"selected": "autopilot", "tests": selected})

    def test_list_mode_refuses_a_libtest_filter_mismatch(self):
        with mock.patch.object(shards, "enumerate_tests", side_effect=[INVENTORY, []]), mock.patch.object(shards.subprocess, "run") as run:
            with self.assertRaises(ValueError):
                shards.run_shard(["harness"], "autopilot", list_only=True)
            run.assert_not_called()

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
        self.assertEqual(library.count("if: matrix.shard == 'rest'"), 6)
        userns = (
            "- name: Allow root libtest userns on GitHub-hosted Ubuntu\n"
            "        if: matrix.shard == 'rest'\n"
            "        run: bash .github/scripts/configure-github-hosted-root-libtest-userns.sh"
        )
        self.assertEqual(library.count(userns), 1)
        self.assertLess(library.index("- name: Lint all targets"), library.index(userns))
        self.assertLess(
            library.index(userns),
            library.index("- name: Verify sealed native entry regressions"),
        )
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
        names = shards.SAFETY_PREFLIGHTS["supervise-core"]
        self.assertEqual(names, (
            "supervise::selection_bridge::tests::account_observe_unknown_models_fail_closed",
            "supervise::selection_bridge::tests::automatic_empty_role_models_resolve_all_roles_from_eligible_catalog",
            "supervise::assignment_execution::attached_parent_capture_tests::attached_capture_bookkeeping_and_shutdown_errors_retain_owners",
        ))
        inventory = sorted({*INVENTORY, *names, *mandatory_supervise_inventory()})
        selected = shards.partition_inventory(inventory)["supervise-core"]
        own_diagnostics = owned_supervise_diagnostics(selected)
        own_causal = owned_supervise_causal(selected)
        summary = "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 9 filtered out; finished in 0.01s\n"
        for failed_index in [None, 0, 1, 2]:
            with self.subTest(failed_index=failed_index), mock.patch.object(shards.subprocess, "run") as run, mock.patch.object(shards, "run_supervise_diagnostics", return_value=0) as diagnostics, mock.patch.object(shards, "run_supervise_causal_diagnostics", return_value=0) as causal:
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
                self.assertEqual(shards.run_shard(["harness"], "supervise-core"), status)
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
                    diagnostics.assert_called_once_with(["harness"], selected, own_diagnostics)
                    causal.assert_called_once_with(["harness"], selected, own_causal)
                else:
                    diagnostics.assert_not_called()
                    causal.assert_not_called()
                    self.assertNotIn(full_command, [call.args[0] for call in run.call_args_list])

    def test_supervise_diagnostics_collect_all_three_before_blocking_full_shard(self):
        names = shards.SUPERVISE_DIAGNOSTICS
        self.assertEqual(names, (
            "supervise::tests::plan_runtime::no_override_selects_single_slug_effort_profile_for_every_role",
            "supervise::assignment_execution::decomposition_tests::auditor_runtime_override_preserves_active_heterogeneous_lens_contract",
            "supervise::selection_bridge::tests::runtime_reselection_returns_matching_executable_runtime_binding",
        ))
        inventory = sorted({
            *INVENTORY, *shards.SAFETY_PREFLIGHTS["supervise-core"], *mandatory_supervise_inventory(),
        })
        partitions = shards.partition_inventory(inventory)
        self.assertCountEqual(
            [name for shard in ("supervise-core", "supervise-fixtures")
             for name in owned_supervise_diagnostics(partitions[shard])],
            list(names),
        )
        good = "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 9 filtered out; finished in 0.01s\n"
        bad = "test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 9 filtered out; finished in 0.01s\n"
        shard_diag_statuses = {
            "supervise-core": [(0, 0), (101, 0), (0, 101), (101, 101), (124, 0)],
            "supervise-fixtures": [(0,), (101,), (124,)],
        }
        for shard, status_sets in shard_diag_statuses.items():
            selected = partitions[shard]
            own_names = owned_supervise_diagnostics(selected)
            own_causal = owned_supervise_causal(selected)
            for statuses in status_sets:
                out, err = io.StringIO(), io.StringIO()
                with self.subTest(shard=shard, statuses=statuses), mock.patch.object(shards, "enumerate_tests", side_effect=[inventory, selected]), mock.patch.object(shards, "run_safety_preflights", return_value=0) as safety, mock.patch.object(shards, "_capture_supervise_diagnostic") as capture, mock.patch.object(shards.subprocess, "run") as run, mock.patch.object(shards, "run_supervise_causal_diagnostics", return_value=0) as causal, mock.patch("sys.stdout", out), mock.patch("sys.stderr", err):
                    responses = []
                    for name, status in zip(own_names, statuses):
                        responses.extend([
                            subprocess.CompletedProcess([], 0, listing([name]), ""),
                            subprocess.CompletedProcess([], status, "partial output" if status == 124 else bad if status else good,
                                                        "fixture panic boundary\n" if status else ""),
                        ])
                    capture.side_effect = responses
                    run.return_value = subprocess.CompletedProcess([], 0)
                    self.assertEqual(shards.run_shard(["harness"], shard), int(any(statuses)))
                    if shard in shards.SAFETY_PREFLIGHTS:
                        safety.assert_called_once_with(["harness"], selected, shard)
                    else:
                        safety.assert_not_called()
                    self.assertEqual(capture.call_count, 2 * len(own_names))
                    for i, name in enumerate(own_names):
                        self.assertEqual(capture.call_args_list[2 * i].args[0],
                                         ["harness", "--list", "--format", "terse", "--exact", "--", name])
                        self.assertEqual(capture.call_args_list[2 * i + 1].args[0],
                                         ["harness", "--exact", "--nocapture", "--", name])
                        self.assertIn(name, out.getvalue())
                    if any(statuses):
                        run.assert_not_called()
                        causal.assert_not_called()
                        self.assertIn("fixture panic boundary", err.getvalue())
                    else:
                        causal.assert_called_once_with(["harness"], selected, own_causal)
                        run.assert_called_once_with(shards.test_command(["harness"], selected), check=False)
                        self.assertNotIn("--nocapture", run.call_args.args[0])

        names = shards.SUPERVISE_CAUSAL_DIAGNOSTICS
        self.assertEqual(names, (
            "supervise::assignment_execution::bound_parent_turn_tests::bound_nested_evidence_rejects_forged_widened_failed_and_cancelled_results",
            "supervise::assignment_execution::managed_parent_controller_tests::managed_cycle_isolated_workers_overlap_and_import_exact_union",
            "supervise::scheduler::decomposition_tests::budget_degrade_ladder_applies_worker_model_effort_fanout_then_halts",
            "supervise::tests::scheduler::claim_and_semantic_block_conflicts_fail_only_the_affected_assignment",
        ))
        inventory = sorted({
            *INVENTORY, *shards.SAFETY_PREFLIGHTS["supervise-core"], *mandatory_supervise_inventory(),
        })
        partitions = shards.partition_inventory(inventory)
        self.assertCountEqual(
            [name for shard in ("supervise-core", "supervise-fixtures")
             for name in owned_supervise_causal(partitions[shard])],
            list(names),
        )
        shard_causal_statuses = {
            "supervise-core": [(0, 0, 0), (101, 0, 0), (0, 101, 0), (0, 0, 101), (101, 101, 101)],
            "supervise-fixtures": [(0,), (101,)],
        }
        for shard, status_sets in shard_causal_statuses.items():
            selected = partitions[shard]
            own_names = owned_supervise_causal(selected)
            for statuses in status_sets:
                out = io.StringIO()
                with self.subTest(shard=shard, causal_statuses=statuses), mock.patch.object(shards, "enumerate_tests", side_effect=[inventory, selected, *[[n] for n in own_names]]), mock.patch.object(shards, "run_safety_preflights", return_value=0), mock.patch.object(shards, "run_supervise_diagnostics", return_value=0), mock.patch.object(shards.subprocess, "run") as run, mock.patch("sys.stdout", out), mock.patch("sys.stderr", io.StringIO()):
                    run.side_effect = [
                        subprocess.CompletedProcess([], status, causal_output(name, status == 101), "")
                        for name, status in zip(own_names, statuses)
                    ] + ([] if any(statuses) else [subprocess.CompletedProcess([], 0)])
                    self.assertEqual(shards.run_shard(["harness"], shard), int(any(statuses)))
                    self.assertEqual(run.call_count, len(own_names) + int(not any(statuses)))
                    for index, name in enumerate(own_names):
                        self.assertEqual(run.call_args_list[index], mock.call(
                            ["harness", "--exact", "--", name],
                            check=False, capture_output=True, text=True,
                        ))
                    report = [json.loads(line) for line in out.getvalue().splitlines() if line.startswith('{"broad_allowed"')]
                    self.assertEqual(len(report), 1)
                    self.assertTrue(report[0]["complete"])
                    self.assertEqual([case["name"] for case in report[0]["supervise_causal_cases"]], list(own_names))
                    self.assertEqual([case["returncode"] for case in report[0]["supervise_causal_cases"]], list(statuses))
                    self.assertEqual(report[0]["broad_allowed"], not any(statuses))
                    full_command = shards.test_command(["harness"], selected)
                    if any(statuses):
                        self.assertNotIn(full_command, [call.args[0] for call in run.call_args_list])
                    else:
                        self.assertEqual(run.call_args, mock.call(full_command, check=False))

    def test_causal_diagnostic_accepts_captured_progress_and_retains_broad_failure_gate(self):
        names = shards.SUPERVISE_CAUSAL_DIAGNOSTICS
        inventory = sorted({
            *INVENTORY, *shards.SAFETY_PREFLIGHTS["supervise-core"], *mandatory_supervise_inventory(),
        })
        partitions = shards.partition_inventory(inventory)
        self.assertIn(f"test {names[1]} has been running for over 60 seconds\n", CAPTURED_MANAGED_CYCLE_STDOUT)
        core_selected = partitions["supervise-core"]
        core_names = owned_supervise_causal(core_selected)
        self.assertEqual(core_names[1], names[1])
        for failed_index in [None, 0, 1]:
            statuses = [101 if i == failed_index else 0 for i in range(len(core_names))]
            outputs = [causal_output(name, status == 101) for name, status in zip(core_names, statuses)]
            outputs[1] = CAPTURED_MANAGED_CYCLE_STDOUT
            if failed_index == 1:
                outputs[1] = outputs[1].replace("... ok", "... FAILED").replace(
                    "test result: ok. 1 passed; 0 failed;", "test result: FAILED. 0 passed; 1 failed;"
                )
            out = io.StringIO()
            with self.subTest(shard="supervise-core", failed_index=failed_index), mock.patch.object(shards, "enumerate_tests", side_effect=[inventory, core_selected, *[[n] for n in core_names]]) as enumerate_tests, mock.patch.object(shards, "run_safety_preflights", return_value=0), mock.patch.object(shards, "run_supervise_diagnostics", return_value=0), mock.patch.object(shards.subprocess, "run") as run, mock.patch("sys.stdout", out), mock.patch("sys.stderr", io.StringIO()):
                run.side_effect = [
                    subprocess.CompletedProcess([], status, output, "")
                    for status, output in zip(statuses, outputs)
                ] + ([] if failed_index is not None else [subprocess.CompletedProcess([], 0)])
                self.assertEqual(shards.run_shard(["harness"], "supervise-core"), int(failed_index is not None))
                self.assertEqual(enumerate_tests.call_args_list, [
                    mock.call(["harness"]), mock.call(["harness"], core_selected),
                    *[mock.call(["harness"], [name]) for name in core_names],
                ])
                self.assertEqual(run.call_count, len(core_names) + int(failed_index is None))
                for index, name in enumerate(core_names):
                    self.assertEqual(run.call_args_list[index], mock.call(
                        ["harness", "--exact", "--", name], check=False, capture_output=True, text=True,
                    ))
                report = [json.loads(line) for line in out.getvalue().splitlines() if line.startswith('{"broad_allowed"')]
                self.assertEqual(len(report), 1)
                self.assertTrue(report[0]["complete"])
                self.assertEqual([case["name"] for case in report[0]["supervise_causal_cases"]], list(core_names))
                self.assertEqual([case["outcome"] for case in report[0]["supervise_causal_cases"]], ["FAIL" if status else "PASS" for status in statuses])
                self.assertEqual(report[0]["broad_allowed"], failed_index is None)
                broad = shards.test_command(["harness"], core_selected)
                if failed_index is None:
                    self.assertEqual(run.call_args, mock.call(broad, check=False))
                else:
                    self.assertNotIn(broad, [call.args[0] for call in run.call_args_list])
        fixtures_selected = partitions["supervise-fixtures"]
        fixtures_names = owned_supervise_causal(fixtures_selected)
        self.assertEqual(fixtures_names, [names[3]])
        for failed_index in [None, 0]:
            statuses = [101 if i == failed_index else 0 for i in range(len(fixtures_names))]
            outputs = [causal_output(name, status == 101) for name, status in zip(fixtures_names, statuses)]
            out = io.StringIO()
            with self.subTest(shard="supervise-fixtures", failed_index=failed_index), mock.patch.object(shards, "enumerate_tests", side_effect=[inventory, fixtures_selected, *[[n] for n in fixtures_names]]) as enumerate_tests, mock.patch.object(shards, "run_safety_preflights", return_value=0) as safety, mock.patch.object(shards, "run_supervise_diagnostics", return_value=0), mock.patch.object(shards.subprocess, "run") as run, mock.patch("sys.stdout", out), mock.patch("sys.stderr", io.StringIO()):
                run.side_effect = [
                    subprocess.CompletedProcess([], status, output, "")
                    for status, output in zip(statuses, outputs)
                ] + ([] if failed_index is not None else [subprocess.CompletedProcess([], 0)])
                self.assertEqual(shards.run_shard(["harness"], "supervise-fixtures"), int(failed_index is not None))
                safety.assert_not_called()
                self.assertEqual(enumerate_tests.call_args_list, [
                    mock.call(["harness"]), mock.call(["harness"], fixtures_selected),
                    *[mock.call(["harness"], [name]) for name in fixtures_names],
                ])
                self.assertEqual(run.call_count, len(fixtures_names) + int(failed_index is None))
                report = [json.loads(line) for line in out.getvalue().splitlines() if line.startswith('{"broad_allowed"')]
                self.assertEqual(len(report), 1)
                self.assertTrue(report[0]["complete"])
                self.assertEqual([case["name"] for case in report[0]["supervise_causal_cases"]], list(fixtures_names))
                self.assertEqual(report[0]["broad_allowed"], failed_index is None)
                broad = shards.test_command(["harness"], fixtures_selected)
                if failed_index is None:
                    self.assertEqual(run.call_args, mock.call(broad, check=False))
                else:
                    self.assertNotIn(broad, [call.args[0] for call in run.call_args_list])

    def test_causal_diagnostic_refuses_wrong_duplicate_or_misordered_progress(self):
        names = shards.SUPERVISE_CAUSAL_DIAGNOSTICS
        output = CAPTURED_MANAGED_CYCLE_STDOUT
        warning = f"test {names[1]} has been running for over 60 seconds\n"
        terminal = f"test {names[1]} ... ok\n"
        invalid = [
            output.replace(warning, warning.replace(names[1], names[0])),
            output.replace(warning, warning.replace(names[1], names[1] + "_longer")),
            output.replace(warning, warning.replace("60", "61")),
            output.replace(warning, warning.replace("60", "sixty")),
            output.replace(warning, warning + warning),
            output.replace(warning + terminal, terminal + warning),
            output.replace(terminal, ""),
            output.replace(terminal, terminal + terminal),
            output.replace(terminal, terminal.replace(names[1], names[0])),
            output.replace(terminal, terminal.replace("... ok", "... ignored")),
            output + warning,
        ]
        for malformed in invalid:
            with self.subTest(output=malformed), mock.patch.object(shards.subprocess, "run") as run, mock.patch("sys.stdout", io.StringIO()), mock.patch("sys.stderr", io.StringIO()):
                run.side_effect = [
                    subprocess.CompletedProcess([], 0, listing([names[0]]), ""),
                    subprocess.CompletedProcess([], 101, causal_output(names[0], True), ""),
                    subprocess.CompletedProcess([], 0, listing([names[1]]), ""),
                    subprocess.CompletedProcess([], 0, malformed, ""),
                ]
                with self.assertRaises(ValueError):
                    shards.run_supervise_causal_diagnostics(["harness"], names)
                self.assertEqual(run.call_count, 4)

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


        names = shards.SUPERVISE_CAUSAL_DIAGNOSTICS
        good = causal_output(names[0])
        bad = causal_output(names[0], True)
        invalid = [
            (0, ""), (0, good.replace("1 passed", "0 passed")),
            (0, good.replace("0 ignored", "1 ignored")),
            (0, good.replace("0 measured", "1 measured")),
            (0, good.replace("1 passed", "2 passed")), (0, good + good),
            (0, good.replace(names[0], names[0] + "_longer")),
            (0, good.replace("... ok", "... ignored")),
            (0, good.replace(f"test {names[0]} ... ok", "")),
            (0, good + f"test {names[1]} ... ok\n"),
            (0, good + "test result: unrecognized\n"),
            (0, "test result: unrecognized\n" + good),
            (0, good + "nonterminal output\n"),
            (0, good + f"test {names[1]} ... unrecognized\n"),
            (101, good), (0, bad), (2, bad), (124, bad), (-9, bad),
        ]
        for status, output in invalid:
            with self.subTest(causal_status=status, output=output), mock.patch.object(shards.subprocess, "run") as run, mock.patch("sys.stdout", io.StringIO()), mock.patch("sys.stderr", io.StringIO()):
                run.side_effect = [
                    subprocess.CompletedProcess([], 0, listing([names[0]]), ""),
                    subprocess.CompletedProcess([], status, output, ""),
                ]
                with self.assertRaises(ValueError):
                    shards.run_supervise_causal_diagnostics(["harness"], names)
                self.assertEqual(run.call_count, 2)
        for invalid_index in [1, 2, 3]:
            with self.subTest(invalid_after_completed_failure=invalid_index), mock.patch.object(shards.subprocess, "run") as run, mock.patch("sys.stdout", io.StringIO()), mock.patch("sys.stderr", io.StringIO()):
                run.side_effect = [
                    result for index, name in enumerate(names[:invalid_index + 1]) for result in [
                        subprocess.CompletedProcess([], 0, listing([name]), ""),
                        subprocess.CompletedProcess([], 101 if index < invalid_index else 2, causal_output(name, True), ""),
                    ]
                ]
                with self.assertRaises(ValueError):
                    shards.run_supervise_causal_diagnostics(["harness"], names)
                self.assertEqual(run.call_count, 2 * (invalid_index + 1))
        with mock.patch.object(shards.subprocess, "run", side_effect=OSError("fixture infrastructure failure")) as run:
            with self.assertRaises(OSError):
                shards.run_supervise_causal_diagnostics(["harness"], names)
            self.assertEqual(run.call_count, 1)

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


        names = shards.SUPERVISE_CAUSAL_DIAGNOSTICS
        for observed in [[], [names[0] + "_longer"], [names[0], names[0] + "_longer"], [names[0], names[0]], ["malformed inventory"]]:
            with self.subTest(causal_inventory=observed), mock.patch.object(shards.subprocess, "run") as run:
                run.return_value = subprocess.CompletedProcess([], 0, listing(observed) if observed != ["malformed inventory"] else "running 1 test\n", "")
                with self.assertRaises(ValueError):
                    shards.run_supervise_causal_diagnostics(["harness"], names)
                self.assertEqual(run.call_count, 1)
        with mock.patch.object(shards.subprocess, "run") as run:
            with self.assertRaises(ValueError):
                shards.run_supervise_causal_diagnostics(["harness"], [])
            run.assert_not_called()
        with mock.patch.object(shards.subprocess, "run", side_effect=subprocess.CalledProcessError(101, ["harness"])) as run:
            with self.assertRaises(subprocess.CalledProcessError):
                shards.run_supervise_causal_diagnostics(["harness"], names)
            self.assertEqual(run.call_count, 1)


        with mock.patch.object(shards.subprocess, "run") as run, mock.patch("sys.stdout", io.StringIO()), mock.patch("sys.stderr", io.StringIO()):
            run.side_effect = [
                result for name in names[:3] for result in [
                    subprocess.CompletedProcess([], 0, listing([name]), ""),
                    subprocess.CompletedProcess([], 0, causal_output(name), ""),
                ]
            ] + [subprocess.CompletedProcess([], 0, listing([names[3] + "_longer"]), "")]
            with self.assertRaises(ValueError):
                shards.run_supervise_causal_diagnostics(["harness"], names)
            self.assertEqual(run.call_count, 7)
            self.assertNotIn(["harness", "--exact", "--", names[3]],
                             [call.args[0] for call in run.call_args_list])

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


        names = shards.SUPERVISE_CAUSAL_DIAGNOSTICS
        with mock.patch.object(shards.subprocess, "Popen") as popen, mock.patch.object(shards.os, "killpg", create=True) as killpg, mock.patch.object(shards.subprocess, "run") as run, mock.patch("sys.stdout", io.StringIO()), mock.patch("sys.stderr", io.StringIO()):
            run.side_effect = [
                result for name in names for result in [
                    subprocess.CompletedProcess([], 0, listing([name]), ""),
                    subprocess.CompletedProcess([], 0, causal_output(name), ""),
                ]
            ]
            self.assertEqual(shards.run_supervise_causal_diagnostics(["harness"], names), 0)
            self.assertEqual(run.call_count, 8)
            popen.assert_not_called()
            killpg.assert_not_called()
            for call in run.call_args_list:
                self.assertNotIn("timeout", call.kwargs)
                self.assertNotIn("start_new_session", call.kwargs)
                self.assertNotIn("--nocapture", call.args[0])
                self.assertNotIn("--ignored", call.args[0])

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
                "    if '--shard' in sys.argv:\n"
                "        shard = sys.argv[sys.argv.index('--shard') + 1]\n"
                "        print('--test\\nmerge_cli' if shard == 'merge' else '--bench\\ncoordination')\n"
                "    else:\n"
                "        print('--lib' if sys.argv[2] == 'lib' else '--doc' if sys.argv[2] == 'doc' else '--bin\\nmaco')\n",
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
            result = subprocess.run(
                ["bash", str(wrapper), "doc"], capture_output=True, text=True
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.splitlines(), ["cargo", "test", "--locked", "--doc"])
            for shard, flags in (("merge", ["--test", "merge_cli"]), ("other", ["--bench", "coordination"])):
                result = subprocess.run(
                    ["bash", str(wrapper), "non-lib", shard], capture_output=True, text=True
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.splitlines(), ["cargo", "test", "--locked", *flags])
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
        mod budget { #[test] fn new_budget_body() {} }
        mod licensed_breakage { #[test] fn new_licensed_body() {} }
        mod scheduler {
            // Empty body verifies wrapper selection only, not concurrency semantics.
            #[test] fn claim_and_semantic_block_conflicts_fail_only_the_affected_assignment() {}
        }
        mod plan_runtime {
            #[test] fn no_override_selects_single_slug_effort_profile_for_every_role() {}
            #[test] fn new_runtime_body() {}
        }
    }
    mod scheduler {
        mod decomposition_tests {
            // Empty body verifies wrapper selection only, not budget semantics.
            #[test] fn budget_degrade_ladder_applies_worker_model_effort_fanout_then_halts() {}
        }
    }
    mod assignment_execution {
        mod decomposition_tests {
            #[test] fn auditor_runtime_override_preserves_active_heterogeneous_lens_contract() {}
            #[test] fn new_decomposition_body() {}
        }
        mod bound_parent_turn_tests {
            // Empty body verifies wrapper selection only, not evidence semantics.
            #[test] fn bound_nested_evidence_rejects_forged_widened_failed_and_cancelled_results() {}
            #[test] fn new_bound_parent_body() {}
        }
        mod managed_parent_controller_tests {
            // Empty body verifies wrapper selection only, not worker cleanup semantics.
            #[test] fn managed_cycle_isolated_workers_overlap_and_import_exact_union() {}
            #[test] fn new_managed_parent_body() {}
        }
        mod nested_driver_tests { #[test] fn new_nested_body() {} }
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
mod external_agent { #[test] fn new_external_body() {} }
mod worktree { #[test] fn new_worktree_body() {} }
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
            self.assertEqual(len(inventory), 29)
            partitions = shards.partition_inventory(inventory)
            observed = []
            for shard, names in partitions.items():
                observed.extend(shards.enumerate_tests(runner, names))
                result = subprocess.run(shards.test_command(runner, names), capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                if shard == "supervise-core":
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
                self.assertIn('"total": 29', result.stdout)


if __name__ == "__main__":
    unittest.main()
