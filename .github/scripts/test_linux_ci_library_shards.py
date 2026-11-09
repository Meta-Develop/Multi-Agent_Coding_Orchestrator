#!/usr/bin/env python3
"""Pure unit coverage for Linux CI library shard partition and inventory."""

from __future__ import annotations

import importlib.util
import io
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock


def load_library_shards():
    path = Path(__file__).with_name("linux_ci_library_shards.py")
    spec = importlib.util.spec_from_file_location("linux_ci_library_shards", path)
    module = importlib.util.module_from_spec(spec)
    assert spec is not None and spec.loader is not None
    spec.loader.exec_module(module)
    return module


class LinuxCiLibraryShardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.shards = load_library_shards()

    def test_shard_names(self) -> None:
        self.assertEqual(
            self.shards.SHARDS,
            ("autopilot", "supervise-core", "supervise-bound", "supervise-decomposition", "supervise-parent",
             "supervise-nested-driver", "supervise-nested", "supervise-fixtures", "supervise-fixtures-budget",
             "supervise-fixtures-licensed", "supervise-fixtures-runtime", "external-agent", "worktree", "rest"),
        )

    def test_mixed_inventory_disjoint_complete_union(self) -> None:
        inventory = [
            "autopilot::alpha",
            "supervise::assignment_execution::beta",
            "supervise::tests::gamma",
            "runtime_adapter::delta",
        ]
        parts = self.shards.partition_inventory(inventory)
        self.assertEqual(parts["autopilot"], ["autopilot::alpha"])
        self.assertEqual(
            parts["supervise-nested"], ["supervise::assignment_execution::beta"]
        )
        self.assertEqual(parts["supervise-fixtures"], ["supervise::tests::gamma"])
        self.assertEqual(parts["rest"], ["runtime_adapter::delta"])
        flattened = [name for group in parts.values() for name in group]
        self.assertEqual(sorted(flattened), sorted(inventory))
        self.assertEqual(len(flattened), len(set(flattened)))

    def test_new_shards_refine_the_old_partition_without_loss_or_overlap(self) -> None:
        inventory = [
            *self.shards.SUPERVISE_DIAGNOSTICS,
            *self.shards.SUPERVISE_CAUSAL_DIAGNOSTICS,
            *self.shards.SAFETY_PREFLIGHTS["supervise-core"],
            *self.shards.REST_SAFETY_PREFLIGHTS,
            "autopilot::new", "supervise::tests::new", "supervise::future::new",
            "supervise::assignment_execution::decomposition_tests::new",
            "supervise::assignment_execution::managed_parent_controller_tests::new",
            "supervise::assignment_execution::nested_worker::new",
            "supervise::assignment_execution::nested_driver_tests::new",
            "supervise::assignment_execution::worker_dispatch_limits_tests::new",
            "supervise::assignment_execution::isolated_worker_evidence_tests::new",
            "supervise::assignment_execution::messaging_ipc_tests::new",
            "supervise::assignment_execution::managed_parent_process_tests::new",
            "supervise::assignment_execution::future_nested::new",
            "supervise::assignment_execution::attached_parent_capture_tests::new",
            "supervise::assignment_execution::bound_parent_turn_tests::new",
            "external_agent::new", "worktree::new", "future_module::new",
            "future::external_agent::lookalike", "worktree_extra::lookalike",
        ]
        inventory = sorted(set(inventory))
        parts = self.shards.partition_inventory(inventory)
        self.assertEqual(parts, self.shards.partition_inventory(list(reversed(inventory))))
        old_core = sorted(n for n in inventory if n.startswith("supervise::")
                          and not n.startswith("supervise::tests::"))
        old_rest = sorted(n for n in inventory if not n.startswith(("autopilot::", "supervise::")))
        self.assertEqual(sorted(n for key in ("supervise-core", "supervise-bound", "supervise-decomposition",
                                              "supervise-parent", "supervise-nested-driver", "supervise-nested")
                                for n in parts[key]), old_core)
        for prefix in self.shards.NESTED_DRIVER_PREFIXES:
            self.assertIn(f"{prefix}new", parts["supervise-nested-driver"])
        self.assertIn("supervise::assignment_execution::managed_parent_process_tests::new", parts["supervise-nested"])
        self.assertIn("supervise::assignment_execution::nested_worker::new", parts["supervise-nested"])
        self.assertIn("supervise::assignment_execution::future_nested::new", parts["supervise-nested"])
        self.assertEqual(sorted(n for key in ("external-agent", "worktree", "rest")
                                for n in parts[key]), old_rest)
        flattened = [n for group in parts.values() for n in group]
        self.assertEqual(sorted(flattened), inventory)
        self.assertEqual(len(flattened), len(set(flattened)))
        for shard, names in self.shards.SAFETY_PREFLIGHTS.items():
            self.assertTrue(set(names) <= set(parts[shard]))
        self.shards.validate_mandatory_supervise_ownership(inventory, parts)

    def test_lookalike_substrings_go_to_rest(self) -> None:
        inventory = [
            "host::autopilot::lookalike",
            "xsupervise::tests::lookalike",
            "process_runner::supervise::nested",
        ]
        parts = self.shards.partition_inventory(inventory)
        self.assertEqual(parts["rest"], sorted(inventory))
        self.assertEqual(parts["autopilot"], [])
        self.assertEqual(parts["supervise-core"], [])
        self.assertEqual(parts["supervise-fixtures"], [])

    def test_fixture_split_preserves_diagnostics_and_future_modules(self) -> None:
        inventory = [
            *self.shards.SUPERVISE_DIAGNOSTICS,
            *self.shards.SUPERVISE_CAUSAL_DIAGNOSTICS,
            "supervise::tests::budget::new",
            "supervise::tests::prompts_gates::new",
            "supervise::tests::licensed_breakage::new",
            "supervise::tests::mixed_runtime::new",
            "supervise::tests::plan_runtime::new",
            "supervise::tests::qualification_handoff::new",
            "supervise::tests::reaudit::new",
            "supervise::tests::run_artifacts::new",
            "supervise::tests::future_module::new",
        ]
        parts = self.shards.partition_inventory(inventory)
        self.shards.validate_mandatory_supervise_ownership(inventory, parts)
        for module, shard in self.shards.FIXTURE_MODULE_SHARDS.items():
            self.assertIn(f"supervise::tests::{module}::new", parts[shard])
        self.assertIn("supervise::tests::future_module::new", parts["supervise-fixtures"])
        self.assertCountEqual([n for group in parts.values() for n in group], inventory)

    def test_empty_and_duplicate_inventory_refuse(self) -> None:
        with self.assertRaises(ValueError):
            self.shards.partition_inventory([])
        with self.assertRaises(ValueError):
            self.shards.partition_inventory(["a::b", "a::b"])

    def test_empty_selected_test_command_refuses(self) -> None:
        with self.assertRaises(ValueError):
            self.shards.test_command(["cargo", "test", "--locked", "--lib", "--"], [])

    def test_only_nested_shard_streams_all_filters_and_preserves_failure_exit(self) -> None:
        runner = ["cargo", "test", "--locked", "--lib", "--"]
        inventory = sorted({
            *self.shards.SUPERVISE_DIAGNOSTICS,
            *self.shards.SUPERVISE_CAUSAL_DIAGNOSTICS,
            *self.shards.SAFETY_PREFLIGHTS["supervise-core"],
            *self.shards.REST_SAFETY_PREFLIGHTS,
            "autopilot::keep", "supervise::core::keep",
            "supervise::assignment_execution::bound_parent_turn_tests::keep",
            "supervise::assignment_execution::decomposition_tests::keep",
            "supervise::assignment_execution::managed_parent_controller_tests::keep",
            "supervise::assignment_execution::nested_driver_tests::keep",
            "supervise::assignment_execution::managed_parent_correction::tests::keep",
            "supervise::assignment_execution::managed_parent_outer_tests::keep",
            "supervise::assignment_execution::managed_parent_outer_tests::production_journal_cli_helper",
            "supervise::tests::keep", "supervise::tests::budget::keep",
            "supervise::tests::licensed_breakage::keep",
            "supervise::tests::plan_runtime::keep",
            "external_agent::keep", "worktree::keep", "future_module::keep",
        })
        parts = self.shards.partition_inventory(inventory)
        executed = []
        for shard, selected in parts.items():
            with (
                self.subTest(shard=shard),
                redirect_stdout(io.StringIO()),
                mock.patch.object(self.shards, "enumerate_tests", side_effect=[inventory, selected]) as enumerate_tests,
                mock.patch.object(self.shards, "run_safety_preflights", return_value=0),
                mock.patch.object(self.shards, "run_supervise_diagnostics", return_value=0),
                mock.patch.object(self.shards, "run_supervise_causal_diagnostics", return_value=0),
                mock.patch.object(self.shards.subprocess, "run") as run,
            ):
                run.return_value.returncode = 101
                self.assertEqual(self.shards.run_shard(runner, shard), 101)
                self.assertEqual(enumerate_tests.call_args_list, [
                    mock.call(runner), mock.call(runner, selected),
                ])
                options = ["--nocapture", "--exact"] if shard == "supervise-nested" else ["--exact"]
                command = run.call_args.args[0]
                executed.extend(command[command.index("--", len(runner)) + 1:])
                run.assert_called_once_with([*runner, *options, "--", *selected], check=False)
        self.assertCountEqual(executed, inventory)
        self.assertEqual(len(executed), len(set(executed)))
        self.assertEqual(runner, ["cargo", "test", "--locked", "--lib", "--"])

    def test_inventory_parsing_duplicate_and_malformed(self) -> None:
        with self.assertRaises(ValueError):
            self.shards.parse_inventory("alpha::t: test\nalpha::t: test\n")
        with self.assertRaises(ValueError):
            self.shards.parse_inventory("this is not inventory\n")

    def test_mandatory_diagnostics_missing_from_inventory_rejected(self) -> None:
        inventory = ["autopilot::a", "supervise::core::b", "other::c"]
        parts = self.shards.partition_inventory(inventory)
        with self.assertRaises(ValueError):
            self.shards.validate_mandatory_supervise_ownership(inventory, parts)

    def test_mandatory_diagnostics_wrong_ownership_rejected(self) -> None:
        name = self.shards.SUPERVISE_DIAGNOSTICS[0]
        inventory = [name, "autopilot::keep"]
        parts = {
            "autopilot": ["autopilot::keep"],
            "supervise-core": [],
            "supervise-fixtures": [],
            "rest": [name],
        }
        with self.assertRaises(ValueError):
            self.shards.validate_mandatory_supervise_ownership(inventory, parts)

    def test_per_shard_diagnostics_cover_mandatory_cases_exactly_once(self) -> None:
        extra = ["autopilot::keep", "runtime_adapter::keep"]
        inventory = [
            *self.shards.SUPERVISE_DIAGNOSTICS,
            *self.shards.SUPERVISE_CAUSAL_DIAGNOSTICS,
            *extra,
        ]
        parts = self.shards.partition_inventory(inventory)
        self.shards.validate_mandatory_supervise_ownership(inventory, parts)
        owned: list[str] = []
        for shard in ("supervise-core", "supervise-fixtures"):
            selected = set(parts[shard])
            owned.extend(n for n in self.shards.SUPERVISE_DIAGNOSTICS if n in selected)
            owned.extend(
                n for n in self.shards.SUPERVISE_CAUSAL_DIAGNOSTICS if n in selected
            )
        mandatory = [
            *self.shards.SUPERVISE_DIAGNOSTICS,
            *self.shards.SUPERVISE_CAUSAL_DIAGNOSTICS,
        ]
        self.assertEqual(sorted(owned), sorted(mandatory))
        self.assertEqual(len(owned), len(set(owned)))
        self.assertEqual(
            self.shards.SAFETY_PREFLIGHTS["supervise-core"],
            (
                "supervise::selection_bridge::tests::account_observe_unknown_models_fail_closed",
                "supervise::selection_bridge::tests::automatic_empty_role_models_resolve_all_roles_from_eligible_catalog",
                "supervise::assignment_execution::attached_parent_capture_tests::attached_capture_bookkeeping_and_shutdown_errors_retain_owners",
            ),
        )
        self.assertNotIn("supervise", self.shards.SAFETY_PREFLIGHTS)


if __name__ == "__main__":
    unittest.main()
