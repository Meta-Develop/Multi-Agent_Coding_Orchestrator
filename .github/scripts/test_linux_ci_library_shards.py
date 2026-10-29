#!/usr/bin/env python3
"""Pure unit coverage for Linux CI library shard partition and inventory."""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


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
             "supervise-nested", "supervise-fixtures", "external-agent", "worktree", "rest"),
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
                                              "supervise-parent", "supervise-nested")
                                for n in parts[key]), old_core)
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

    def test_empty_and_duplicate_inventory_refuse(self) -> None:
        with self.assertRaises(ValueError):
            self.shards.partition_inventory([])
        with self.assertRaises(ValueError):
            self.shards.partition_inventory(["a::b", "a::b"])

    def test_empty_selected_test_command_refuses(self) -> None:
        with self.assertRaises(ValueError):
            self.shards.test_command(["cargo", "test", "--locked", "--lib", "--"], [])

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
