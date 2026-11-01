#!/usr/bin/env python3
"""Run an exact, enumerated subset of the root package's library test harness."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Sequence

SHARDS = (
    "autopilot", "supervise-core", "supervise-bound", "supervise-decomposition", "supervise-parent",
    "supervise-nested", "supervise-fixtures", "supervise-fixtures-budget",
    "supervise-fixtures-licensed", "supervise-fixtures-runtime", "external-agent", "worktree", "rest",
)
# Balance the former 2,285-second hosted job using CT101's full fixture run:
# approximately 824/668/875/755 summed test seconds (three test threads).
# Keep related modules together; new modules stay in supervise-fixtures.
FIXTURE_MODULE_SHARDS = {
    "budget": "supervise-fixtures-budget",
    "prompts_gates": "supervise-fixtures-budget",
    "licensed_breakage": "supervise-fixtures-licensed",
    "plan_runtime": "supervise-fixtures-runtime",
    "qualification_handoff": "supervise-fixtures-runtime",
    "reaudit": "supervise-fixtures-runtime",
    "run_artifacts": "supervise-fixtures-runtime",
}
REST_SAFETY_PREFLIGHTS = (
    "process_runner::tests::gemini_online_profile_projects_only_the_trusted_resolver_file",
    "runtime_adapter::cursor_managed_parent::tests::offline_check_failure_diagnostic_keeps_untrusted_output_private",
    "runtime_adapter::cursor_managed_parent::tests::assignment_authority_admits_exact_write_read_and_parent_owned_check",
)
SAFETY_PREFLIGHTS = {
    "rest": REST_SAFETY_PREFLIGHTS,
    "supervise-core": (
        "supervise::selection_bridge::tests::account_observe_unknown_models_fail_closed",
        "supervise::selection_bridge::tests::automatic_empty_role_models_resolve_all_roles_from_eligible_catalog",
        "supervise::assignment_execution::attached_parent_capture_tests::attached_capture_bookkeeping_and_shutdown_errors_retain_owners",
    ),
}


SUPERVISE_DIAGNOSTICS = (
    "supervise::tests::plan_runtime::no_override_selects_single_slug_effort_profile_for_every_role",
    "supervise::assignment_execution::decomposition_tests::auditor_runtime_override_preserves_active_heterogeneous_lens_contract",
    "supervise::selection_bridge::tests::runtime_reselection_returns_matching_executable_runtime_binding",
)
# Per-command diagnostic ceiling; not an acceptance threshold.
# Each of three cases gets one inventory query and at most one body, with no retry.
SUPERVISE_DIAGNOSTIC_TIMEOUT_SECONDS = 30

SUPERVISE_CAUSAL_DIAGNOSTICS = (
    "supervise::assignment_execution::bound_parent_turn_tests::bound_nested_evidence_rejects_forged_widened_failed_and_cancelled_results",
    "supervise::assignment_execution::managed_parent_controller_tests::managed_cycle_isolated_workers_overlap_and_import_exact_union",
    "supervise::scheduler::decomposition_tests::budget_degrade_ladder_applies_worker_model_effort_fanout_then_halts",
    "supervise::tests::scheduler::claim_and_semantic_block_conflicts_fail_only_the_affected_assignment",
)


def parse_inventory(output: str) -> list[str]:
    names: list[str] = []
    for line in output.splitlines():
        if not line:
            continue
        match = re.fullmatch(r"(.+): (?:test|benchmark)", line)
        if not match:
            raise ValueError(f"unexpected libtest inventory line: {line!r}")
        names.append(match[1])
    if len(names) != len(set(names)):
        raise ValueError("duplicate names in libtest inventory")
    return sorted(names)


def expected_supervise_group(name: str) -> str:
    if name.startswith("supervise::tests::"):
        return "supervise-fixtures"
    if name.startswith("supervise::"):
        return "supervise-core"
    raise ValueError(f"mandatory diagnostic is not a supervise case: {name}")


def validate_mandatory_supervise_ownership(
    inventory: Sequence[str], partitions: dict[str, list[str]]
) -> None:
    assigned: dict[str, str] = {}
    for shard, group in partitions.items():
        for name in group:
            if name in assigned:
                raise ValueError(f"duplicate shard ownership for {name}")
            assigned[name] = shard
    for name in (*SUPERVISE_DIAGNOSTICS, *SUPERVISE_CAUSAL_DIAGNOSTICS):
        if name not in assigned:
            raise ValueError(
                f"mandatory supervise diagnostic missing from inventory: {name}"
            )
        owner = assigned[name]
        expected = expected_supervise_group(name)
        if owner != expected:
            raise ValueError(
                f"mandatory supervise diagnostic {name} owned by {owner}, expected {expected}"
            )


def partition_inventory(names: Sequence[str]) -> dict[str, list[str]]:
    if not names or len(names) != len(set(names)):
        raise ValueError("library inventory must be nonempty and unique")
    partitions: dict[str, list[str]] = {shard: [] for shard in SHARDS}
    standalone = {
        *SAFETY_PREFLIGHTS["supervise-core"],
        *SUPERVISE_DIAGNOSTICS, *SUPERVISE_CAUSAL_DIAGNOSTICS,
    }
    for name in sorted(names):
        # Match the root module, not an arbitrary substring in a test name.
        if name.startswith("autopilot::"):
            owner = "autopilot"
        elif name.startswith("supervise::tests::"):
            owner = "supervise-fixtures"
            if name not in standalone:
                module = name.removeprefix("supervise::tests::").split("::", 1)[0]
                owner = FIXTURE_MODULE_SHARDS.get(module, owner)
        elif name.startswith("supervise::"):
            owner = "supervise-core"
            # Keep the existing standalone preflights/diagnostics with their
            # original owners; split the remaining slow assignment bodies.
            if name not in standalone:
                if name.startswith("supervise::assignment_execution::bound_parent_turn"):
                    owner = "supervise-bound"
                elif name.startswith("supervise::assignment_execution::decomposition_tests::"):
                    owner = "supervise-decomposition"
                elif name.startswith("supervise::assignment_execution::managed_parent_controller_tests::"):
                    owner = "supervise-parent"
                elif name.startswith("supervise::assignment_execution::") and not name.startswith(
                    "supervise::assignment_execution::attached_parent_capture_tests::"
                ):
                    owner = "supervise-nested"
        elif name.startswith("external_agent::"):
            owner = "external-agent"
        elif name.startswith("worktree::"):
            owner = "worktree"
        else:
            owner = "rest"
        partitions[owner].append(name)
    flattened = [name for group in partitions.values() for name in group]
    if len(flattened) != len(set(flattened)) or set(flattened) != set(names):
        raise ValueError("library shards do not form a disjoint complete partition")
    return partitions


def test_command(runner: Sequence[str], names: Sequence[str]) -> list[str]:
    if not names:
        raise ValueError("refusing an empty shard (libtest would otherwise run everything)")
    return [*runner, "--exact", "--", *names]


def enumerate_tests(runner: Sequence[str], names: Sequence[str] | None = None) -> list[str]:
    command = [*runner, "--list", "--format", "terse"]
    if names is not None:
        command += test_command([], names)
    result = subprocess.run(command, check=True, capture_output=True, text=True)
    if result.stderr:
        print(result.stderr, end="", file=sys.stderr, flush=True)
    return parse_inventory(result.stdout)


def run_safety_preflights(runner: Sequence[str], selected: Sequence[str], shard: str) -> int:
    for name in SAFETY_PREFLIGHTS[shard]:
        if name not in selected or enumerate_tests(runner, [name]) != [name]:
            raise ValueError(f"safety preflight must select exactly one {shard} test: {name}")
        print(json.dumps({f"{shard}_safety_preflight": name}, sort_keys=True), flush=True)
        result = subprocess.run(
            [*runner, "--exact", "--nocapture", "--", name],
            check=False, capture_output=True, text=True,
        )
        print(result.stdout, end="", flush=True)
        print(result.stderr, end="", file=sys.stderr, flush=True)
        if result.returncode != 0:
            return result.returncode
        summaries = re.findall(
            r"^test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored; "
            r"(\d+) measured; \d+ filtered out; finished in .+$",
            result.stdout, re.MULTILINE,
        )
        if summaries != [("1", "0", "0", "0")]:
            raise ValueError(f"safety preflight did not execute exactly one nonignored test: {name}")
        if "skipping Nix-store-dependent Gemini online profile test" in result.stdout + result.stderr:
            raise ValueError(f"safety preflight returned through its missing-Nix skip: {name}")
    return 0


def _capture_supervise_diagnostic(command: Sequence[str]) -> subprocess.CompletedProcess[str]:
    # The inspected bodies create no processes. Cargo may own the libtest child,
    # so terminate this new session's process group, not only the Cargo wrapper.
    with subprocess.Popen(
        command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, text=True, start_new_session=True,
    ) as process:
        try:
            stdout, stderr = process.communicate(timeout=SUPERVISE_DIAGNOSTIC_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            stdout, stderr = process.communicate()
            return subprocess.CompletedProcess(command, 124, stdout, stderr)
        return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)


def run_supervise_diagnostics(runner: Sequence[str], selected: Sequence[str], cases: Sequence[str] | None = None) -> int:
    if cases is None:
        cases = SUPERVISE_DIAGNOSTICS
    if not cases:
        return 0
    failed = False
    for name in cases:
        print(json.dumps({"supervise_diagnostic": name}, sort_keys=True), flush=True)
        if name not in selected:
            print("supervise diagnostic refused: name absent from shard inventory", flush=True)
            failed = True
            continue
        try:
            inventory = _capture_supervise_diagnostic(
                [*runner, "--list", "--format", "terse", "--exact", "--", name]
            )
            print(inventory.stdout, end="", flush=True)
            print(inventory.stderr, end="", file=sys.stderr, flush=True)
            if inventory.returncode != 0 or parse_inventory(inventory.stdout) != [name]:
                print(json.dumps({"supervise_diagnostic_inventory_refused": name,
                                  "returncode": inventory.returncode}, sort_keys=True), flush=True)
                failed = True
                continue
            result = _capture_supervise_diagnostic(
                [*runner, "--exact", "--nocapture", "--", name]
            )
        except (OSError, ValueError) as error:
            print(json.dumps({"supervise_diagnostic_refused": name,
                              "error_kind": type(error).__name__}, sort_keys=True), flush=True)
            failed = True
            continue
        print(result.stdout, end="", flush=True)
        print(result.stderr, end="", file=sys.stderr, flush=True)
        summaries = re.findall(
            r"^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored; "
            r"(\d+) measured; \d+ filtered out; finished in .+$",
            result.stdout, re.MULTILINE,
        )
        expected = [("ok", "1", "0", "0", "0")] if result.returncode == 0 else [
            ("FAILED", "0", "1", "0", "0")
        ]
        single_body = summaries == expected
        print(json.dumps({"supervise_diagnostic_result": name,
                          "returncode": result.returncode,
                          "exactly_one_nonignored_body": single_body}, sort_keys=True), flush=True)
        failed = failed or result.returncode != 0 or not single_body
    return 1 if failed else 0



def run_supervise_causal_diagnostics(runner: Sequence[str], selected: Sequence[str], cases: Sequence[str] | None = None) -> int:
    # Natural completion only: the existing hosted-job limit bounds a hung case.
    # Aggregate completed one-body failures; malformed/infra outcomes fail closed.
    if cases is None:
        cases = SUPERVISE_CAUSAL_DIAGNOSTICS
    if not cases:
        return 0
    completed = []
    for name in cases:
        if name not in selected or enumerate_tests(runner, [name]) != [name]:
            raise ValueError(f"causal diagnostic must select exactly one supervise test: {name}")
        print(json.dumps({"supervise_causal_diagnostic": name}, sort_keys=True), flush=True)
        result = subprocess.run(
            [*runner, "--exact", "--", name],
            check=False, capture_output=True, text=True,
        )
        print(result.stdout, end="", flush=True)
        print(result.stderr, end="", file=sys.stderr, flush=True)
        summaries = re.findall(
            r"^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored; "
            r"(\d+) measured; \d+ filtered out; finished in .+$",
            result.stdout, re.MULTILINE,
        )
        bodies = re.findall(
            r"^test (.+) \.\.\. (ok|FAILED|ignored)$", result.stdout, re.MULTILINE,
        )
        summary_lines = [
            line for line in result.stdout.splitlines() if line.startswith("test result:")
        ]
        body_lines = [
            line for line in result.stdout.splitlines()
            if line.startswith("test ") and not line.startswith("test result:")
        ]
        # Accept the selected body's single libtest 60-second warning only before its result.
        if body_lines[:1] == [f"test {name} has been running for over 60 seconds"]:
            body_lines = body_lines[1:]
        terminal = (
            len(summary_lines) == 1 and len(body_lines) == 1
            and result.stdout.rstrip().splitlines()[-1:] == summary_lines
        )
        passed = (
            terminal and result.returncode == 0
            and summaries == [("ok", "1", "0", "0", "0")]
            and bodies == [(name, "ok")]
        )
        failed = (
            terminal and result.returncode == 101
            and summaries == [("FAILED", "0", "1", "0", "0")]
            and bodies == [(name, "FAILED")]
        )
        if not (passed or failed):
            raise ValueError(f"causal diagnostic lacks a genuine completed nonignored one-body result: {name}")
        completed.append({"name": name, "returncode": result.returncode,
                      "outcome": "PASS" if passed else "FAIL"})
        print(json.dumps({"supervise_causal_result": completed[-1]}, sort_keys=True), flush=True)
    status = int(any(case["outcome"] == "FAIL" for case in completed))
    print(json.dumps({"supervise_causal_cases": completed, "complete": True,
                      "broad_allowed": status == 0}, sort_keys=True), flush=True)
    return status

def run_shard(runner: Sequence[str], shard: str, list_only: bool = False) -> int:
    if shard not in SHARDS:
        raise ValueError(f"unknown library shard: {shard}")
    started = time.monotonic()
    inventory = enumerate_tests(runner)
    enumerated = time.monotonic()
    partitions = partition_inventory(inventory)
    selected = partitions[shard]
    command = test_command(runner, selected)
    # Verify libtest itself selects precisely these names using the execution
    # filters. Ignored tests remain listed, but keep libtest's default skip policy.
    observed = enumerate_tests(runner, selected)
    if observed != selected:
        raise ValueError("libtest selection differs from the assigned shard inventory")
    digest = hashlib.sha256("\n".join(inventory).encode("utf-8")).hexdigest()
    print(
        json.dumps(
            {
                "library_inventory_sha256": digest,
                "total": len(inventory),
                "shards": {key: len(value) for key, value in partitions.items()},
                "selected": shard,
                "compile_and_inventory_seconds": round(enumerated - started, 3),
                "selection_check_seconds": round(time.monotonic() - enumerated, 3),
            },
            sort_keys=True,
        ),
        flush=True,
    )
    if list_only:
        print(json.dumps({"selected": shard, "tests": selected}, sort_keys=True), flush=True)
        return 0
    if shard in SAFETY_PREFLIGHTS:
        preflight_status = run_safety_preflights(runner, selected, shard)
        if preflight_status != 0:
            return preflight_status
    if shard in ("supervise-core", "supervise-fixtures"):
        validate_mandatory_supervise_ownership(inventory, partitions)
        own_diagnostics = [name for name in SUPERVISE_DIAGNOSTICS if name in selected]
        own_causal = [name for name in SUPERVISE_CAUSAL_DIAGNOSTICS if name in selected]
        diagnostic_status = run_supervise_diagnostics(runner, selected, own_diagnostics)
        if diagnostic_status != 0:
            return diagnostic_status
        causal_status = run_supervise_causal_diagnostics(runner, selected, own_causal)
        if causal_status != 0:
            return causal_status
    started = time.monotonic()
    result = subprocess.run(command, check=False)
    print(json.dumps({"selected": shard, "test_seconds": round(time.monotonic() - started, 3),
                      "returncode": result.returncode}, sort_keys=True), flush=True)
    return result.returncode


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("shard", choices=SHARDS)
    parser.add_argument("--manifest-dir", type=Path, default=Path("."))
    parser.add_argument("--list", action="store_true", help="verify and print this shard's exact inventory without running bodies")
    args = parser.parse_args(argv)
    root = args.manifest_dir.resolve()
    # The partition wrapper verifies the existing full Cargo metadata target
    # contract before entering the unchanged delegated systemd runner.
    os.chdir(root)
    # Keep Cargo's normal test environment and package-root working directory.
    # Enumeration builds the harness once; later calls reuse that same build.
    return run_shard(["cargo", "test", "--locked", "--lib", "--"], args.shard, args.list)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, subprocess.CalledProcessError) as error:
        sys.exit(f"library shard refused: {error}")
