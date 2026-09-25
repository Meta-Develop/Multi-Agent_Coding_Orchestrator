#!/usr/bin/env python3
"""Run an exact, enumerated subset of the root package's library test harness."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Sequence

SHARDS = ("autopilot", "supervise", "rest")


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


def partition_inventory(names: Sequence[str]) -> dict[str, list[str]]:
    if not names or len(names) != len(set(names)):
        raise ValueError("library inventory must be nonempty and unique")
    partitions: dict[str, list[str]] = {shard: [] for shard in SHARDS}
    for name in sorted(names):
        # Match the root module, not an arbitrary substring in a test name.
        owner = next(
            (shard for shard in SHARDS[:-1] if name.startswith(f"{shard}::")),
            "rest",
        )
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
    return parse_inventory(result.stdout)


def run_shard(runner: Sequence[str], shard: str) -> int:
    if shard not in SHARDS:
        raise ValueError(f"unknown library shard: {shard}")
    inventory = enumerate_tests(runner)
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
            },
            sort_keys=True,
        ),
        flush=True,
    )
    return subprocess.run(command, check=False).returncode


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("shard", choices=SHARDS)
    parser.add_argument("--manifest-dir", type=Path, default=Path("."))
    args = parser.parse_args(argv)
    root = args.manifest_dir.resolve()
    # The partition wrapper verifies the existing full Cargo metadata target
    # contract before entering the unchanged delegated systemd runner.
    os.chdir(root)
    # Keep Cargo's normal test environment and package-root working directory.
    # Enumeration builds the harness once; later calls reuse that same build.
    return run_shard(["cargo", "test", "--locked", "--lib", "--"], args.shard)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, subprocess.CalledProcessError) as error:
        sys.exit(f"library shard refused: {error}")
