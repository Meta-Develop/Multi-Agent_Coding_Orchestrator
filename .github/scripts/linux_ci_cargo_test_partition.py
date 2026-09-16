#!/usr/bin/env python3
"""Derive disjoint Linux CI cargo test partitions from cargo metadata."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence

TESTABLE_KINDS = frozenset({"lib", "bin", "test", "bench", "example"})
SKIPPED_ONLY_KINDS = frozenset({"custom-build"})
TARGET_NAME_RE = re.compile(r"^[A-Za-z0-9_-]+$")


@dataclass(frozen=True)
class TestableTarget:
    kind: str
    name: str

    def key(self) -> tuple[str, str]:
        if self.kind == "lib":
            return ("lib", "")
        return (self.kind, self.name)

    def argv_tokens(self) -> tuple[str, ...]:
        if self.kind == "lib":
            return ("--lib",)
        return (f"--{self.kind}", self.name)


def validate_target_name(name: str) -> None:
    if not TARGET_NAME_RE.match(name):
        raise ValueError(f"unsafe cargo target name: {name!r}")


def collect_testable_targets(package: Mapping[str, object]) -> list[TestableTarget]:
    raw_targets = package.get("targets")
    if not isinstance(raw_targets, list):
        raise ValueError("package targets must be a list")

    collected: list[TestableTarget] = []
    seen_keys: set[tuple[str, str]] = set()

    for index, raw in enumerate(raw_targets):
        if not isinstance(raw, Mapping):
            raise ValueError(f"target entry {index} is not an object")

        kinds = raw.get("kind")
        if not isinstance(kinds, (list, tuple)) or not kinds:
            raise ValueError(f"target entry {index} has missing or empty kind")

        kinds_tuple = tuple(str(kind) for kind in kinds)

        if kinds_tuple == ("custom-build",):
            continue

        if "custom-build" in kinds_tuple:
            raise ValueError(f"target entry {index} mixes custom-build with other kinds")

        testable = [kind for kind in kinds_tuple if kind in TESTABLE_KINDS]
        unsupported = [
            kind for kind in kinds_tuple if kind not in TESTABLE_KINDS
        ]
        if unsupported:
            raise ValueError(
                f"unsupported target kinds {unsupported!r} on target entry {index}"
            )
        if len(testable) != 1:
            raise ValueError(
                f"ambiguous testable kinds {kinds_tuple!r} on target entry {index}"
            )

        kind = testable[0]
        name = str(raw.get("name", ""))
        if kind != "lib":
            validate_target_name(name)

        target = TestableTarget(kind=kind, name=name)
        key = target.key()
        if key in seen_keys:
            raise ValueError(f"duplicate metadata target key: {key!r}")
        seen_keys.add(key)
        collected.append(target)

    return sorted(collected, key=lambda item: item.key())


def load_root_package(manifest_dir: Path) -> Mapping[str, object]:
    manifest_path = (manifest_dir / "Cargo.toml").resolve()
    completed = subprocess.run(
        [
            "cargo",
            "metadata",
            "--no-deps",
            "--locked",
            "--format-version",
            "1",
        ],
        cwd=manifest_dir,
        check=False,
        capture_output=True,
    )
    if completed.returncode != 0:
        stderr = completed.stderr.decode("utf-8", errors="replace")
        stdout = completed.stdout.decode("utf-8", errors="replace")
        sys.stderr.write(stderr or stdout)
        raise SystemExit(completed.returncode)
    metadata = json.loads(completed.stdout.decode("utf-8"))
    for package in metadata.get("packages", []):
        if Path(str(package["manifest_path"])).resolve() == manifest_path:
            return package
    raise SystemExit(f"no metadata package for {manifest_path}")


def partition_argv(targets: Sequence[TestableTarget], partition: str) -> list[str]:
    if partition == "lib":
        lib_targets = [target for target in targets if target.kind == "lib"]
        if len(lib_targets) != 1:
            raise ValueError("expected exactly one library target in metadata")
        return list(lib_targets[0].argv_tokens())
    if partition == "non-lib":
        argv: list[str] = []
        for target in targets:
            if target.kind == "lib":
                continue
            argv.extend(target.argv_tokens())
        return argv
    raise ValueError(f"unknown partition: {partition}")


def argv_to_keys(argv: Sequence[str]) -> list[tuple[str, str]]:
    index = 0
    keys: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    while index < len(argv):
        token = argv[index]
        if token == "--lib":
            key = ("lib", "")
            index += 1
        elif token.startswith("--"):
            kind = token[2:]
            if kind not in {"bin", "test", "bench", "example"}:
                raise ValueError(f"unsupported cargo test flag: {token}")
            index += 1
            if index >= len(argv):
                raise ValueError(f"missing name for {token}")
            name = argv[index]
            validate_target_name(name)
            key = (kind, name)
            index += 1
        else:
            raise ValueError(f"unexpected argv token: {token!r}")

        if key in seen:
            raise ValueError(f"duplicate partition target key: {key!r}")
        seen.add(key)
        keys.append(key)
    return keys


def verify_partition(targets: Sequence[TestableTarget]) -> None:
    expected_keys = [target.key() for target in targets]
    expected = set(expected_keys)
    if len(expected_keys) != len(expected):
        raise ValueError("duplicate metadata target keys in collected targets")

    lib_keys = argv_to_keys(partition_argv(targets, "lib"))
    non_lib_keys = argv_to_keys(partition_argv(targets, "non-lib"))
    lib_set = set(lib_keys)
    non_lib_set = set(non_lib_keys)
    if lib_set & non_lib_set:
        raise ValueError("lib and non-lib partitions overlap")
    union = lib_set | non_lib_set
    if union != expected:
        missing = sorted(expected - union)
        extra = sorted(union - expected)
        raise ValueError(
            "partition argv does not cover metadata targets "
            f"(missing={missing!r}, extra={extra!r})"
        )


def emit_argv(argv: Sequence[str]) -> None:
    for token in argv:
        sys.stdout.write(f"{token}\n")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "command",
        choices=("verify", "argv"),
        help="verify full metadata coverage or emit argv lines for one partition",
    )
    parser.add_argument(
        "partition",
        nargs="?",
        choices=("lib", "non-lib"),
        help="required for argv",
    )
    parser.add_argument(
        "--manifest-dir",
        type=Path,
        default=Path("."),
        help="directory containing the root Cargo.toml",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    manifest_dir = args.manifest_dir.resolve()
    package = load_root_package(manifest_dir)
    targets = collect_testable_targets(package)

    if args.command == "verify":
        verify_partition(targets)
        return 0

    if args.partition is None:
        parser.error("argv requires a partition")
    partition_argv_tokens = partition_argv(targets, args.partition)
    if args.partition == "non-lib" and not partition_argv_tokens:
        sys.stderr.write("non-lib partition is empty\n")
        return 1
    emit_argv(partition_argv_tokens)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
