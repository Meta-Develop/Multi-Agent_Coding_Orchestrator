#!/usr/bin/env python3
"""Derive disjoint Linux CI cargo test partitions from cargo metadata."""

from __future__ import annotations

import argparse
from collections import Counter
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
NON_LIB_SHARDS = ("merge", "other")
MERGE_TEST_TARGETS = frozenset({"merge_cli", "pr_issue_cli"})


@dataclass(frozen=True)
class TestableTarget:
    kind: str
    name: str

    def key(self) -> tuple[str, str]:
        if self.kind in {"lib", "doc"}:
            return (self.kind, "")
        return (self.kind, self.name)

    def argv_tokens(self) -> tuple[str, ...]:
        if self.kind in {"lib", "doc"}:
            return (f"--{self.kind}",)
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
        if kind == "lib":
            doctest = raw.get("doctest", True)
            if not isinstance(doctest, bool):
                raise ValueError("library doctest metadata must be a boolean")
            if doctest:
                # --lib never runs rustdoc's tests; they need a separate owner.
                collected.append(TestableTarget(kind="doc", name=name))

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


def partition_argv(
    targets: Sequence[TestableTarget], partition: str, shard: str | None = None
) -> list[str]:
    if shard is not None and (partition != "non-lib" or shard not in NON_LIB_SHARDS):
        raise ValueError(f"invalid {partition} shard: {shard}")
    if partition in {"lib", "doc"}:
        selected = [target for target in targets if target.kind == partition]
        if partition == "lib" and len(selected) != 1:
            raise ValueError("expected exactly one library target in metadata")
        if len(selected) > 1:
            raise ValueError(f"expected at most one {partition} target in metadata")
        return list(selected[0].argv_tokens()) if selected else []
    if partition == "non-lib":
        argv: list[str] = []
        for target in targets:
            if target.kind in {"lib", "doc"}:
                continue
            owner = "merge" if target.kind == "test" and target.name in MERGE_TEST_TARGETS else "other"
            if shard is not None and owner != shard:
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
        if token in {"--lib", "--doc"}:
            key = (token[2:], "")
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
    doc_keys = argv_to_keys(partition_argv(targets, "doc"))
    non_lib_keys = argv_to_keys(partition_argv(targets, "non-lib"))
    lib_set = set(lib_keys)
    doc_set = set(doc_keys)
    non_lib_set = set(non_lib_keys)
    if lib_set & non_lib_set or doc_set & (lib_set | non_lib_set):
        raise ValueError("lib, doc and non-lib partitions overlap")
    union = lib_set | doc_set | non_lib_set
    if union != expected:
        missing = sorted(expected - union)
        extra = sorted(union - expected)
        raise ValueError(
            "partition argv does not cover metadata targets "
            f"(missing={missing!r}, extra={extra!r})"
        )
    sharded_keys = [
        key for shard in NON_LIB_SHARDS
        for key in argv_to_keys(partition_argv(targets, "non-lib", shard))
    ]
    if len(sharded_keys) != len(set(sharded_keys)) or set(sharded_keys) != non_lib_set:
        raise ValueError("non-lib shards do not form a disjoint complete partition")


def parse_test_listing(output: str) -> Counter[tuple[str, str]]:
    """Keep occurrences: distinct integration binaries can use the same name."""
    result: Counter[tuple[str, str]] = Counter()
    for line in output.splitlines():
        if not line or re.fullmatch(r"\d+ tests?, \d+ benchmarks?", line):
            continue
        match = re.fullmatch(r"(.+): (test|benchmark)", line)
        if match is None:
            raise ValueError(f"unexpected Cargo test listing line: {line!r}")
        result[(match[2], match[1])] += 1
    return result


def verify_test_inventory(
    full: Counter[tuple[str, str]],
    partitions: Mapping[str, Counter[tuple[str, str]]],
) -> dict[str, object]:
    combined: Counter[tuple[str, str]] = Counter()
    for selected in partitions.values():
        combined.update(selected)
    missing = full - combined
    extra = combined - full
    # Bare cargo test omits explicit Criterion bench targets. Retain that
    # additional coverage, but never tolerate an extra/duplicate test body.
    extra_tests = Counter({key: count for key, count in extra.items() if key[0] != "benchmark"})
    if missing or extra_tests:
        raise ValueError(
            f"full test inventory differs from partitions (missing={missing!r}, extra={extra_tests!r})"
        )
    return {
        "full_tests": sum(count for (kind, _), count in full.items() if kind == "test"),
        "partition_tests": sum(count for (kind, _), count in combined.items() if kind == "test"),
        "partitions": {key: sum(value.values()) for key, value in partitions.items()},
        "additional_benchmarks": sorted(name for (_, name) in extra.elements()),
        "missing": [], "extra_tests": [],
    }


def verify_full_inventory(targets: Sequence[TestableTarget], manifest_dir: Path) -> dict[str, object]:
    # Import locally so metadata-only verification does not need a test harness.
    import linux_ci_library_shards as library

    def listing(args: Sequence[str], test_args: Sequence[str] = ()) -> str:
        result = subprocess.run(
            ["cargo", "test", "--locked", *args, "--", "--list", *test_args],
            cwd=manifest_dir, check=True, capture_output=True, text=True,
        )
        if result.stderr:
            print(result.stderr, end="", file=sys.stderr, flush=True)
        return result.stdout

    verify_partition(targets)
    full = parse_test_listing(listing([]))
    inventory = library.parse_inventory(listing(["--lib"], ["--format", "terse"]))
    groups = library.partition_inventory(inventory)
    library.validate_mandatory_supervise_ownership(inventory, groups)
    partitions = {}
    for shard, names in groups.items():
        selected = parse_test_listing(listing(["--lib"], library.test_command([], names)))
        if selected != Counter(("test", name) for name in names):
            raise ValueError(f"library shard selection differs from ownership: {shard}")
        partitions[shard] = selected
    for shard in NON_LIB_SHARDS:
        partitions[f"non-lib-{shard}"] = parse_test_listing(listing(partition_argv(targets, "non-lib", shard)))
    doc_args = partition_argv(targets, "doc")
    partitions["doc"] = parse_test_listing(listing(doc_args)) if doc_args else Counter()
    result = verify_test_inventory(full, partitions)
    result["doctests"] = sorted(name for (_, name) in partitions["doc"].elements())
    return result


def emit_argv(argv: Sequence[str]) -> None:
    for token in argv:
        sys.stdout.write(f"{token}\n")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "command",
        choices=("verify", "verify-inventory", "argv"),
        help="verify metadata or full test inventory, or emit argv for one partition",
    )
    parser.add_argument(
        "partition",
        nargs="?",
        choices=("lib", "non-lib", "doc"),
        help="required for argv",
    )
    parser.add_argument(
        "--shard", choices=NON_LIB_SHARDS,
        help="optional non-lib target shard; omission retains the complete non-lib partition",
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
    if args.command == "verify-inventory":
        print(json.dumps(verify_full_inventory(targets, manifest_dir), sort_keys=True))
        return 0

    if args.partition is None:
        parser.error("argv requires a partition")
    partition_argv_tokens = partition_argv(targets, args.partition, args.shard)
    if args.partition == "non-lib" and not partition_argv_tokens:
        sys.stderr.write("non-lib partition is empty\n")
        return 1
    emit_argv(partition_argv_tokens)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
