#!/usr/bin/env python3
"""Fail when a consuming Cargo.lock is incompatible with account-manager/core."""

from __future__ import annotations

import argparse
import subprocess
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence


CORE_PACKAGE = "coding-agent-manager"
CORE_MANIFEST = Path("account-manager/core/Cargo.toml")


@dataclass(frozen=True)
class Consumer:
    name: str
    lockfile: Path
    cargo_metadata_args: tuple[str, ...]


CONSUMERS = (
    Consumer("root workspace", Path("Cargo.lock"), ()),
    Consumer(
        "desktop workspace",
        Path("account-manager/src-tauri/Cargo.lock"),
        ("--manifest-path", "account-manager/src-tauri/Cargo.toml"),
    ),
)


@dataclass(frozen=True)
class Version:
    major: int
    minor: int
    patch: int

    @classmethod
    def parse(cls, text: str) -> Version:
        core = text.strip().split("+", 1)[0].split("-", 1)[0]
        parts = core.split(".")
        if not parts or not all(part.isdigit() for part in parts):
            raise ValueError(f"unsupported version {text!r}")
        numbers = [int(part) for part in parts[:3]]
        while len(numbers) < 3:
            numbers.append(0)
        return cls(*numbers)

    def __lt__(self, other: Version) -> bool:
        return (self.major, self.minor, self.patch) < (
            other.major,
            other.minor,
            other.patch,
        )

    def __le__(self, other: Version) -> bool:
        return self == other or self < other


def caret_exclusive_upper(minimum: Version) -> Version:
    if minimum.major > 0:
        return Version(minimum.major + 1, 0, 0)
    if minimum.minor > 0:
        return Version(0, minimum.minor + 1, 0)
    return Version(0, 0, minimum.patch + 1)


def satisfies_caret(requirement: str, locked: str) -> bool:
    text = requirement.strip()
    if text.startswith("^"):
        text = text[1:]
    if not text or any(text.startswith(prefix) for prefix in "=<>~*"):
        raise ValueError(f"unsupported version requirement {requirement!r}")
    if "," in text or " " in text:
        raise ValueError(f"unsupported version requirement {requirement!r}")
    minimum = Version.parse(text)
    locked_version = Version.parse(locked)
    return minimum <= locked_version < caret_exclusive_upper(minimum)


def _requirement_from_spec(spec: object) -> str | None:
    if isinstance(spec, str):
        return spec
    if isinstance(spec, Mapping) and "version" in spec:
        version = spec["version"]
        if isinstance(version, str):
            return version
    return None


def runtime_requirements(manifest: Mapping[str, object]) -> dict[str, str]:
    requirements: dict[str, str] = {}

    def absorb(dependencies: object) -> None:
        if not isinstance(dependencies, Mapping):
            return
        for name, spec in dependencies.items():
            if not isinstance(name, str):
                continue
            requirement = _requirement_from_spec(spec)
            if requirement is not None:
                requirements[name] = requirement

    absorb(manifest.get("dependencies"))
    target = manifest.get("target")
    if isinstance(target, Mapping):
        for spec in target.values():
            if isinstance(spec, Mapping):
                absorb(spec.get("dependencies"))
    return requirements


def _packages(lockfile: Mapping[str, object]) -> list[Mapping[str, object]]:
    packages = lockfile.get("package", [])
    if not isinstance(packages, list):
        raise ValueError("Cargo.lock is missing [[package]] entries")
    return [package for package in packages if isinstance(package, Mapping)]


def _path_package(
    packages: Sequence[Mapping[str, object]], name: str
) -> Mapping[str, object]:
    matches = [
        package
        for package in packages
        if package.get("name") == name and "source" not in package
    ]
    if len(matches) != 1:
        raise ValueError(f"expected one path package {name!r}, found {len(matches)}")
    return matches[0]


def _parse_lock_dep(spec: str) -> tuple[str, str | None]:
    parts = spec.split()
    if not parts:
        raise ValueError("empty lockfile dependency spec")
    version = None
    if len(parts) > 1 and parts[1][0].isdigit():
        version = parts[1]
    return parts[0], version


def _resolve_locked(
    packages: Sequence[Mapping[str, object]], spec: str
) -> Mapping[str, object]:
    name, version = _parse_lock_dep(spec)
    if version is None:
        matches = [package for package in packages if package.get("name") == name]
        if len(matches) != 1:
            raise ValueError(
                f"lockfile must disambiguate {name!r}; found {len(matches)} packages"
            )
        return matches[0]
    matches = [
        package
        for package in packages
        if package.get("name") == name and package.get("version") == version
    ]
    if len(matches) != 1:
        raise ValueError(f"lockfile is missing {name} {version}")
    return matches[0]


def consumer_incompatibilities(
    core_manifest: Mapping[str, object],
    lockfile: Mapping[str, object],
    consumer_name: str,
    lock_path: Path,
) -> list[str]:
    try:
        requirements = runtime_requirements(core_manifest)
        packages = _packages(lockfile)
        core = _path_package(packages, CORE_PACKAGE)
    except ValueError as error:
        return [f"{consumer_name}: {lock_path.as_posix()}: {error}"]

    locked_deps = core.get("dependencies", [])
    if not isinstance(locked_deps, list):
        return [
            f"{consumer_name}: {lock_path.as_posix()}: {CORE_PACKAGE} dependencies are not a list"
        ]

    resolved: dict[str, str] = {}
    errors: list[str] = []
    for spec in locked_deps:
        if not isinstance(spec, str):
            continue
        try:
            package = _resolve_locked(packages, spec)
        except ValueError as error:
            errors.append(f"{consumer_name}: {lock_path.as_posix()}: {error}")
            continue
        name = package.get("name")
        version = package.get("version")
        if isinstance(name, str) and isinstance(version, str):
            resolved[name] = version

    for name, requirement in sorted(requirements.items()):
        locked = resolved.get(name)
        if locked is None:
            errors.append(
                f"{consumer_name}: {lock_path.as_posix()} omits {CORE_PACKAGE} "
                f"dependency {name} required by {CORE_MANIFEST.as_posix()}"
            )
            continue
        try:
            compatible = satisfies_caret(requirement, locked)
        except ValueError as error:
            errors.append(
                f"{consumer_name}: {lock_path.as_posix()}: {name}: {error}"
            )
            continue
        if not compatible:
            errors.append(
                f"{consumer_name}: {lock_path.as_posix()} pins {name} {locked}, "
                f"but {CORE_MANIFEST.as_posix()} requires {requirement}"
            )
    return errors


def check_core_consumers(root: Path) -> list[str]:
    manifest_path = root / CORE_MANIFEST
    if not manifest_path.is_file():
        return [f"missing {CORE_MANIFEST.as_posix()}"]

    with manifest_path.open("rb") as handle:
        core_manifest = tomllib.load(handle)

    errors: list[str] = []
    for consumer in CONSUMERS:
        lock_path = root / consumer.lockfile
        if not lock_path.is_file():
            errors.append(
                f"{consumer.name}: missing {consumer.lockfile.as_posix()} "
                f"(shared-core updates must refresh every consuming lockfile)"
            )
            continue
        with lock_path.open("rb") as handle:
            lockfile = tomllib.load(handle)
        errors.extend(
            consumer_incompatibilities(
                core_manifest,
                lockfile,
                consumer.name,
                consumer.lockfile,
            )
        )
    return errors


def run_locked_metadata(root: Path, cargo: Sequence[str]) -> list[str]:
    errors: list[str] = []
    for consumer in CONSUMERS:
        command = [
            *cargo,
            "metadata",
            "--locked",
            "--format-version",
            "1",
            *consumer.cargo_metadata_args,
        ]
        try:
            completed = subprocess.run(
                command,
                cwd=root,
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
        except OSError as error:
            errors.append(f"{consumer.name}: failed to execute {command[0]}: {error}")
            continue
        if completed.returncode == 0:
            continue
        detail = (completed.stderr or "cargo metadata failed").strip()
        errors.append(
            f"{consumer.name}: {' '.join(command[1:])} failed for "
            f"{consumer.lockfile.as_posix()}: {detail}"
        )
    return errors


def render_errors(errors: Sequence[str]) -> str:
    lines = [
        "shared-core lockfile check failed; update every consuming lockfile:",
        *[f"- {error}" for error in errors],
    ]
    return "\n".join(lines)


def _argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "repository",
        nargs="?",
        type=Path,
        default=Path.cwd(),
        help="repository root (default: current directory)",
    )
    parser.add_argument(
        "--parse-only",
        action="store_true",
        help="compare core requirements with consuming lockfiles without cargo",
    )
    parser.add_argument(
        "--cargo-only",
        action="store_true",
        help="run cargo metadata --locked for every consuming workspace",
    )
    parser.add_argument(
        "--cargo",
        default="cargo",
        help="cargo executable (default: cargo)",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _argument_parser().parse_args(argv)
    if arguments.parse_only and arguments.cargo_only:
        print("choose at most one of --parse-only and --cargo-only", file=sys.stderr)
        return 2

    root = arguments.repository.resolve()
    errors: list[str] = []
    if not arguments.cargo_only:
        errors.extend(check_core_consumers(root))
    if not arguments.parse_only:
        errors.extend(run_locked_metadata(root, [arguments.cargo]))
    if errors:
        print(render_errors(errors), file=sys.stderr)
        return 1

    checked = ", ".join(
        f"{consumer.name} ({consumer.lockfile.as_posix()})" for consumer in CONSUMERS
    )
    print(f"shared-core lockfiles are compatible: {checked}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
