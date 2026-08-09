#!/usr/bin/env python3
"""Check tracked repository paths for Windows portability hazards."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence


# A Windows GitHub Actions checkout root consumes 68 UTF-16 code units. Adding
# the separator leaves 69 units before a repository-relative path. Limiting the
# latter to 180 units gives 249 visible units in total, a 10-unit margin below
# the 259 visible-unit maximum of a traditional 260-unit Win32 path buffer.
MAX_WINDOWS_PATH_UNITS = 180

_INVALID_FILENAME_CHARACTERS = frozenset('<>:"\\|?*')
_RESERVED_DEVICE_NAMES = frozenset({"con", "prn", "aux", "nul"})
_RESERVED_DEVICE_SUFFIXES = frozenset("123456789¹²³")


@dataclass(frozen=True)
class Violation:
    """One portability violation involving one or more tracked paths."""

    code: str
    detail: str
    paths: tuple[bytes, ...]

    def sort_key(self) -> tuple[tuple[bytes, ...], str, str]:
        return (self.paths, self.code, self.detail)


def windows_utf16_units(value: str) -> int:
    """Return the number of UTF-16 code units Windows uses for *value*."""

    return len(value.encode("utf-16-le")) // 2


def quote_path(path: bytes) -> str:
    """Return a single-line, unambiguous representation of a raw Git path."""

    try:
        decoded = path.decode("utf-8")
    except UnicodeDecodeError:
        return repr(path)
    return json.dumps(decoded, ensure_ascii=True)


def _quote_text(value: str) -> str:
    return json.dumps(value, ensure_ascii=True)


def _reserved_device_name(component: str) -> bool:
    # Extensions do not make a DOS device name safe: NUL.txt still names NUL.
    stem = component.split(".", 1)[0].rstrip(" ").casefold()
    if stem in _RESERVED_DEVICE_NAMES:
        return True
    return (
        len(stem) == 4
        and stem[:3] in {"com", "lpt"}
        and stem[3] in _RESERVED_DEVICE_SUFFIXES
    )


def _invalid_character_labels(component: str) -> list[str]:
    invalid = {
        character
        for character in component
        if character in _INVALID_FILENAME_CHARACTERS or ord(character) < 32
    }
    labels: list[str] = []
    for character in sorted(invalid, key=ord):
        if ord(character) < 32:
            labels.append(f"U+{ord(character):04X}")
        else:
            labels.append(_quote_text(character))
    return labels


def _component_collisions(
    decoded_paths: Sequence[tuple[bytes, tuple[str, ...]]],
) -> list[Violation]:
    nodes: dict[
        tuple[tuple[str, ...], str], dict[str, set[bytes]]
    ] = {}
    prefixes: dict[tuple[str, ...], set[bytes]] = {}
    files: dict[tuple[str, ...], set[bytes]] = {}

    for raw_path, components in decoded_paths:
        folded_components = tuple(component.casefold() for component in components)
        files.setdefault(folded_components, set()).add(raw_path)
        for index, (component, folded_component) in enumerate(
            zip(components, folded_components)
        ):
            folded_parent = folded_components[:index]
            node = nodes.setdefault((folded_parent, folded_component), {})
            node.setdefault(component, set()).add(raw_path)
            prefixes.setdefault(folded_components[: index + 1], set()).add(raw_path)

    violations: list[Violation] = []
    for component_variants in nodes.values():
        if len(component_variants) < 2:
            continue
        spellings = sorted(component_variants, key=lambda value: value.encode("utf-8"))
        involved_paths = tuple(
            sorted(
                {
                    path
                    for paths_for_spelling in component_variants.values()
                    for path in paths_for_spelling
                }
            )
        )
        violations.append(
            Violation(
                "casefold-collision",
                "path components "
                + ", ".join(_quote_text(spelling) for spelling in spellings)
                + " collide under Unicode case folding",
                involved_paths,
            )
        )

    for folded_path, file_paths in files.items():
        descendant_paths = prefixes.get(folded_path, set()) - file_paths
        if not descendant_paths:
            continue
        involved_paths = tuple(sorted(file_paths | descendant_paths))
        violations.append(
            Violation(
                "file-directory-collision",
                "a tracked file collides with a directory prefix under Unicode "
                "case folding",
                involved_paths,
            )
        )

    return violations


def collect_violations(raw_paths: Iterable[bytes]) -> list[Violation]:
    """Return all portability violations in raw NUL-delimited Git paths."""

    violations: list[Violation] = []
    decoded_paths: list[tuple[bytes, tuple[str, ...]]] = []

    for raw_path in sorted(set(raw_paths)):
        try:
            path = raw_path.decode("utf-8")
        except UnicodeDecodeError as error:
            violations.append(
                Violation(
                    "invalid-utf8",
                    f"path is not valid UTF-8 at byte {error.start}: {error.reason}",
                    (raw_path,),
                )
            )
            continue

        units = windows_utf16_units(path)
        if units > MAX_WINDOWS_PATH_UNITS:
            violations.append(
                Violation(
                    "path-length",
                    f"path uses {units} Windows UTF-16 units; maximum is "
                    f"{MAX_WINDOWS_PATH_UNITS}",
                    (raw_path,),
                )
            )

        components = tuple(path.split("/"))
        decoded_paths.append((raw_path, components))
        for component in components:
            labels = _invalid_character_labels(component)
            if labels:
                violations.append(
                    Violation(
                        "invalid-character",
                        f"component {_quote_text(component)} contains "
                        + ", ".join(labels),
                        (raw_path,),
                    )
                )
            if component.endswith((".", " ")):
                violations.append(
                    Violation(
                        "trailing-dot-or-space",
                        f"component {_quote_text(component)} ends in a dot or space",
                        (raw_path,),
                    )
                )
            if _reserved_device_name(component):
                violations.append(
                    Violation(
                        "reserved-device-name",
                        f"component {_quote_text(component)} is a reserved Win32 "
                        "device name",
                        (raw_path,),
                    )
                )

    violations.extend(_component_collisions(decoded_paths))
    return sorted(violations, key=Violation.sort_key)


def git_tracked_paths(repository: Path) -> list[bytes]:
    """Read tracked paths as raw bytes using Git's NUL-delimited output."""

    command = ["git", "ls-files", "-z"]
    git_directory = _wsl_worktree_git_directory(repository)
    if git_directory is not None:
        command = [
            "git",
            "--git-dir",
            str(git_directory),
            "--work-tree",
            str(repository.resolve()),
            "ls-files",
            "-z",
        ]

    result = subprocess.run(
        command,
        cwd=repository,
        check=True,
        stdout=subprocess.PIPE,
    )
    return [path for path in result.stdout.split(b"\0") if path]


def _wsl_worktree_git_directory(repository: Path) -> str | None:
    """Translate a Windows-created worktree's Git pointer when running in WSL."""

    if sys.platform != "linux":
        return None

    try:
        lines = (repository / ".git").read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError):
        return None
    if len(lines) != 1 or not lines[0].startswith("gitdir: "):
        return None

    git_directory = lines[0].removeprefix("gitdir: ")
    if re.fullmatch(r"[A-Za-z]:[\\/].+", git_directory) is None:
        return None

    try:
        translated = subprocess.run(
            ["wslpath", "-u", git_directory],
            cwd=repository,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError, UnicodeError):
        return None

    if not translated.startswith("/"):
        return None
    return translated


def render_violations(violations: Sequence[Violation]) -> str:
    """Render deterministic, safely quoted diagnostics."""

    lines = [
        f"repository portability check failed with {len(violations)} violation(s):"
    ]
    for violation in violations:
        rendered_paths = ", ".join(quote_path(path) for path in violation.paths)
        lines.append(
            f"- {violation.code}: {violation.detail}; path(s): {rendered_paths}"
        )
    return "\n".join(lines)


def _argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "repository",
        nargs="?",
        type=Path,
        default=Path.cwd(),
        help="repository to inspect (default: current directory)",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _argument_parser().parse_args(argv)
    try:
        paths = git_tracked_paths(arguments.repository)
    except (OSError, subprocess.CalledProcessError) as error:
        print(f"unable to list tracked paths: {error}", file=sys.stderr)
        return 2

    violations = collect_violations(paths)
    if violations:
        print(render_violations(violations), file=sys.stderr)
        return 1

    print(f"repository portability check passed ({len(paths)} tracked paths)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
