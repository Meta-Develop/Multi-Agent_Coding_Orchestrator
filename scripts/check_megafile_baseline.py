#!/usr/bin/env python3
"""Check that over-threshold Rust files cannot grow beyond a recorded baseline."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence


DEFAULT_MAX_LINES = 4_000
DEFAULT_MAX_BYTES = 512 * 1024


class OperationalError(Exception):
    """Unrecoverable operational failure; maps to exit status 2."""


@dataclass(frozen=True)
class Thresholds:
    """Inclusive physical size limits for a tracked Rust file."""

    max_lines: int
    max_bytes: int


@dataclass(frozen=True)
class FileMeasurement:
    """On-disk size and physical line count for one tracked Rust file."""

    path: str
    lines: int
    bytes: int


@dataclass(frozen=True)
class BaselineEntry:
    """Recorded size of one previously accepted over-threshold file."""

    lines: int
    bytes: int


@dataclass(frozen=True)
class Finding:
    """One baseline violation or ratchet-tighten notice."""

    code: str
    path: str
    measured_lines: int | None = None
    measured_bytes: int | None = None
    baseline_lines: int | None = None
    baseline_bytes: int | None = None
    threshold_lines: int | None = None
    threshold_bytes: int | None = None

    def sort_key(self) -> tuple[str, str]:
        return (self.path, self.code)

    def to_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {"code": self.code, "path": self.path}
        if self.measured_lines is not None:
            payload["measured_lines"] = self.measured_lines
        if self.measured_bytes is not None:
            payload["measured_bytes"] = self.measured_bytes
        if self.baseline_lines is not None:
            payload["baseline_lines"] = self.baseline_lines
        if self.baseline_bytes is not None:
            payload["baseline_bytes"] = self.baseline_bytes
        if self.threshold_lines is not None:
            payload["threshold_lines"] = self.threshold_lines
        if self.threshold_bytes is not None:
            payload["threshold_bytes"] = self.threshold_bytes
        return payload


@dataclass(frozen=True)
class Evaluation:
    """Deterministically sorted policy findings for a set of measurements."""

    violations: tuple[Finding, ...]
    notices: tuple[Finding, ...]


def quote_path(path: str) -> str:
    """Return a single-line JSON-quoted UTF-8 path."""

    return json.dumps(path, ensure_ascii=True)


def quote_raw_path(path: bytes) -> str:
    """Return a single-line, unambiguous representation of a raw Git path."""

    try:
        return quote_path(path.decode("utf-8"))
    except UnicodeDecodeError:
        return repr(path)


def default_baseline_path(repository: Path) -> Path:
    return repository / "scripts" / "megafile_baseline.json"


def physical_line_count(data: bytes) -> int:
    """Count physical lines using ``\\n`` only, matching the Rust sampler."""

    if not data:
        return 0
    return data.count(b"\n") + (0 if data.endswith(b"\n") else 1)


def is_over_threshold(measurement: FileMeasurement, thresholds: Thresholds) -> bool:
    return (
        measurement.lines >= thresholds.max_lines
        or measurement.bytes >= thresholds.max_bytes
    )


def measure_file(repository: Path, relative_path: str) -> FileMeasurement:
    """Read one repository-relative file and return its physical size."""

    path = repository / relative_path
    data = path.read_bytes()
    size = path.stat().st_size
    return FileMeasurement(path=relative_path, lines=physical_line_count(data), bytes=size)


def _require_non_negative_int(value: object, path: str, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(
            f"entry {quote_path(path)} field {field} must be a non-negative integer"
        )
    return value


def parse_baseline(payload: object) -> dict[str, BaselineEntry]:
    """Validate a loaded JSON document as a path-to-size baseline map."""

    if not isinstance(payload, dict):
        raise ValueError("baseline must be a JSON object")

    entries: dict[str, BaselineEntry] = {}
    for path, entry in payload.items():
        if not isinstance(path, str):
            raise ValueError("baseline keys must be strings")
        if not isinstance(entry, dict):
            raise ValueError(f"entry {quote_path(path)} must be a JSON object")
        unexpected = sorted(key for key in entry if key not in {"lines", "bytes"})
        if unexpected:
            labels = ", ".join(quote_path(key) for key in unexpected)
            raise ValueError(
                f"entry {quote_path(path)} has unknown key(s): {labels}"
            )
        if "lines" not in entry or "bytes" not in entry:
            raise ValueError(
                f"entry {quote_path(path)} must include integer lines and bytes"
            )
        entries[path] = BaselineEntry(
            lines=_require_non_negative_int(entry["lines"], path, "lines"),
            bytes=_require_non_negative_int(entry["bytes"], path, "bytes"),
        )
    return entries


def load_baseline(path: Path) -> dict[str, BaselineEntry]:
    """Load a baseline map, treating a missing file as an empty mapping."""

    if not path.exists():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise OperationalError(
            f"unable to read baseline {quote_path(str(path))}: {error}"
        ) from error
    try:
        return parse_baseline(payload)
    except ValueError as error:
        raise OperationalError(
            f"invalid baseline {quote_path(str(path))}: {error}"
        ) from error


def serialize_baseline(measurements: Sequence[FileMeasurement]) -> str:
    """Render a deterministic baseline document with sorted outer keys."""

    payload = {
        item.path: {"lines": item.lines, "bytes": item.bytes}
        for item in sorted(measurements, key=lambda item: item.path)
    }
    return json.dumps(payload, indent=2, ensure_ascii=True) + "\n"


def write_baseline(path: Path, measurements: Sequence[FileMeasurement]) -> None:
    path.write_text(serialize_baseline(measurements), encoding="utf-8")


def evaluate(
    measurements: Sequence[FileMeasurement],
    baseline: Mapping[str, BaselineEntry],
    thresholds: Thresholds,
) -> Evaluation:
    """Compare measurements against a baseline without touching the filesystem."""

    violations: list[Finding] = []
    notices: list[Finding] = []
    measured_paths = {measurement.path for measurement in measurements}

    for measurement in measurements:
        entry = baseline.get(measurement.path)
        over_threshold = is_over_threshold(measurement, thresholds)
        if entry is None:
            if over_threshold:
                violations.append(
                    Finding(
                        code="new-megafile",
                        path=measurement.path,
                        measured_lines=measurement.lines,
                        measured_bytes=measurement.bytes,
                        threshold_lines=thresholds.max_lines,
                        threshold_bytes=thresholds.max_bytes,
                    )
                )
            continue

        if measurement.lines > entry.lines:
            violations.append(
                Finding(
                    code="growth-lines",
                    path=measurement.path,
                    measured_lines=measurement.lines,
                    baseline_lines=entry.lines,
                )
            )
        elif measurement.lines < entry.lines:
            notices.append(
                Finding(
                    code="shrink-lines",
                    path=measurement.path,
                    measured_lines=measurement.lines,
                    baseline_lines=entry.lines,
                )
            )

        if measurement.bytes > entry.bytes:
            violations.append(
                Finding(
                    code="growth-bytes",
                    path=measurement.path,
                    measured_bytes=measurement.bytes,
                    baseline_bytes=entry.bytes,
                )
            )
        elif measurement.bytes < entry.bytes:
            notices.append(
                Finding(
                    code="shrink-bytes",
                    path=measurement.path,
                    measured_bytes=measurement.bytes,
                    baseline_bytes=entry.bytes,
                )
            )

        if not over_threshold:
            notices.append(
                Finding(
                    code="dropped-under-threshold",
                    path=measurement.path,
                    measured_lines=measurement.lines,
                    measured_bytes=measurement.bytes,
                    threshold_lines=thresholds.max_lines,
                    threshold_bytes=thresholds.max_bytes,
                )
            )

    for path in baseline:
        if path in measured_paths:
            continue
        entry = baseline[path]
        notices.append(
            Finding(
                code="missing-from-tree",
                path=path,
                baseline_lines=entry.lines,
                baseline_bytes=entry.bytes,
            )
        )

    return Evaluation(
        violations=tuple(sorted(violations, key=Finding.sort_key)),
        notices=tuple(sorted(notices, key=Finding.sort_key)),
    )


def _over_threshold_clauses(finding: Finding) -> str:
    clauses: list[str] = []
    if (
        finding.measured_lines is not None
        and finding.threshold_lines is not None
        and finding.measured_lines >= finding.threshold_lines
    ):
        clauses.append(
            f"has {finding.measured_lines} lines (threshold {finding.threshold_lines})"
        )
    if (
        finding.measured_bytes is not None
        and finding.threshold_bytes is not None
        and finding.measured_bytes >= finding.threshold_bytes
    ):
        clause = f"{finding.measured_bytes} bytes (threshold {finding.threshold_bytes})"
        if clauses:
            clauses.append(f"and {clause}")
        else:
            clauses.append(f"has {clause}")
    if not clauses:
        return "is over the configured threshold"
    return " ".join(clauses)


def render_violation(finding: Finding) -> str:
    quoted = quote_path(finding.path)
    if finding.code == "new-megafile":
        return (
            f"- new-megafile: {quoted} {_over_threshold_clauses(finding)}; "
            "file is absent from the baseline"
        )
    if finding.code == "growth-lines":
        return (
            f"- growth-lines: {quoted} has {finding.measured_lines} lines; "
            f"baseline is {finding.baseline_lines}"
        )
    if finding.code == "growth-bytes":
        return (
            f"- growth-bytes: {quoted} has {finding.measured_bytes} bytes; "
            f"baseline is {finding.baseline_bytes}"
        )
    return f"- {finding.code}: {quoted}"


def render_notice(finding: Finding) -> str:
    quoted = quote_path(finding.path)
    ratchet = "re-run with --update-baseline to tighten the ratchet"
    if finding.code == "shrink-lines":
        return (
            f"notice: {quoted} shrank to {finding.measured_lines} lines from "
            f"baseline {finding.baseline_lines}; {ratchet}"
        )
    if finding.code == "shrink-bytes":
        return (
            f"notice: {quoted} shrank to {finding.measured_bytes} bytes from "
            f"baseline {finding.baseline_bytes}; {ratchet}"
        )
    if finding.code == "dropped-under-threshold":
        return (
            f"notice: {quoted} dropped under threshold "
            f"({finding.measured_lines} lines, {finding.measured_bytes} bytes; "
            f"thresholds {finding.threshold_lines} lines, "
            f"{finding.threshold_bytes} bytes); {ratchet}"
        )
    if finding.code == "missing-from-tree":
        return (
            f"notice: {quoted} is recorded in the baseline but is no longer a "
            f"tracked Rust file; {ratchet}"
        )
    return f"notice: {quoted}; {ratchet}"


def render_violations(violations: Sequence[Finding]) -> str:
    lines = [
        f"megafile baseline check failed with {len(violations)} violation(s):"
    ]
    lines.extend(render_violation(violation) for violation in violations)
    return "\n".join(lines)


def git_tracked_rust_files(repository: Path) -> list[bytes]:
    """Read tracked Rust paths as raw bytes using Git's NUL-delimited output."""

    command = ["git", "ls-files", "-z", "--", "*.rs"]
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
            "--",
            "*.rs",
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


def _decode_tracked_paths(raw_paths: Sequence[bytes]) -> list[str]:
    decoded: list[str] = []
    for raw_path in raw_paths:
        try:
            decoded.append(raw_path.decode("utf-8"))
        except UnicodeDecodeError as error:
            raise OperationalError(
                "tracked Rust path is not valid UTF-8 at byte "
                f"{error.start}: {error.reason}: {quote_raw_path(raw_path)}"
            ) from error
    return sorted(set(decoded))


def _report_payload(
    *,
    ok: bool,
    thresholds: Thresholds,
    tracked_rust_files: int,
    over_threshold: int,
    evaluation: Evaluation,
    baseline_path: Path,
    updated_baseline: bool,
) -> dict[str, object]:
    return {
        "ok": ok,
        "thresholds": {
            "max_lines": thresholds.max_lines,
            "max_bytes": thresholds.max_bytes,
        },
        "tracked_rust_files": tracked_rust_files,
        "over_threshold": over_threshold,
        "violations": [finding.to_dict() for finding in evaluation.violations],
        "notices": [finding.to_dict() for finding in evaluation.notices],
        "baseline_path": str(baseline_path),
        "updated_baseline": updated_baseline,
    }


def _emit_notices(notices: Sequence[Finding]) -> None:
    for notice in notices:
        print(render_notice(notice), file=sys.stderr)


def _emit_json(payload: Mapping[str, object]) -> None:
    print(json.dumps(payload, ensure_ascii=True, indent=2))


def _argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "repository",
        nargs="?",
        type=Path,
        default=Path.cwd(),
        help="repository to inspect (default: current directory)",
    )
    parser.add_argument(
        "--max-lines",
        type=int,
        default=DEFAULT_MAX_LINES,
        metavar="N",
        help=f"physical line threshold (default: {DEFAULT_MAX_LINES})",
    )
    parser.add_argument(
        "--max-bytes",
        type=int,
        default=DEFAULT_MAX_BYTES,
        metavar="N",
        help=f"file size threshold in bytes (default: {DEFAULT_MAX_BYTES})",
    )
    parser.add_argument(
        "--baseline",
        type=Path,
        default=None,
        help="baseline JSON path (default: <repository>/scripts/megafile_baseline.json)",
    )
    parser.add_argument(
        "--update-baseline",
        action="store_true",
        help="rewrite the baseline from the current over-threshold files",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="write a machine-readable report to stdout",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _argument_parser().parse_args(argv)
    repository = arguments.repository
    baseline_path = arguments.baseline or default_baseline_path(repository)
    thresholds = Thresholds(
        max_lines=arguments.max_lines,
        max_bytes=arguments.max_bytes,
    )

    try:
        raw_paths = git_tracked_rust_files(repository)
    except (OSError, subprocess.CalledProcessError) as error:
        print(f"unable to list tracked Rust files: {error}", file=sys.stderr)
        return 2

    try:
        relative_paths = _decode_tracked_paths(raw_paths)
        measurements = [
            measure_file(repository, relative_path) for relative_path in relative_paths
        ]
        if arguments.update_baseline:
            over_threshold_files = [
                measurement
                for measurement in measurements
                if is_over_threshold(measurement, thresholds)
            ]
            try:
                write_baseline(baseline_path, over_threshold_files)
            except OSError as error:
                print(
                    f"unable to write baseline {quote_path(str(baseline_path))}: "
                    f"{error}",
                    file=sys.stderr,
                )
                return 2
            evaluation = Evaluation(violations=(), notices=())
            over_threshold_count = len(over_threshold_files)
            payload = _report_payload(
                ok=True,
                thresholds=thresholds,
                tracked_rust_files=len(measurements),
                over_threshold=over_threshold_count,
                evaluation=evaluation,
                baseline_path=baseline_path,
                updated_baseline=True,
            )
            if arguments.json_output:
                _emit_json(payload)
            else:
                print(
                    "updated megafile baseline with "
                    f"{over_threshold_count} over-threshold file(s) "
                    f"({len(measurements)} tracked Rust files)"
                )
            return 0

        baseline = load_baseline(baseline_path)
        evaluation = evaluate(measurements, baseline, thresholds)
        over_threshold_count = sum(
            1
            for measurement in measurements
            if is_over_threshold(measurement, thresholds)
        )
        ok = not evaluation.violations
        payload = _report_payload(
            ok=ok,
            thresholds=thresholds,
            tracked_rust_files=len(measurements),
            over_threshold=over_threshold_count,
            evaluation=evaluation,
            baseline_path=baseline_path,
            updated_baseline=False,
        )
        _emit_notices(evaluation.notices)
        if arguments.json_output:
            _emit_json(payload)
        elif ok:
            print(
                "megafile baseline check passed "
                f"({len(measurements)} tracked Rust files, "
                f"{over_threshold_count} over threshold)"
            )
        if evaluation.violations:
            print(render_violations(evaluation.violations), file=sys.stderr)
            return 1
        return 0
    except OperationalError as error:
        print(str(error), file=sys.stderr)
        return 2
    except OSError as error:
        print(f"unable to measure tracked Rust files: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
