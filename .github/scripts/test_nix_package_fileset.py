#!/usr/bin/env python3
"""Check that locked package evaluation rejects a missing required source input."""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


def evaluate(nix: str, source: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            nix,
            "eval",
            "--no-update-lock-file",
            "--no-write-lock-file",
            "--raw",
            f"path:{source}#packages.x86_64-linux.maco.drvPath",
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=300,
    )


def check_fileset(root: Path) -> None:
    nix = shutil.which("nix")
    if nix is None:
        raise RuntimeError("Nix is required; the negative fixture was not run")
    paths = subprocess.run(
        ["git", "ls-files", "--cached", "-z"],
        cwd=root,
        capture_output=True,
        check=True,
    ).stdout.split(b"\0")
    original_lock = (root / "flake.lock").read_bytes()
    with tempfile.TemporaryDirectory(prefix="maco-nix-fileset-") as temporary:
        source = Path(temporary) / "source"
        source.mkdir()
        # Copy only repository inputs, without Git metadata, caches or build outputs.
        for raw in paths:
            if not raw:
                continue
            relative = Path(os.fsdecode(raw))
            destination = source / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(root / relative, destination, follow_symlinks=False)

        required = source / "build.rs"
        if not required.is_file() or required.is_symlink():
            raise RuntimeError("The complete source fixture must contain build.rs")
        positive = evaluate(nix, source)
        if positive.returncode != 0:
            raise RuntimeError(
                "Complete source evaluation failed; no negative result is accepted:\n"
                + positive.stderr
            )
        derivation = positive.stdout.strip()
        if not derivation.startswith("/nix/store/") or not derivation.endswith(".drv"):
            raise RuntimeError("Complete source evaluation did not return a derivation")
        if (source / "flake.lock").read_bytes() != original_lock:
            raise RuntimeError("Complete source evaluation changed flake.lock")
        print("PASS: complete source evaluates with locked inputs", flush=True)

        required.unlink()
        negative = evaluate(nix, source)
        if negative.returncode == 0:
            raise RuntimeError("Package evaluation accepted a missing build.rs")
        # A tool, network or daemon failure is not proof of fileset validation.
        if (
            negative.returncode < 0
            or "build.rs" not in negative.stderr
            or "does not exist" not in negative.stderr
        ):
            raise RuntimeError(
                "Evaluation failed without the expected missing-build.rs diagnostic:\n"
                + negative.stderr
            )
        if (source / "flake.lock").read_bytes() != original_lock:
            raise RuntimeError("Missing-input evaluation changed flake.lock")
        print("PASS: package fileset rejects missing build.rs", flush=True)

    if (root / "flake.lock").read_bytes() != original_lock:
        raise RuntimeError("Checkout flake.lock changed during the fixture")


def main() -> int:
    try:
        check_fileset(Path(__file__).resolve().parents[2])
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
