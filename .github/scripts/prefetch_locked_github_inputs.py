#!/usr/bin/env python3
"""Prepare exact locked GitHub sources via codeload, verified by Nix NAR hash."""

from __future__ import annotations

import base64
import binascii
import json
from pathlib import Path
import re
import subprocess
import sys


MAX_LOCK_BYTES = 1024 * 1024


def github_inputs(raw: bytes) -> list[tuple[str, str, str]]:
    if len(raw) > MAX_LOCK_BYTES:
        raise ValueError("flake.lock exceeds 1 MiB")
    lock = json.loads(raw)
    if not isinstance(lock, dict) or lock.get("version") != 7:
        raise ValueError("Expected flake.lock version 7")
    nodes = lock.get("nodes")
    if not isinstance(nodes, dict):
        raise ValueError("Expected flake.lock nodes")
    inputs = []
    for name, node in nodes.items():
        if not isinstance(node, dict):
            raise ValueError(f"Invalid lock node: {name}")
        if "locked" not in node:
            continue
        pin = node["locked"]
        if not isinstance(pin, dict):
            raise ValueError(f"Invalid locked input: {name}")
        if pin.get("type") != "github":
            continue
        if set(pin) - {"type", "owner", "repo", "rev", "narHash", "lastModified"}:
            raise ValueError(f"Unsupported GitHub pin fields: {name}")
        owner, repo, rev, nar_hash = (
            pin.get(key) for key in ("owner", "repo", "rev", "narHash")
        )
        if (
            not isinstance(owner, str)
            or re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?", owner) is None
            or not isinstance(repo, str)
            or re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", repo) is None
            or repo in {".", ".."}
            or not isinstance(rev, str)
            or re.fullmatch(r"[0-9a-f]{40}", rev) is None
        ):
            raise ValueError(f"Invalid GitHub owner/repo/revision: {name}")
        if not isinstance(nar_hash, str) or not nar_hash.startswith("sha256-"):
            raise ValueError(f"Invalid SHA-256 NAR hash: {name}")
        encoded = nar_hash.removeprefix("sha256-")
        try:
            digest = base64.b64decode(encoded, validate=True)
        except (ValueError, binascii.Error) as error:
            raise ValueError(f"Invalid SHA-256 NAR hash: {name}") from error
        if len(digest) != 32 or base64.b64encode(digest).decode("ascii") != encoded:
            raise ValueError(f"Invalid SHA-256 NAR hash: {name}")
        url = f"https://codeload.github.com/{owner}/{repo}/tar.gz/{rev}"
        inputs.append((name, url, nar_hash))
    return inputs


def prefetch_locked_inputs(root: Path, nix: str = "nix") -> None:
    lock_path = root / "flake.lock"
    with lock_path.open("rb") as source:
        original = source.read(MAX_LOCK_BYTES + 1)
    inputs = github_inputs(original)
    for name, url, expected in inputs:
        # --unpack binds the NAR hash; --name source matches locked GitHub sources.
        result = subprocess.run(
            [
                nix, "store", "prefetch-file", "--unpack", "--name", "source",
                "--expected-hash", expected, "--json", url,
            ],
            capture_output=True,
            text=True,
            check=True,
            timeout=300,
        )
        receipt = json.loads(result.stdout)
        if (
            not isinstance(receipt, dict)
            or receipt.get("hash") != expected
            or not isinstance(receipt.get("storePath"), str)
            or re.fullmatch(
                r"/nix/store/[0-9abcdfghijklmnpqrsvwxyz]{32}-source",
                receipt["storePath"],
            ) is None
        ):
            raise RuntimeError(f"Nix did not return the expected NAR source: {name}")
        print(json.dumps({"input": name, "url": url, **receipt}), flush=True)
    if lock_path.read_bytes() != original:
        raise RuntimeError("Prefetch changed flake.lock")
    if not inputs:
        print("No locked GitHub inputs to prefetch", flush=True)


def main() -> int:
    try:
        prefetch_locked_inputs(Path(__file__).resolve().parents[2])
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
