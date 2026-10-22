#!/usr/bin/env python3
"""Audit the desktop graph with fail-closed, version-exact advisory exceptions."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import subprocess
import sys
import tomllib


def check_exceptions(manifest: dict, lock: dict, policy: dict) -> list[str]:
    exceptions = manifest.get("package", {}).get("metadata", {}).get(
        "desktop-advisories", []
    )
    ignored = policy.get("advisories", {}).get("ignore", [])
    if policy.get("advisories", {}).get("unused-ignored-advisory") != "deny":
        raise ValueError("desktop policy must reject unused advisory exceptions")
    if policy.get("advisories", {}).get("unsound") != "all":
        raise ValueError("desktop policy must check transitive unsoundness advisories")
    ids = []
    for entry in exceptions:
        if set(entry) != {"id", "package", "version", "reason", "removal"}:
            raise ValueError("advisory exceptions require id, package, version, reason and removal")
        if not all(isinstance(value, str) and value.strip() for value in entry.values()):
            raise ValueError("advisory exception fields must be nonempty strings")
        if not re.fullmatch(r"RUSTSEC-\d{4}-\d{4}", entry["id"]):
            raise ValueError("invalid advisory identifier")
        if not re.fullmatch(r"\d+\.\d+\.\d+", entry["version"]):
            raise ValueError("advisory exception version must be exact")
        packages = [p for p in lock["package"] if p["name"] == entry["package"]]
        if len(packages) != 1 or packages[0]["version"] != entry["version"]:
            raise ValueError(f"review or remove {entry['id']}: {entry['package']} version changed")
        if packages[0].get("source") != "registry+https://github.com/rust-lang/crates.io-index":
            raise ValueError(f"review {entry['id']}: package source changed")
        ids.append(entry["id"])
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate advisory exception")
    if any(not isinstance(entry, dict) or set(entry) != {"id", "reason"} for entry in ignored):
        raise ValueError("desktop deny ignores require an id and a reason")
    if sorted(entry["id"] for entry in ignored) != sorted(ids):
        raise ValueError("desktop deny exceptions differ from the version-exact manifest")
    return ids


def check_report(report: dict, exceptions: list[dict]) -> None:
    """Bind IDs to the packages actually reported by RustSec, not just TOML."""
    vulnerabilities = report.get("vulnerabilities")
    warnings = report.get("warnings")
    if not isinstance(vulnerabilities, dict) or not isinstance(warnings, dict):
        raise ValueError("invalid cargo-audit report")
    if vulnerabilities.get("found") is not False or vulnerabilities.get("list") != []:
        raise ValueError("desktop has an unexcepted security vulnerability")
    expected = {(e["id"], e["package"], e["version"]) for e in exceptions}
    observed = set()
    for kind, findings in warnings.items():
        for finding in findings:
            advisory = finding.get("advisory") or {}
            package = finding.get("package") or {}
            key = (advisory.get("id"), package.get("name"), package.get("version"))
            if kind not in {"unmaintained", "unsound"} or key not in expected:
                raise ValueError(f"unexcepted desktop warning: {kind} {key}")
            observed.add(key)
    if observed != expected:
        raise ValueError("an advisory exception is no longer needed; review and remove it")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check-only", action="store_true", help="validate exception scope without running audit tools")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    desktop = root / "account-manager/src-tauri"
    try:
        def read(path: Path) -> dict:
            return tomllib.loads(path.read_text(encoding="utf-8"))

        manifest = read(desktop / "Cargo.toml")
        ids = check_exceptions(manifest, read(desktop / "Cargo.lock"), read(desktop / "deny.toml"))
        for name in (".cargo/audit.toml", "deny.toml"):
            if read(root / name).get("advisories", {}).get("ignore") != []:
                raise ValueError(f"root {name} must remain exception-free")
        if not args.check_only:
            raw = subprocess.run([
                "cargo", "audit", "--file", str(desktop / "Cargo.lock"),
                "--deny", "warnings", "--json",
            ], cwd=root, stdout=subprocess.PIPE, text=True)
            if raw.returncode not in {0, 1}:
                raise ValueError(f"cargo-audit failed with exit {raw.returncode}")
            exceptions = manifest.get("package", {}).get("metadata", {}).get("desktop-advisories", [])
            check_report(json.loads(raw.stdout), exceptions)
            # cargo-audit accepts IDs, not package versions. Validate the exact
            # report first, then pass only the reviewed IDs for this invocation.
            command = ["cargo", "audit", "--no-fetch", "--file", str(desktop / "Cargo.lock"), "--deny", "warnings"]
            for advisory in ids:
                command.extend(["--ignore", advisory])
            subprocess.run(command, cwd=root, check=True)
            subprocess.run([
                "cargo", "deny", "--manifest-path", str(desktop / "Cargo.toml"),
                "--locked", "--config", str(desktop / "deny.toml"), "check",
                "-D", "warnings", "advisories", "bans", "licenses", "sources",
            ], cwd=root, check=True)
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        print(f"desktop supply-chain check failed: {error}", file=sys.stderr)
        return 1
    print(f"desktop supply-chain policy passed ({len(ids)} version-exact advisory exceptions)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
