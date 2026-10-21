#!/usr/bin/env python3
"""Check encrypted keyring sessions without accessing a credential service."""

from __future__ import annotations

from pathlib import Path
import subprocess
import sys


def check_tree(tree: str) -> None:
    packages: dict[tuple[str, str], set[str]] = {}
    for line in tree.splitlines():
        if not line.strip():
            continue
        package, features = line.removesuffix(" (*)").split("|", 1)
        name, version, *_ = package.split()
        packages.setdefault((name, version), set()).update(features.split(","))
    keyrings = [
        (version, features)
        for (name, version), features in packages.items()
        if name == "keyring"
    ]
    if len(keyrings) != 1:
        raise ValueError("expected exactly one resolved keyring")
    version, features = keyrings[0]
    # In keyring 3 the wrapper's feature selects Dh instead of Plain. Enabling
    # crypto only on dbus-secret-service does not select encrypted sessions.
    if not version.startswith("v3."):
        raise ValueError("review the DH feature contract when upgrading keyring")
    if not {"sync-secret-service", "crypto-rust"} <= features:
        raise ValueError("keyring must enable sync-secret-service and crypto-rust for DH")
    backends = [
        enabled for (name, _), enabled in packages.items()
        if name == "dbus-secret-service"
    ]
    if len(backends) != 1 or "crypto-rust" not in backends[0]:
        raise ValueError("dbus-secret-service must enable crypto-rust")
    # Cargo metadata includes weak-optional lockfile nodes that cargo tree
    # correctly omits from the compilation graph, even with --target all.
    # RUSTSEC-2026-0370/0371/0372 have no patched versions. Checking
    # only keyring's old exact versions would let the shared exceptions hide
    # active desktop zvariant 5 / zbus_names 4 (or a future affected version).
    excepted = {"zvariant", "zvariant_derive", "zbus_names"}
    active = sorted(f"{name} {version}" for name, version in packages
                    if name in excepted)
    if active:
        raise ValueError("advisory-excepted packages must never be compiled: "
                         + ", ".join(active))
    if "async-secret-service" in features or any(
        name == "secret-service" for name, _ in packages
    ):
        raise ValueError("the excepted async Secret Service path must never be compiled")


def check_workspace(root: Path, manifest: Path) -> None:
    result = subprocess.run(
        [
            "cargo", "tree", "--locked", "--workspace", "--target", "all",
            "--edges", "normal,build,dev", "--prefix", "none",
            "--format", "{p}|{f}", "--manifest-path", str(manifest),
        ],
        cwd=root,
        check=True,
        stdout=subprocess.PIPE,
        text=True,
    )
    check_tree(result.stdout)


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    # Audit/deny policy is shared, so every normal invocation must validate
    # both consumers before any lockfile-wide advisory exceptions are used.
    failed = False
    for manifest in (Path("Cargo.toml"), Path("account-manager/src-tauri/Cargo.toml")):
        try:
            check_workspace(root, manifest)
        except (ValueError, subprocess.CalledProcessError) as error:
            print(f"keyring crypto check failed ({manifest}): {error}", file=sys.stderr)
            failed = True
    if failed:
        return 1
    print("both workspaces enable keyring DH; advisory-excepted packages are inactive")
    return 0


if __name__ == "__main__":
    sys.exit(main())
