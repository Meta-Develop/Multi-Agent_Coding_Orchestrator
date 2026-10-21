#!/usr/bin/env python3
"""Check encrypted keyring sessions without accessing a credential service."""

from __future__ import annotations

from pathlib import Path
import subprocess
import sys


def check_tree(tree: str) -> None:
    packages: dict[tuple[str, str], set[str]] = {}
    for line in tree.splitlines():
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
    inactive = {
        ("secret-service", "v4.0.0"),
        ("zvariant", "v4.2.0"),
        ("zvariant_derive", "v4.2.0"),
        ("zbus_names", "v3.0.0"),
    }
    if "async-secret-service" in features or inactive.intersection(packages):
        raise ValueError("the excepted async Secret Service path must never be compiled")


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    try:
        result = subprocess.run(
            [
                "cargo", "tree", "--locked", "--target", "all",
                "--edges", "normal,build,dev", "--prefix", "none",
                "--format", "{p}|{f}", *sys.argv[1:],
            ],
            cwd=root,
            check=True,
            stdout=subprocess.PIPE,
            text=True,
        )
        check_tree(result.stdout)
    except (ValueError, subprocess.CalledProcessError) as error:
        print(f"keyring crypto check failed: {error}", file=sys.stderr)
        return 1
    print("keyring DH features enabled; excepted async path is not compiled")
    return 0


if __name__ == "__main__":
    sys.exit(main())
