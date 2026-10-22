#!/usr/bin/env python3
"""Check encrypted keyring sessions without accessing a credential service."""

from __future__ import annotations

from pathlib import Path
import subprocess
import sys
import tomllib


def check_tree(tree: str) -> None:
    packages: dict[tuple[str, str], set[str]] = {}
    for line in tree.splitlines():
        if not line.strip():
            continue
        package, features = line.removesuffix(" (*)").split("|", 1)
        name, version, *_ = package.split()
        packages.setdefault((name, version), set()).update(features.split(","))
    # These are the reviewed keyring 4 store API and DH implementation versions.
    # The dbus store always selects EncryptionType::Dh and refuses to compile
    # without crypto. It has no optional async Secret Service dependency.
    required = {
        "keyring-core": ("v1.0.1", set()),
        "dbus-secret-service-keyring-store": ("v1.0.1", {"crypto-rust"}),
        "dbus-secret-service": ("v4.1.0", {"crypto-rust"}),
        "apple-native-keyring-store": ("v1.0.2", {"keychain"}),
        "windows-native-keyring-store": ("v1.1.0", set()),
    }
    for name, (version, features) in required.items():
        resolved = [(v, f) for (n, v), f in packages.items() if n == name]
        if len(resolved) != 1 or resolved[0][0] != version:
            raise ValueError(f"review the native store contract for {name}: expected {version}")
        if not features <= resolved[0][1]:
            raise ValueError(f"{name} must enable {', '.join(sorted(features))}")
    if any(name in {"keyring", "secret-service", "zbus-secret-service-keyring-store"}
           for name, _ in packages):
        raise ValueError("use explicit native stores, without the legacy or async keyring path")


def check_policies(root: Path) -> None:
    # No global exception may mask the desktop's independent Tauri dependencies.
    # Desktop-only dispositions are version-checked separately; they must never
    # become global exceptions affecting the native core or root workspace.
    for name in (".cargo/audit.toml", "deny.toml"):
        policy = tomllib.loads((root / name).read_text())
        advisories = policy.get("advisories", {})
        if advisories.get("ignore") != []:
            raise ValueError(f"{name} must have no advisory exceptions")
        if "unused-ignored-advisory" in advisories:
            raise ValueError(f"{name} must not allow unused advisory exceptions")


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
    try:
        check_policies(root)
    except ValueError as error:
        print(f"keyring crypto check failed: {error}", file=sys.stderr)
        return 1
    # Keep desktop defaults and every target enabled when validating stores.
    failed = False
    for manifest in (Path("Cargo.toml"), Path("account-manager/src-tauri/Cargo.toml")):
        try:
            check_workspace(root, manifest)
        except (ValueError, subprocess.CalledProcessError) as error:
            print(f"keyring crypto check failed ({manifest}): {error}", file=sys.stderr)
            failed = True
    if failed:
        return 1
    print("both workspaces use explicit DH stores; no global advisory exceptions")
    return 0


if __name__ == "__main__":
    sys.exit(main())
