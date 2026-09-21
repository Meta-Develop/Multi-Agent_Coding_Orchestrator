from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

from scripts import check_desktop_lockfile as lockcheck


ROOT = Path(__file__).resolve().parents[2]
DEPENDABOT = ROOT / ".github" / "dependabot.yml"
WORKFLOW = ROOT / ".github" / "workflows" / "account-manager.yml"
SCRIPT = ROOT / "scripts" / "check_desktop_lockfile.py"


def active_text(source: str) -> str:
    lines = []
    for raw_line in source.splitlines():
        text = raw_line.lstrip(" ")
        if not text or text.startswith("#"):
            continue
        lines.append(raw_line)
    return "\n".join(lines)


def job_text(source: str, job_id: str) -> str:
    lines = active_text(source).splitlines()
    prefix = f"  {job_id}:"
    starts = [index for index, line in enumerate(lines) if line.startswith(prefix)]
    if len(starts) != 1:
        raise AssertionError(f"expected one {job_id} job, found {len(starts)}")
    start = starts[0]
    end = start + 1
    while end < len(lines):
        line = lines[end]
        if line.startswith("  ") and not line.startswith("   ") and line.endswith(":"):
            break
        end += 1
    return "\n".join(lines[start:end])


class DependabotLockfileCoverageTests(unittest.TestCase):
    def test_cargo_covers_root_and_desktop_lockfiles(self) -> None:
        source = DEPENDABOT.read_text(encoding="utf-8")
        active = active_text(source)
        self.assertIn("package-ecosystem: \"cargo\"", active)
        self.assertIn("package-ecosystem: \"github-actions\"", active)
        self.assertIn('      - "/"', active)
        self.assertIn('      - "/account-manager/src-tauri"', active)
        self.assertIn("group-by: dependency-name", active)
        self.assertNotIn("\t", source)

        cargo_block = active.split('package-ecosystem: "github-actions"', 1)[0]
        self.assertIn("directories:", cargo_block)
        self.assertIn('      - "/"', cargo_block)
        self.assertIn('      - "/account-manager/src-tauri"', cargo_block)
        self.assertIn("group-by: dependency-name", cargo_block)
        self.assertNotIn("directory:", cargo_block)

    def test_dependabot_yaml_loads(self) -> None:
        source = DEPENDABOT.read_text(encoding="utf-8")
        loaded = load_dependabot_yaml(source)
        self.assertEqual(loaded["version"], 2)
        updates = loaded["updates"]
        self.assertEqual(len(updates), 2)
        cargo, actions = updates
        self.assertEqual(cargo["package-ecosystem"], "cargo")
        self.assertEqual(cargo["directories"], ["/", "/account-manager/src-tauri"])
        group = cargo["groups"]["cargo-across-lockfiles"]
        self.assertEqual(group["patterns"], ["*"])
        self.assertEqual(group["group-by"], "dependency-name")
        self.assertEqual(actions["package-ecosystem"], "github-actions")
        self.assertEqual(actions["directory"], "/")


class DesktopLockWorkflowTests(unittest.TestCase):
    def test_cheap_locked_check_runs_before_desktop_builds(self) -> None:
        source = WORKFLOW.read_text(encoding="utf-8")
        lock_job = job_text(source, "desktop-lock")
        rust_job = job_text(source, "rust")
        self.assertIn("needs: desktop-lock", rust_job)
        self.assertNotIn("needs: desktop-lock", job_text(source, "frontend"))
        self.assertIn(
            "python3 scripts/check_desktop_lockfile.py --parse-only", lock_job
        )
        self.assertIn(
            "python3 scripts/check_desktop_lockfile.py --cargo-only", lock_job
        )
        parse_at = lock_job.index("--parse-only")
        rustup_at = lock_job.index("rustup toolchain install")
        cargo_at = lock_job.index("--cargo-only")
        self.assertLess(parse_at, rustup_at)
        self.assertLess(rustup_at, cargo_at)
        self.assertNotIn("webkit", lock_job.lower())
        self.assertNotIn("libsoup", lock_job.lower())
        self.assertNotIn("continue-on-error", lock_job)
        self.assertNotIn("if: ${{ false }}", lock_job)

    def test_commented_lock_job_is_rejected(self) -> None:
        source = WORKFLOW.read_text(encoding="utf-8")
        commented = source.replace("  desktop-lock:\n", "  # desktop-lock:\n", 1)
        self.assertNotEqual(commented, source)
        with self.assertRaises(AssertionError):
            job_text(commented, "desktop-lock")


class SharedCoreConsumerTests(unittest.TestCase):
    def test_script_tracks_both_consuming_lockfiles(self) -> None:
        paths = {consumer.lockfile.as_posix() for consumer in lockcheck.CONSUMERS}
        self.assertEqual(
            paths,
            {"Cargo.lock", "account-manager/src-tauri/Cargo.lock"},
        )
        desktop = next(
            consumer
            for consumer in lockcheck.CONSUMERS
            if consumer.lockfile.as_posix().endswith("src-tauri/Cargo.lock")
        )
        self.assertEqual(
            desktop.cargo_metadata_args,
            ("--manifest-path", "account-manager/src-tauri/Cargo.toml"),
        )
        self.assertIn("metadata", SCRIPT.read_text(encoding="utf-8"))
        self.assertIn("--locked", SCRIPT.read_text(encoding="utf-8"))

    def test_current_tree_consumers_match_core_requirements(self) -> None:
        self.assertEqual(lockcheck.check_core_consumers(ROOT), [])
        self.assertEqual(lockcheck.main(["--parse-only", str(ROOT)]), 0)

    def test_core_requirement_bump_cannot_omit_desktop_lock(self) -> None:
        errors = lockcheck.consumer_incompatibilities(
            tomllib_core(base64_req="0.23"),
            tomllib_lock(
                core_deps=['base64 0.22.1', "serde"],
                extra_packages=(("base64", "0.22.1"), ("serde", "1.0.0")),
            ),
            "desktop workspace",
            Path("account-manager/src-tauri/Cargo.lock"),
        )
        self.assertTrue(any("desktop workspace" in error for error in errors))
        self.assertTrue(any("base64" in error and "0.22.1" in error for error in errors))
        self.assertTrue(any("0.23" in error for error in errors))

        compatible = lockcheck.consumer_incompatibilities(
            tomllib_core(base64_req="0.23"),
            tomllib_lock(
                core_deps=["base64", "serde"],
                extra_packages=(("base64", "0.23.2"), ("serde", "1.0.0")),
            ),
            "desktop workspace",
            Path("account-manager/src-tauri/Cargo.lock"),
        )
        self.assertEqual(compatible, [])

    def test_omitted_consumer_lockfile_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "account-manager" / "core").mkdir(parents=True)
            (root / "account-manager" / "core" / "Cargo.toml").write_text(
                CORE_TOML.format(base64_req="0.22"),
                encoding="utf-8",
            )
            (root / "Cargo.lock").write_text(
                lockfile_text(
                    core_deps=["base64"],
                    extra_packages=(("base64", "0.22.1"),),
                ),
                encoding="utf-8",
            )
            errors = lockcheck.check_core_consumers(root)
        self.assertTrue(
            any("account-manager/src-tauri/Cargo.lock" in error for error in errors)
        )
        self.assertTrue(any("desktop workspace" in error for error in errors))

    def test_representative_update_tree_flags_stale_desktop_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_consumer_tree(
                root,
                base64_req="0.23",
                root_base64="0.23.2",
                desktop_base64="0.22.1",
            )
            errors = lockcheck.check_core_consumers(root)
        self.assertTrue(any("desktop workspace" in error for error in errors))
        self.assertFalse(
            any(error.startswith("root workspace:") for error in errors)
        )

    def test_locked_metadata_names_the_failing_consumer(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            mock = root / "cargo_mock.py"
            mock.write_text(CARGO_MOCK, encoding="utf-8")
            errors = lockcheck.run_locked_metadata(root, [sys.executable, str(mock)])
        self.assertEqual(len(errors), 1)
        self.assertIn("desktop workspace", errors[0])
        self.assertIn("--locked", errors[0])
        self.assertIn("account-manager/src-tauri/Cargo.lock", errors[0])
        self.assertIn("lock file needs to be updated", errors[0])


def tomllib_core(base64_req: str) -> dict[str, object]:
    import tomllib

    return tomllib.loads(CORE_TOML.format(base64_req=base64_req))


def tomllib_lock(
    core_deps: list[str], extra_packages: tuple[tuple[str, str], ...]
) -> dict[str, object]:
    import tomllib

    return tomllib.loads(
        lockfile_text(core_deps=core_deps, extra_packages=extra_packages)
    )


def write_consumer_tree(
    root: Path,
    *,
    base64_req: str,
    root_base64: str,
    desktop_base64: str,
) -> None:
    (root / "account-manager" / "core").mkdir(parents=True)
    (root / "account-manager" / "src-tauri").mkdir(parents=True)
    (root / "account-manager" / "core" / "Cargo.toml").write_text(
        CORE_TOML.format(base64_req=base64_req),
        encoding="utf-8",
    )
    (root / "Cargo.lock").write_text(
        lockfile_text(
            core_deps=["base64", "serde"],
            extra_packages=(("base64", root_base64), ("serde", "1.0.0")),
        ),
        encoding="utf-8",
    )
    (root / "account-manager" / "src-tauri" / "Cargo.lock").write_text(
        lockfile_text(
            core_deps=[f"base64 {desktop_base64}", "serde"],
            extra_packages=(("base64", desktop_base64), ("serde", "1.0.0")),
        ),
        encoding="utf-8",
    )


def lockfile_text(
    *,
    core_deps: list[str],
    extra_packages: tuple[tuple[str, str], ...],
) -> str:
    blocks = ["version = 4", ""]
    for name, version in extra_packages:
        blocks.append("[[package]]")
        blocks.append(f'name = "{name}"')
        blocks.append(f'version = "{version}"')
        blocks.append('source = "registry+https://github.com/rust-lang/crates.io-index"')
        blocks.append("")
    blocks.append("[[package]]")
    blocks.append(f'name = "{lockcheck.CORE_PACKAGE}"')
    blocks.append('version = "0.1.0"')
    blocks.append("dependencies = [")
    for spec in core_deps:
        blocks.append(f' "{spec}",')
    blocks.append("]")
    blocks.append("")
    return "\n".join(blocks)


CORE_TOML = """
[package]
name = "coding-agent-manager"
version = "0.1.0"
edition = "2021"

[dependencies]
base64 = "{base64_req}"
serde = "1"
"""

CARGO_MOCK = r"""
import sys

args = sys.argv[1:]
if "--locked" not in args or "metadata" not in args:
    sys.stderr.write("expected cargo metadata --locked\n")
    sys.exit(3)
manifest = ""
if "--manifest-path" in args:
    manifest = args[args.index("--manifest-path") + 1].replace("\\", "/")
if "src-tauri" in manifest:
    sys.stderr.write("error: the lock file needs to be updated\n")
    sys.exit(101)
sys.stdout.write("{}\n")
"""


def load_dependabot_yaml(source: str) -> dict[str, object]:
    yaml_spec = importlib.util.find_spec("yaml")
    if yaml_spec is not None:
        yaml = importlib.import_module("yaml")
        loaded = yaml.safe_load(source)
        if not isinstance(loaded, dict):
            raise AssertionError("dependabot.yml must load as a mapping")
        return loaded
    return parse_simple_yaml(source)


def parse_simple_yaml(source: str) -> dict[str, object]:
    if "\t" in source:
        raise AssertionError("dependabot.yml must not use tabs")
    lines = [
        (len(raw) - len(raw.lstrip(" ")), raw.lstrip(" ").rstrip())
        for raw in source.splitlines()
        if raw.strip() and not raw.lstrip().startswith("#")
    ]

    def parse_value(text: str) -> object:
        if text.startswith('"') and text.endswith('"'):
            return text[1:-1]
        if text.isdigit():
            return int(text)
        return text

    def parse_block(index: int, indent: int) -> tuple[object, int]:
        if index < len(lines) and lines[index][0] == indent and lines[index][1].startswith("- "):
            items: list[object] = []
            while index < len(lines) and lines[index][0] == indent and lines[index][1].startswith("- "):
                item_text = lines[index][1][2:]
                index += 1
                if ": " in item_text or item_text.endswith(":"):
                    key, _, rest = item_text.partition(":")
                    mapping: dict[str, object] = {}
                    rest = rest.strip()
                    if rest:
                        mapping[key] = parse_value(rest)
                    if index < len(lines) and lines[index][0] > indent:
                        nested, index = parse_block(index, lines[index][0])
                        if isinstance(nested, dict):
                            mapping.update(nested)
                    items.append(mapping)
                else:
                    items.append(parse_value(item_text))
            return items, index

        mapping: dict[str, object] = {}
        while index < len(lines) and lines[index][0] == indent:
            key, _, rest = lines[index][1].partition(":")
            rest = rest.strip()
            index += 1
            if rest:
                mapping[key] = parse_value(rest)
                continue
            if index >= len(lines) or lines[index][0] <= indent:
                mapping[key] = None
                continue
            mapping[key], index = parse_block(index, lines[index][0])
        return mapping, index

    loaded, index = parse_block(0, 0)
    if index != len(lines) or not isinstance(loaded, dict):
        raise AssertionError("dependabot.yml is not valid mapping YAML")
    return loaded


if __name__ == "__main__":
    unittest.main()
