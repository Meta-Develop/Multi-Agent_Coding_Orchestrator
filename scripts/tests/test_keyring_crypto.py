import contextlib
import io
import importlib.util
from pathlib import Path
import tomllib
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "check_keyring_crypto", ROOT / "scripts/check_keyring_crypto.py"
)
CHECK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECK)

ENCRYPTED = """coding-agent-manager v0.1.0 (/fixture)|
keyring v3.6.3|apple-native,crypto-rust,sync-secret-service,windows-native
dbus-secret-service v4.1.0|crypto-rust
"""


class KeyringCryptoTests(unittest.TestCase):
    def test_encrypted_synchronous_graph_passes(self):
        CHECK.check_tree(ENCRYPTED)

    def test_backend_crypto_alone_does_not_select_dh(self):
        # Reproduces the regression: backend crypto survives, keyring crypto
        # is removed, and the wrapper silently selects Plain.
        with self.assertRaisesRegex(ValueError, "keyring must enable"):
            CHECK.check_tree(ENCRYPTED.replace("apple-native,crypto-rust,", "apple-native,"))

    def test_backend_must_also_have_crypto(self):
        with self.assertRaisesRegex(ValueError, "dbus-secret-service"):
            CHECK.check_tree(ENCRYPTED.replace("v4.1.0|crypto-rust", "v4.1.0|"))

    def test_async_feature_invalidates_lockfile_only_exception(self):
        with self.assertRaisesRegex(ValueError, "must never be compiled"):
            CHECK.check_tree(ENCRYPTED.replace("apple-native,", "async-secret-service,"))

    def test_each_advisory_package_is_rejected_at_every_version(self):
        for name, versions in {
            "zvariant": ("4.2.0", "5.15.0", "5.15.1", "99.0.0"),
            "zvariant_derive": ("4.2.0", "5.15.0", "5.15.1", "99.0.0"),
            "zbus_names": ("3.0.0", "4.3.4", "4.3.5", "99.0.0"),
        }.items():
            for version in versions:
                package = f"{name} v{version}"
                with self.subTest(package=package):
                    with self.assertRaisesRegex(ValueError, package):
                        CHECK.check_tree(ENCRYPTED + package + "|\n")

    def test_async_package_is_rejected_even_without_the_feature(self):
        for version in ("4.0.0", "5.2.0"):
            with self.subTest(version=version):
                with self.assertRaisesRegex(ValueError, "must never be compiled"):
                    CHECK.check_tree(ENCRYPTED + f"secret-service v{version}|\n")

    def test_workspace_root_separator_lines_are_supported(self):
        CHECK.check_tree(ENCRYPTED + "\n\n" + ENCRYPTED)

    def test_other_platform_dependencies_and_deduplication_are_supported(self):
        CHECK.check_tree(ENCRYPTED + "keyring v3.6.3|crypto-rust (*)\n"
                         + "windows-sys v0.61.2|\n")

    def test_main_checks_both_workspaces(self):
        with patch.object(CHECK, "check_workspace") as check:
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(CHECK.main(), 0)
        self.assertEqual([call.args[1] for call in check.call_args_list],
                         [Path("Cargo.toml"), Path("account-manager/src-tauri/Cargo.toml")])

    def test_active_desktop_package_fails_the_shared_policy_gate(self):
        def tree_for_manifest(root, manifest):
            tree = ENCRYPTED
            if manifest == Path("account-manager/src-tauri/Cargo.toml"):
                tree += "zvariant v5.15.0|\nzbus_names v4.3.4|\n"
            CHECK.check_tree(tree)

        errors = io.StringIO()
        with patch.object(CHECK, "check_workspace", side_effect=tree_for_manifest):
            with contextlib.redirect_stderr(errors):
                self.assertEqual(CHECK.main(), 1)
        self.assertIn("account-manager/src-tauri/Cargo.toml", errors.getvalue())
        self.assertIn("zvariant v5.15.0", errors.getvalue())
        self.assertIn("zbus_names v4.3.4", errors.getvalue())

    def test_failure_in_one_workspace_does_not_skip_the_other(self):
        with patch.object(CHECK, "check_workspace", side_effect=ValueError("failed")) as check:
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(CHECK.main(), 1)
        self.assertEqual(check.call_count, 2)

    def test_cargo_graph_includes_all_targets_and_default_features(self):
        with patch.object(CHECK.subprocess, "run") as run:
            run.return_value.stdout = ENCRYPTED
            CHECK.check_workspace(ROOT, Path("account-manager/src-tauri/Cargo.toml"))
        command = run.call_args.args[0]
        self.assertEqual(command[command.index("--target") + 1], "all")
        self.assertEqual(command[command.index("--edges") + 1], "normal,build,dev")
        self.assertEqual(command[command.index("--manifest-path") + 1],
                         "account-manager/src-tauri/Cargo.toml")
        self.assertNotIn("--no-default-features", command)
        self.assertIn("--locked", command)
        self.assertIn("--workspace", command)

    def test_absent_or_upgraded_keyring_requires_review(self):
        for tree in ("", ENCRYPTED.replace("keyring v3.6.3", "keyring v4.2.0")):
            with self.subTest(tree=tree), self.assertRaises(ValueError):
                CHECK.check_tree(tree)

    def test_supply_chain_ci_runs_the_real_feature_graph_check(self):
        workflow = (ROOT / ".github/workflows/supply-chain.yml").read_text()
        self.assertIn("run: python3 scripts/check_keyring_crypto.py", workflow)

    def test_only_the_three_unmaintained_advisories_are_excepted(self):
        expected = {"RUSTSEC-2026-0370", "RUSTSEC-2026-0371", "RUSTSEC-2026-0372"}
        for config in (".cargo/audit.toml", "deny.toml"):
            with self.subTest(config=config):
                policy = tomllib.loads((ROOT / config).read_text())
                self.assertEqual(set(policy["advisories"]["ignore"]), expected)


if __name__ == "__main__":
    unittest.main()
