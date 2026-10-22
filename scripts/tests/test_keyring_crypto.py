import contextlib
import io
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "check_keyring_crypto", ROOT / "scripts/check_keyring_crypto.py"
)
CHECK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECK)

ENCRYPTED = """coding-agent-manager v0.1.0 (/fixture)|
keyring-core v1.0.1|
dbus-secret-service-keyring-store v1.0.1|crypto-rust
dbus-secret-service v4.1.0|crypto-rust
apple-native-keyring-store v1.0.2|keychain
windows-native-keyring-store v1.1.0|default,search
"""


class KeyringCryptoTests(unittest.TestCase):
    def test_explicit_encrypted_native_stores_pass(self):
        CHECK.check_tree(ENCRYPTED)

    def test_backend_crypto_alone_does_not_enable_the_store_crypto(self):
        with self.assertRaisesRegex(ValueError, "store must enable crypto-rust"):
            CHECK.check_tree(ENCRYPTED.replace("store v1.0.1|crypto-rust", "store v1.0.1|"))

    def test_backend_must_also_have_crypto(self):
        with self.assertRaisesRegex(ValueError, "dbus-secret-service must enable"):
            CHECK.check_tree(ENCRYPTED.replace("v4.1.0|crypto-rust", "v4.1.0|"))

    def test_mac_store_must_keep_legacy_keychain(self):
        with self.assertRaisesRegex(ValueError, "must enable keychain"):
            CHECK.check_tree(ENCRYPTED.replace("v1.0.2|keychain", "v1.0.2|protected"))

    def test_each_missing_or_upgraded_store_requires_review(self):
        for line in ENCRYPTED.splitlines()[1:]:
            with self.subTest(line=line):
                with self.assertRaises(ValueError):
                    CHECK.check_tree(ENCRYPTED.replace(line, ""))
                with self.assertRaises(ValueError):
                    CHECK.check_tree(ENCRYPTED.replace(line, line.replace(" v1.", " v2.").replace(" v4.", " v5.")))

    def test_legacy_and_async_keyring_paths_are_rejected(self):
        for package in ("keyring v3.6.3", "secret-service v4.0.0",
                        "zbus-secret-service-keyring-store v1.0.0"):
            with self.subTest(package=package), self.assertRaisesRegex(ValueError, "legacy or async"):
                CHECK.check_tree(ENCRYPTED + package + "|\n")

    def test_unrelated_desktop_packages_are_audited_without_global_ignores(self):
        # The clean route removes all advisory ignores instead of suppressing
        # desktop zbus warnings. Normal audit must report these independently.
        CHECK.check_tree(ENCRYPTED + "zvariant v5.15.0|\nzbus_names v4.3.4|\n")
        CHECK.check_policies(ROOT)

    def test_advisory_exceptions_cannot_be_reintroduced(self):
        for name in (".cargo/audit.toml", "deny.toml"):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                for config in (".cargo/audit.toml", "deny.toml"):
                    path = root / config
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text('[advisories]\nignore = []\n')
                (root / name).write_text('[advisories]\nignore = ["RUSTSEC-2026-0370"]\n')
                with self.assertRaisesRegex(ValueError, "no advisory exceptions"):
                    CHECK.check_policies(root)

    def test_unused_ignore_allowance_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".cargo").mkdir()
            (root / ".cargo/audit.toml").write_text('[advisories]\nignore = []\n')
            (root / "deny.toml").write_text('[advisories]\nignore = []\nunused-ignored-advisory = "allow"\n')
            with self.assertRaisesRegex(ValueError, "unused advisory"):
                CHECK.check_policies(root)

    def test_workspace_separator_and_deduplication_lines_are_supported(self):
        CHECK.check_tree(ENCRYPTED + "\n\n" + ENCRYPTED
                         + "keyring-core v1.0.1| (*)\nwindows-sys v0.61.2|\n")

    def test_main_checks_both_workspaces(self):
        with patch.object(CHECK, "check_workspace") as check:
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(CHECK.main(), 0)
        self.assertEqual([call.args[1] for call in check.call_args_list],
                         [Path("Cargo.toml"), Path("account-manager/src-tauri/Cargo.toml")])

    def test_policy_failure_blocks_the_shared_gate(self):
        with patch.object(CHECK, "check_policies", side_effect=ValueError("no ignores")):
            with patch.object(CHECK, "check_workspace") as check:
                with contextlib.redirect_stderr(io.StringIO()):
                    self.assertEqual(CHECK.main(), 1)
        check.assert_not_called()

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
        self.assertNotIn("--no-default-features", command)
        self.assertIn("--locked", command)
        self.assertIn("--workspace", command)

    def test_supply_chain_ci_runs_the_real_feature_graph_check(self):
        workflow = (ROOT / ".github/workflows/supply-chain.yml").read_text()
        self.assertIn("run: python3 scripts/check_keyring_crypto.py", workflow)


if __name__ == "__main__":
    unittest.main()
