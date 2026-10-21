import importlib.util
from pathlib import Path
import tomllib
import unittest


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

    def test_each_advisory_package_must_remain_inactive(self):
        for package in ("secret-service v4.0.0", "zvariant v4.2.0",
                        "zvariant_derive v4.2.0", "zbus_names v3.0.0"):
            with self.subTest(package=package):
                with self.assertRaisesRegex(ValueError, "must never be compiled"):
                    CHECK.check_tree(ENCRYPTED + package + "|\n")

    def test_other_platform_dependencies_and_deduplication_are_supported(self):
        CHECK.check_tree(ENCRYPTED + "keyring v3.6.3|crypto-rust (*)\n"
                         + "zvariant v5.15.1|\n")

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
