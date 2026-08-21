import tomllib
import unittest
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


class LibzSysDenyPolicyContractTests(unittest.TestCase):
    maxDiff = None

    def test_libz_sys_policy_is_name_scoped_with_exact_license_evidence(self):
        with (REPOSITORY_ROOT / "deny.toml").open("rb") as policy_file:
            licenses = tomllib.load(policy_file)["licenses"]

        def is_libz_sys(entry):
            return entry.get("crate", "").split("@", 1)[0] == "libz-sys"

        actual = {
            "exceptions": [
                entry for entry in licenses["exceptions"] if is_libz_sys(entry)
            ],
            "clarifications": [
                entry for entry in licenses["clarify"] if is_libz_sys(entry)
            ],
        }
        expected = {
            "exceptions": [{"allow": ["Zlib"], "crate": "libz-sys"}],
            "clarifications": [
                {
                    "crate": "libz-sys",
                    "expression": "(MIT OR Apache-2.0) AND Zlib",
                    "license-files": [
                        {"path": "LICENSE-APACHE", "hash": 0x24B54F4B},
                        {"path": "LICENSE-MIT", "hash": 0x88396382},
                        {"path": "src/zlib/LICENSE", "hash": 0xCBC15CD1},
                    ],
                }
            ],
        }

        self.assertEqual(
            expected,
            actual,
            "libz-sys must be scoped by crate name while retaining the complete "
            "Zlib exception and exact clarification evidence",
        )


if __name__ == "__main__":
    unittest.main()
