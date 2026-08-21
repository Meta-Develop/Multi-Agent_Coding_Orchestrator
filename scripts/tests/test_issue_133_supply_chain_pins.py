import pathlib
import re
import tomllib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
PINS = ROOT / "scripts" / "supply_chain_pins.toml"
WORKFLOW = ROOT / ".github" / "workflows" / "supply-chain.yml"
FLAKE = ROOT / "flake.nix"
CONTRIBUTING = ROOT / "CONTRIBUTING.md"


class SupplyChainPinContractTests(unittest.TestCase):
    def test_pin_file_declares_explicit_tool_releases(self) -> None:
        pins = self._pins()
        self.assertEqual(set(pins), {"cargo_audit", "cargo_deny"})
        for name, value in pins.items():
            with self.subTest(name=name):
                self.assertIsInstance(value, str)
                self.assertRegex(
                    value,
                    r"^[0-9]+\.[0-9]+\.[0-9]+$",
                    f"{name} must be an explicit x.y.z release",
                )

    def test_workflow_installs_versions_from_the_pin_file(self) -> None:
        source = WORKFLOW.read_text(encoding="utf-8")
        active = self._active_text(source)

        self.assertIn('pathlib.Path("scripts/supply_chain_pins.toml")', active)
        self.assertIn(
            'cargo install --locked --version "${CARGO_AUDIT}" cargo-audit',
            active,
        )
        self.assertIn(
            'cargo install --locked --version "${CARGO_DENY}" cargo-deny',
            active,
        )
        self.assertIn(
            'if [[ "${installed_audit}" != "${CARGO_AUDIT}" ]]; then',
            active,
        )
        self.assertIn(
            'if [[ "${installed_deny}" != "${CARGO_DENY}" ]]; then',
            active,
        )
        self.assertRegex(active, r"exit 1")

        for value in self._pins().values():
            self.assertNotRegex(
                active,
                rf"(?<![0-9]){re.escape(value)}(?![0-9])",
                "supply-chain.yml must not duplicate pin versions",
            )

    def test_flake_builds_the_same_pin_file_versions(self) -> None:
        source = FLAKE.read_text(encoding="utf-8")
        active = self._active_text(source)

        self.assertIn(
            "builtins.fromTOML (builtins.readFile ./scripts/supply_chain_pins.toml)",
            active,
        )
        self.assertIn("version = supplyChainPins.cargo_audit;", active)
        self.assertIn("version = supplyChainPins.cargo_deny;", active)
        self.assertNotIn("pkgs.cargo-audit", active)
        self.assertNotIn("pkgs.cargo-deny", active)

        for value in self._pins().values():
            self.assertNotRegex(
                active,
                rf'(?<![0-9]){re.escape(value)}(?![0-9])',
                "flake.nix must not duplicate pin versions",
            )

    def test_contributing_lists_the_pinned_supply_chain_commands(self) -> None:
        source = CONTRIBUTING.read_text(encoding="utf-8")
        active = self._active_text(source)
        self.assertIn(
            "nix develop path:$PWD -c cargo audit --deny warnings",
            active,
        )
        self.assertIn(
            "nix develop path:$PWD -c cargo deny --locked check -D warnings "
            "advisories bans licenses sources",
            active,
        )

    def test_commented_pin_reads_are_rejected(self) -> None:
        source = WORKFLOW.read_text(encoding="utf-8")
        commented = source.replace(
            'pathlib.Path("scripts/supply_chain_pins.toml")',
            '# pathlib.Path("scripts/supply_chain_pins.toml")',
            1,
        )
        self.assertNotEqual(commented, source)
        active = self._active_text(commented)
        self.assertNotIn('pathlib.Path("scripts/supply_chain_pins.toml")', active)

    def _pins(self) -> dict[str, object]:
        with PINS.open("rb") as pin_file:
            return tomllib.load(pin_file)

    @staticmethod
    def _active_text(source: str) -> str:
        lines = []
        for raw_line in source.splitlines():
            text = raw_line.lstrip(" ")
            if not text or text.startswith("#"):
                continue
            lines.append(raw_line)
        return "\n".join(lines)


if __name__ == "__main__":
    unittest.main()
