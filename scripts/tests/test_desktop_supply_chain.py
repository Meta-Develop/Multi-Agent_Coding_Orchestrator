"""Regression tests for the boundary around desktop-only advisory exceptions."""

import copy
import importlib.util
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location(
    "desktop_supply_chain", Path(__file__).resolve().parents[1] / "check_desktop_supply_chain.py"
)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class DesktopSupplyChainTests(unittest.TestCase):
    def setUp(self):
        self.entry = {
            "id": "RUSTSEC-2024-0429", "package": "glib", "version": "0.18.5",
            "reason": "GTK3 requires the old binding", "removal": "Upgrade the desktop runtime",
        }
        self.manifest = {"package": {"metadata": {"desktop-advisories": [self.entry]}}}
        self.package = {"name": "glib", "version": "0.18.5", "source": "registry+https://github.com/rust-lang/crates.io-index"}
        self.lock = {"package": [self.package]}
        self.policy = {"advisories": {"unused-ignored-advisory": "deny", "unsound": "all", "ignore": [{"id": self.entry["id"], "reason": self.entry["reason"]}]}}

    def check(self):
        return MODULE.check_exceptions(self.manifest, self.lock, self.policy)

    def test_exact_reviewed_version(self):
        self.assertEqual(self.check(), [self.entry["id"]])

    def test_changed_missing_or_additional_version_requires_review(self):
        for packages in ([], [{**self.package, "version": "0.18.6"}], [self.package, {**self.package, "version": "0.20.0"}]):
            with self.subTest(packages=packages), self.assertRaises(ValueError):
                self.lock["package"] = packages
                self.check()

    def test_source_replacement_requires_review(self):
        self.package["source"] = "git+https://example.invalid/replacement"
        with self.assertRaises(ValueError):
            self.check()

    def test_wildcard_or_missing_rationale_rejected(self):
        for key, value in (("version", "0.18.*"), ("reason", ""), ("removal", "")):
            original = copy.deepcopy(self.entry)
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.entry[key] = value
                self.check()
            self.entry.update(original)

    def test_unreviewed_or_duplicate_ignore_rejected(self):
        for ignored in ([], ["RUSTSEC-2024-0429"], self.policy["advisories"]["ignore"] * 2):
            with self.subTest(ignored=ignored), self.assertRaises(ValueError):
                self.policy["advisories"]["ignore"] = ignored
                self.check()

    def test_unused_or_transitive_advisories_cannot_be_silenced(self):
        for key, value in (("unused-ignored-advisory", "allow"), ("unsound", "workspace")):
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.policy["advisories"][key] = value
                self.check()
            self.policy["advisories"][key] = "deny" if key.startswith("unused") else "all"

    def report(self):
        return {
            "vulnerabilities": {"found": False, "list": []},
            "warnings": {"unsound": [{"advisory": {"id": self.entry["id"]}, "package": self.package}]},
        }

    def test_actual_advisory_identity_is_bound_to_version(self):
        MODULE.check_report(self.report(), [self.entry])
        self.entry["package"] = "different-reviewed-package"
        with self.assertRaises(ValueError):
            MODULE.check_report(self.report(), [self.entry])

    def test_new_vulnerability_or_warning_is_not_ignored(self):
        report = self.report()
        report["vulnerabilities"] = {"found": True, "list": [{"advisory": {"id": self.entry["id"]}}]}
        with self.assertRaises(ValueError):
            MODULE.check_report(report, [self.entry])
        report = self.report()
        report["warnings"]["yanked"] = [{"package": self.package}]
        with self.assertRaises(ValueError):
            MODULE.check_report(report, [self.entry])

    def test_obsolete_exceptions_and_invalid_reports_fail_closed(self):
        for report in ({}, {"vulnerabilities": {"found": False, "list": []}, "warnings": {}}):
            with self.subTest(report=report), self.assertRaises(ValueError):
                MODULE.check_report(report, [self.entry])

    def test_last_exception_can_be_removed_after_upstream_fix(self):
        self.manifest["package"].pop("metadata")
        self.policy["advisories"]["ignore"] = []
        self.assertEqual(self.check(), [])
        MODULE.check_report({"vulnerabilities": {"found": False, "list": []}, "warnings": {}}, [])


if __name__ == "__main__":
    unittest.main()
