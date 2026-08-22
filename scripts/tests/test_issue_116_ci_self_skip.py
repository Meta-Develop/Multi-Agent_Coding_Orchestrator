import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
PROBE = ROOT / "src" / "containment_probe.rs"
HELPER = ROOT / "src" / "test_containment.rs"


class Issue116CiSelfSkipContract(unittest.TestCase):
    def test_linux_ci_runs_plain_locked_all_targets(self):
        source = WORKFLOW.read_text(encoding="utf-8")
        self.assertNotIn(
            "CONTAINMENT_DEPENDENT_TESTS",
            source,
            "ci.yml must not keep a hand-maintained containment skip list",
        )
        self.assertNotIn("--skip", source)
        self.assertIn("cargo test --locked --all-targets\n", source)
        self.assertTrue(PROBE.is_file())
        helper = HELPER.read_text(encoding="utf-8")
        self.assertIn("skip_without_containment", helper)
        self.assertIn("skip_if_unavailable", PROBE.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
