"""Keep dependency reuse separate from same-run workspace/package identity."""

import pathlib
import re
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]


class CiDependencyCacheTests(unittest.TestCase):
    def test_workspace_artifacts_and_installed_tools_are_never_cached(self):
        source = (ROOT / ".github/workflows/ci.yml").read_text()
        caches = re.findall(
            r"      - name: Cache Rust dependencies\n(.*?)(?=\n      - name:)",
            source, re.DOTALL,
        )
        self.assertEqual(len(caches), 3)
        for cache in caches:
            self.assertRegex(cache, r"uses: Swatinem/rust-cache@[0-9a-f]{40} ")
            self.assertIn('cache-workspace-crates: "false"', cache)
            self.assertIn('cache-bin: "false"', cache)
            # Retain the action's toolchain, Cargo.lock and manifest keying.
            self.assertNotIn("add-rust-environment-hash-key:", cache)
            self.assertTrue('save-if: "false"' in cache or "github.ref == 'refs/heads/main'" in cache)

    def test_linux_caches_follow_same_run_package_qualification(self):
        source = (ROOT / ".github/workflows/ci.yml").read_text()
        for name, end in (("linux-library", "linux-integration"), ("linux-integration", "linux-gate")):
            job = source.split(f"  {name}:\n", 1)[1].split(f"  {end}:\n", 1)[0]
            self.assertIn("needs: nix-package", job)
            self.assertLess(job.index("Verify independent bindings, import, and qualify"),
                            job.index("Cache Rust dependencies"))
            self.assertIn('target.write(f"MACO_SOURCE_MANIFEST_SHA256=', job)
            self.assertIn("artifact-ids: ${{ needs.nix-package.outputs.artifact_id }}", job)
            self.assertLess(job.index("Cache Rust dependencies"),
                            job.index("Require cache to preserve checked-out source"))
            self.assertIn("git diff --no-ext-diff --no-textconv --exit-code HEAD -- .", job)
            first_build_step = "Check formatting" if name == "linux-library" else "Run integration and binary tests"
            self.assertLess(job.index("Require cache to preserve checked-out source"),
                            job.index(first_build_step))

    def test_cache_metadata_cannot_silently_repair_a_lockfile(self):
        source = (ROOT / ".github/workflows/ci.yml").read_text()
        self.assertEqual(source.count("run: git diff --no-ext-diff --no-textconv --exit-code HEAD -- ."), 3)
        portable = source.split("  portable-build:\n", 1)[1].split("  required-rust-gate:\n", 1)[0]
        self.assertLess(portable.index("Cache Rust dependencies"),
                        portable.index("Require cache to preserve checked-out source"))
        self.assertLess(portable.index("Require cache to preserve checked-out source"),
                        portable.index("Check all targets against Cargo.lock"))

    def test_package_parallelism_retains_single_sandboxed_build(self):
        source = (ROOT / ".github/workflows/nix-package.yml").read_text()
        self.assertIn("--max-jobs 1 --cores 4 --option sandbox true", source)
        self.assertIn("--no-update-lock-file --no-write-lock-file --no-link", source)


if __name__ == "__main__":
    unittest.main()
