import hashlib
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
HELPER = ROOT / ".github" / "scripts" / "install-github-hosted-ci-codex.sh"
LIB = ROOT / ".github" / "scripts" / "install-github-hosted-ci-codex.lib.sh"
WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"

PINNED_CODEX_SHA256 = (
    "37c985be9d89e8c4f43b3aa0594c1213eac212d30ae2b95221f08fec807515d1"
)
PINNED_BWRAP_SHA256 = (
    "bf821348773e12a8c10b901759679824d0bb96482c9fcf2cc1eb6f866ec614d7"
)
CODEX_ARCHIVE_MEMBER = "codex-x86_64-unknown-linux-musl"
BWRAP_ARCHIVE_MEMBER = "bwrap-x86_64-unknown-linux-musl"
NESTED_CODEX_TEST = (
    "process_runner::tests::nested_codex_profile_appends_exact_journal_"
    "while_outer_keeps_parent_nonwritable"
)


class InstallGithubHostedCiCodexGuardTests(unittest.TestCase):
    def setUp(self) -> None:
        self.assertTrue(HELPER.is_file())
        self.source = HELPER.read_text(encoding="utf-8")

    def _fake_sudo(self, directory: Path) -> Path:
        sudo = directory / "sudo"
        sudo.write_text("#!/bin/sh\necho SUDO_INVOKED >&2\nexit 97\n", encoding="utf-8")
        sudo.chmod(sudo.stat().st_mode | stat.S_IXUSR)
        return sudo

    def _run(self, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["bash", str(HELPER)],
            check=False,
            capture_output=True,
            text=True,
            env=env,
        )

    def test_pinned_provenance_constants(self) -> None:
        self.assertIn(f"readonly CODEX_EXPECTED_SHA256={PINNED_CODEX_SHA256}", self.source)
        self.assertIn(f"readonly BWRAP_EXPECTED_SHA256={PINNED_BWRAP_SHA256}", self.source)
        self.assertIn("readonly RELEASE_TAG=rust-v0.144.4", self.source)
        self.assertIn(f"readonly CODEX_ARCHIVE_MEMBER={CODEX_ARCHIVE_MEMBER}", self.source)
        self.assertIn(f"readonly BWRAP_ARCHIVE_MEMBER={BWRAP_ARCHIVE_MEMBER}", self.source)
        self.assertIn("readonly BWRAP_INSTALL_PATH=/usr/bin/codex-resources/bwrap", self.source)
        self.assertIn("readonly CODEX_RESOURCES_DIR=/usr/bin/codex-resources", self.source)
        self.assertIn("readonly CODEX_VERSION=0.144.4", self.source)
        lib = LIB.read_text(encoding="utf-8")
        self.assertIn(
            'version_output="$("${INSTALL_PATH}" --version 2>&1 | tr -d \'\\r\')"',
            lib,
        )
        self.assertNotIn("head -n1", lib)
        self.assertIn(
            'rm -f -- "${codex_archive}" "${bwrap_archive}"', self.source
        )
        self.assertNotIn("rm -rf", self.source)
        self.assertIn("readonly BWRAP_EXPECTED_BYTES=261563", self.source)
        self.assertIn('validate-tar "${archive}" "${archive_member}"', self.source)
        self.assertNotIn("--wildcards", self.source)
        self.assertNotIn("--strip-components", self.source)
        self.assertIn(
            "readonly CODEX_ASSET_API_URL=https://api.github.com/repos/"
            "openai/codex/releases/assets/476296992",
            self.source,
        )
        self.assertIn(
            "readonly BWRAP_ASSET_API_URL=https://api.github.com/repos/"
            "openai/codex/releases/assets/476297033",
            self.source,
        )
        self.assertIn('"${CODEX_EXPECTED_SHA256}" "${CODEX_ASSET_API_URL}"', self.source)
        self.assertIn('"${BWRAP_EXPECTED_SHA256}" "${BWRAP_ASSET_API_URL}"', self.source)

    def test_already_installed_codex_does_not_skip_bundled_bwrap(self) -> None:
        codex_marker = 'install_github_hosted_ci_codex_install_verified_artifact \\\n  "${codex_extracted}"'
        bwrap_marker = 'install_github_hosted_ci_codex_install_verified_artifact \\\n  "${bwrap_extracted}"'
        codex_idx = self.source.index(codex_marker)
        bwrap_idx = self.source.index(bwrap_marker)
        between = self.source[codex_idx:bwrap_idx]
        self.assertNotIn("exit 0", between)
        self.assertIn("verify_resource_parent_dir", between)

    def test_refuses_without_github_actions_before_sudo(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            self._fake_sudo(tmp_path)
            env = {
                "PATH": f"{tmp_path}{os.pathsep}{os.environ.get('PATH', '/usr/bin:/bin')}",
                "HOME": tmp,
                "RUNNER_TEMP": tmp,
            }
            result = self._run(env)
            combined = result.stdout + result.stderr
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("GITHUB_ACTIONS is not true", result.stderr)
            self.assertNotIn("SUDO_INVOKED", combined)

    def test_self_hosted_runner_refuses_before_download(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            self._fake_sudo(tmp_path)
            env = {
                "PATH": f"{tmp_path}{os.pathsep}{os.environ.get('PATH', '/usr/bin:/bin')}",
                "HOME": tmp,
                "RUNNER_TEMP": tmp,
                "GITHUB_ACTIONS": "true",
                "RUNNER_ENVIRONMENT": "self-hosted",
            }
            result = self._run(env)
            combined = result.stdout + result.stderr
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("self-hosted is unsupported", result.stderr)
            self.assertNotIn("SUDO_INVOKED", combined)

    def _run_lib(self, env: dict[str, str], snippet: str) -> subprocess.CompletedProcess[str]:
        script = f"""
set -euo pipefail
CODEX_VERSION=0.144.4
source "{LIB}"
{snippet}
"""
        return subprocess.run(
            ["bash", "-c", script],
            check=False,
            capture_output=True,
            text=True,
            env={"PATH": os.environ.get("PATH", os.defpath), **env},
        )

    def test_lib_refuses_dangling_destination_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            destination = Path(tmp) / "codex"
            destination.symlink_to("/missing/codex-target")
            result = self._run_lib(
                {"INSTALL_PATH": str(destination)},
                "install_github_hosted_ci_codex_refuse_destination_symlink",
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("is a symlink", result.stderr)

    def test_lib_refuses_resource_parent_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            resource = Path(tmp) / "codex-resources"
            resource.symlink_to("/missing/resources")
            result = self._run_lib(
                {},
                f'install_github_hosted_ci_codex_refuse_path_symlink "{resource}"',
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("is a symlink", result.stderr)

    def test_lib_refuses_existing_file_with_authenticated_digest_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            destination = Path(tmp) / "bwrap"
            destination.write_bytes(b"wrong-bytes")
            result = self._run_lib(
                {"INSTALL_PATH": str(destination)},
                'install_github_hosted_ci_codex_destination_digest_state "deadbeef"',
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("digest does not match", result.stderr)

    def test_linux_job_runs_nested_codex_test_before_full_suite(self) -> None:
        source = WORKFLOW.read_text(encoding="utf-8")
        install = "bash .github/scripts/install-github-hosted-ci-codex.sh"
        nested = NESTED_CODEX_TEST
        nested_step = "name: Verify nested Codex sandbox integration"
        full_step = "name: Run library tests"
        linux_job = source.split("linux-library:", 1)[1].split("linux-integration:", 1)[0]
        self.assertIn(install, linux_job)
        self.assertIn(nested, linux_job)
        self.assertIn(nested_step, linux_job)
        self.assertIn(full_step, linux_job)
        self.assertIn("cargo test --locked --lib", linux_job)
        self.assertLess(linux_job.index(install), linux_job.index(nested_step))
        self.assertLess(linux_job.index(nested_step), linux_job.index(full_step))
        integration_job = source.split("linux-integration:", 1)[1].split("linux-gate:", 1)[0]
        self.assertIn(install, integration_job)
        self.assertIn(
            "bash .github/scripts/run-linux-ci-cargo-test-partition.sh non-lib",
            integration_job,
        )



class ArchiveTransportTests(unittest.TestCase):
    def _transport(
        self,
        *,
        primary_status: int = 0,
        fallback_status: int = 0,
        primary_payload: str = "fixture-archive",
        fallback_payload: str = "fixture-archive",
        cached_payload: str | None = None,
        asset_id: int = 476296992,
        archive_name: str = "codex-x86_64-unknown-linux-musl.tar.gz",
    ) -> tuple[subprocess.CompletedProcess[str], list[list[str]], bytes]:
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            archive = directory / archive_name
            calls = directory / "calls.jsonl"
            if cached_payload is not None:
                archive.write_text(cached_payload, encoding="utf-8")
            curl = directory / "curl"
            curl.write_text(
                f"#!{sys.executable}\n"
                "import json, os, sys\n"
                "from pathlib import Path\n"
                "args = sys.argv[1:]\n"
                "with open(os.environ['CALLS'], 'a', encoding='utf-8') as log:\n"
                "    log.write(json.dumps(args) + '\\n')\n"
                "route = 'FALLBACK' if args[-1].startswith('https://api.github.com/') else 'PRIMARY'\n"
                "Path(args[args.index('-o') + 1]).write_text(os.environ[route + '_PAYLOAD'], encoding='utf-8')\n"
                "sys.exit(int(os.environ[route + '_STATUS']))\n",
                encoding="utf-8",
            )
            curl.chmod(0o755)
            payload = b"fixture-archive"
            digest = hashlib.sha256(payload).hexdigest()
            api_url = f"https://api.github.com/repos/openai/codex/releases/assets/{asset_id}"
            download_url = (
                "https://github.com/openai/codex/releases/download/"
                f"rust-v0.144.4/{archive_name}"
            )
            script = f'''set -euo pipefail
source "{LIB}"
die() {{ install_github_hosted_ci_codex_die "$@"; }}
ensure_authenticated_archive "{archive}" "{download_url}" "{len(payload)}" "{digest}" "{api_url}"
printf '%s\n' AUTHENTICATED
'''
            result = subprocess.run(
                ["bash", "-c", script],
                check=False,
                capture_output=True,
                text=True,
                env={
                    "PATH": f"{directory}{os.pathsep}{os.defpath}",
                    "CALLS": str(calls),
                    "PRIMARY_STATUS": str(primary_status),
                    "FALLBACK_STATUS": str(fallback_status),
                    "PRIMARY_PAYLOAD": primary_payload,
                    "FALLBACK_PAYLOAD": fallback_payload,
                },
            )
            recorded = (
                [json.loads(line) for line in calls.read_text().splitlines()]
                if calls.exists()
                else []
            )
            return result, recorded, archive.read_bytes()

    def _refused(self, result: subprocess.CompletedProcess[str], message: str) -> None:
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(message, result.stderr)
        self.assertNotIn("AUTHENTICATED", result.stdout)

    def test_primary_success_uses_only_release_route(self) -> None:
        result, calls, content = self._transport()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "AUTHENTICATED")
        self.assertEqual(content, b"fixture-archive")
        self.assertEqual(len(calls), 1)
        self.assertIn("--retry-all-errors", calls[0])
        self.assertEqual(calls[0][calls[0].index("--retry") + 1], "5")
        self.assertEqual(calls[0][calls[0].index("--retry-delay") + 1], "2")
        self.assertTrue(calls[0][-1].startswith("https://github.com/openai/codex/"))

    def test_failed_release_route_replaces_partial_with_pinned_api_asset(self) -> None:
        for asset_id, name in [
            (476296992, "codex-x86_64-unknown-linux-musl.tar.gz"),
            (476297033, "bwrap-x86_64-unknown-linux-musl.tar.gz"),
        ]:
            with self.subTest(asset_id=asset_id):
                result, calls, content = self._transport(
                    primary_status=22,
                    primary_payload="partial release download",
                    asset_id=asset_id,
                    archive_name=name,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(content, b"fixture-archive")
                self.assertEqual(len(calls), 2)
                fallback = calls[1]
                self.assertEqual(
                    fallback[-1],
                    f"https://api.github.com/repos/openai/codex/releases/assets/{asset_id}",
                )
                self.assertEqual(fallback[fallback.index("-H") + 1], "Accept: application/octet-stream")
                self.assertIn("-fsSL", fallback)
                self.assertEqual(fallback[fallback.index("--proto") + 1], "=https")
                self.assertIn("--tlsv1.2", fallback)
                self.assertNotIn("--retry", fallback)
                self.assertFalse(any("Authorization" in arg for arg in fallback))

    def test_both_routes_failing_refuse_even_with_valid_partial_bytes(self) -> None:
        result, calls, _ = self._transport(primary_status=22, fallback_status=22)
        self._refused(result, "download failed on both routes")
        self.assertEqual(len(calls), 2)

    def test_fallback_wrong_size_refuses_before_extraction(self) -> None:
        result, calls, _ = self._transport(primary_status=22, fallback_payload="short")
        self._refused(result, "downloaded archive size does not match")
        self.assertEqual(len(calls), 2)

    def test_fallback_wrong_digest_refuses_before_extraction(self) -> None:
        result, calls, _ = self._transport(
            primary_status=22, fallback_payload="fixture-archivX"
        )
        self._refused(result, "downloaded archive SHA256 does not match")
        self.assertEqual(len(calls), 2)

    def test_primary_integrity_failure_does_not_use_fallback(self) -> None:
        for payload, message in [
            ("short", "downloaded archive size does not match"),
            ("fixture-archivX", "downloaded archive SHA256 does not match"),
        ]:
            with self.subTest(payload=payload):
                result, calls, _ = self._transport(primary_payload=payload)
                self._refused(result, message)
                self.assertEqual(len(calls), 1)

    def test_authenticated_cache_needs_no_transport(self) -> None:
        result, calls, _ = self._transport(cached_payload="fixture-archive")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "AUTHENTICATED")
        self.assertEqual(calls, [])

    def test_corrupt_cache_refuses_without_transport(self) -> None:
        for payload, message in [
            ("short", "cached archive size does not match"),
            ("fixture-archivX", "cached archive SHA256 does not match"),
        ]:
            with self.subTest(payload=payload):
                result, calls, _ = self._transport(cached_payload=payload)
                self._refused(result, message)
                self.assertEqual(calls, [])
