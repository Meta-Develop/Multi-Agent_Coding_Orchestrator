import io
import tarfile
import tempfile
import unittest
from pathlib import Path

from scripts.install_github_hosted_ci_codex_validate import (
    ValidationError,
    refuse_destination_symlink,
    require_digest_match_or_absent,
    sha256_hex,
    validate_tar_single_regular_member,
)


class TarMemberValidationTests(unittest.TestCase):
    def _write_archive(self, path: Path, members: list[tuple[str, bytes, int]]) -> None:
        with tarfile.open(path, mode="w:gz") as archive:
            for name, payload, tar_type in members:
                info = tarfile.TarInfo(name=name)
                info.type = tar_type
                info.size = len(payload)
                archive.addfile(info, io.BytesIO(payload))

    def test_accepts_single_regular_member(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            archive = Path(tmp) / "release.tar.gz"
            self._write_archive(
                archive,
                [("codex-x86_64-unknown-linux-musl", b"native", tarfile.REGTYPE)],
            )
            validate_tar_single_regular_member(
                archive, "codex-x86_64-unknown-linux-musl"
            )

    def test_rejects_symlink_member_before_extract(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            archive = Path(tmp) / "release.tar.gz"
            self._write_archive(
                archive,
                [("codex-x86_64-unknown-linux-musl", b"", tarfile.SYMTYPE)],
            )
            with self.assertRaises(ValidationError) as ctx:
                validate_tar_single_regular_member(
                    archive, "codex-x86_64-unknown-linux-musl"
                )
            self.assertIn("link", str(ctx.exception).lower())


class DestinationDigestValidationTests(unittest.TestCase):
    def test_dangling_symlink_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            destination = Path(tmp) / "codex"
            destination.symlink_to("/definitely/missing/codex-target")
            self.assertTrue(destination.is_symlink())
            self.assertFalse(destination.exists())
            with self.assertRaises(ValidationError) as ctx:
                refuse_destination_symlink(destination)
            self.assertIn("symlink", str(ctx.exception))

    def test_same_version_text_different_bytes_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            destination = Path(tmp) / "codex"
            destination.write_bytes(b"#!/bin/sh\necho 'codex-cli 0.144.4'\n")
            source_digest = sha256_hex(Path(__file__))
            with self.assertRaises(ValidationError) as ctx:
                require_digest_match_or_absent(destination, source_digest)
            self.assertIn("digest does not match", str(ctx.exception))

    def test_matching_bytes_accepted_without_executing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            destination = Path(tmp) / "codex"
            payload = b"authenticated-native-bytes"
            destination.write_bytes(payload)
            source_digest = sha256_hex(destination)
            state = require_digest_match_or_absent(destination, source_digest)
            self.assertEqual(state, "present")
