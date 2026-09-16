"""Pinned Codex CI archive and destination checks (stdlib only)."""

from __future__ import annotations

import hashlib
import stat
import sys
import tarfile
from pathlib import Path


class ValidationError(Exception):
    pass


def sha256_hex(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate_tar_single_regular_member(archive_path: Path, member_name: str) -> None:
    if "/" in member_name or member_name in (".", ".."):
        raise ValidationError(f"refusing: invalid archive member name {member_name!r}")
    with tarfile.open(archive_path, mode="r:gz") as archive:
        names = archive.getnames()
        if names != [member_name]:
            raise ValidationError(
                f"refusing: archive member listing is not exactly {member_name}"
            )
        info = archive.getmember(member_name)
        if info.issym() or info.islnk():
            raise ValidationError(
                f"refusing: archive member {member_name} is a link, not a regular file"
            )
        if info.type not in (tarfile.REGTYPE, tarfile.AREGTYPE):
            raise ValidationError(
                f"refusing: archive member {member_name} is not a regular file"
            )
        if not info.isreg():
            raise ValidationError(
                f"refusing: archive member {member_name} failed regular-file metadata check"
            )


def refuse_destination_symlink(destination: Path) -> None:
    if destination.is_symlink():
        raise ValidationError(f"refusing: {destination} is a symlink")


def require_digest_match_or_absent(destination: Path, source_digest: str) -> str:
    """Return ``present`` when an existing regular file matches ``source_digest``."""
    refuse_destination_symlink(destination)
    if not destination.exists():
        return "absent"
    if not destination.is_file():
        raise ValidationError(
            f"refusing: {destination} exists but is not a regular file"
        )
    existing_digest = sha256_hex(destination)
    if existing_digest != source_digest:
        raise ValidationError(
            f"refusing: {destination} digest does not match authenticated release binary"
        )
    return "present"


def _main(argv: list[str]) -> int:
    if len(argv) != 3 or argv[0] != "validate-tar":
        print("usage: validate-tar ARCHIVE MEMBER", file=sys.stderr)
        return 2
    archive = Path(argv[1])
    member = argv[2]
    try:
        validate_tar_single_regular_member(archive, member)
    except ValidationError as error:
        print(error, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv[1:]))
