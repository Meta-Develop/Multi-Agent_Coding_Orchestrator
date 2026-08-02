#!/usr/bin/env python3
"""Generate the deterministic synthetic authenticated-claims fixture for Issue 33."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import shutil
from pathlib import Path
from typing import Any


AUTH_FRAME_MAGIC = b"MACO\0repository-auth\0hmac-sha256\0v1\0"
RECORD_DOMAIN = b"MACO\0authenticated-claims-record\0v1\0"
HEAD_DOMAIN = b"MACO\0authenticated-claims-head\0v1\0"
LOCATOR_DOMAIN = b"MACO\0authenticated-claims-locator\0v1\0"
SYNTHETIC_KEY = bytes.fromhex("33" * 32)
SYNTHETIC_DEVICE = 33_333_333
SYNTHETIC_COMMON_DIR_FILE = 33_000_001
SYNTHETIC_KEY_FILE = 33_000_002
SYNTHETIC_RUN_DIRECTORY_FILE = 33_000_003


def digest_label(label: str) -> str:
    return hashlib.sha256(label.encode("ascii")).hexdigest()


RUN_ID = digest_label("MACO Issue 33 synthetic fixture run id v1")
JOURNAL_ID = digest_label("MACO Issue 33 synthetic fixture journal id v1")
COMMON_DIR_PATH_SHA256 = digest_label("MACO Issue 33 synthetic fixture common path v1")
HEAD_TEMP_NONCE = digest_label("MACO Issue 33 synthetic fixture head temp nonce v1")
RECORD_TEMP_NONCE = digest_label("MACO Issue 33 synthetic fixture record temp nonce v1")
LOGICAL_ID = "claims"
LOGICAL_ANCHOR_NAME = f".snapshot-init-{hashlib.sha256(LOGICAL_ID.encode('ascii')).hexdigest()}.json"


def compact_json(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":")).encode("ascii")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def authentication_tag(domain: bytes, payload: bytes) -> str:
    framed = b"".join(
        (
            AUTH_FRAME_MAGIC,
            len(domain).to_bytes(8, "big"),
            domain,
            len(payload).to_bytes(8, "big"),
            payload,
        )
    )
    return hmac.new(SYNTHETIC_KEY, framed, hashlib.sha256).hexdigest()


def repository_binding() -> dict[str, Any]:
    return {
        "version": 1,
        "repository_id": hashlib.sha256(SYNTHETIC_KEY).hexdigest(),
        "common_dir_path_sha256": COMMON_DIR_PATH_SHA256,
        "common_dir_identity": {
            "device": SYNTHETIC_DEVICE,
            "file": SYNTHETIC_COMMON_DIR_FILE,
        },
        "key_identity": {
            "device": SYNTHETIC_DEVICE,
            "file": SYNTHETIC_KEY_FILE,
        },
    }


def journal_identity() -> dict[str, Any]:
    return {
        "version": 1,
        "repository": repository_binding(),
        "run_id": RUN_ID,
        "journal_id": JOURNAL_ID,
        "run_directory_identity": {
            "device": SYNTHETIC_DEVICE,
            "file": SYNTHETIC_RUN_DIRECTORY_FILE,
        },
    }


def snapshot_value(generation: int) -> dict[str, Any]:
    claims: list[dict[str, Any]] = []
    next_token = 1
    if generation % 2 == 0:
        token = generation // 2
        claims = [
            {
                "agent_id": "synthetic-fixture-agent",
                "paths": [f"synthetic/example-{token}.txt"],
                "token": token,
            }
        ]
        next_token = token + 1
    elif generation > 1:
        next_token = (generation + 1) // 2
    return {
        "claims": claims,
        "next_token": next_token,
        "repository": repository_binding(),
        "run_owners": [],
        "snapshot_revision": generation,
        "version": 1,
    }


def record(sequence: int, previous_mac: str) -> dict[str, Any]:
    payload = {
        "generation": sequence,
        "token": sequence,
        "value": snapshot_value(sequence),
        "version": 1,
    }
    identity = journal_identity()
    mac_payload = compact_json(
        [1, identity, sequence, previous_mac, "snapshot", None, payload]
    )
    return {
        "version": 1,
        "identity": identity,
        "sequence": sequence,
        "previous_mac": previous_mac,
        "phase": "snapshot",
        "payload": payload,
        "mac": authentication_tag(RECORD_DOMAIN, mac_payload),
    }


def head(sequence: int, last_record_mac: str, record_bytes: int) -> dict[str, Any]:
    identity = journal_identity()
    mac_payload = compact_json([1, identity, sequence, last_record_mac, record_bytes])
    return {
        "version": 1,
        "identity": identity,
        "sequence": sequence,
        "last_record_mac": last_record_mac,
        "record_bytes": record_bytes,
        "mac": authentication_tag(HEAD_DOMAIN, mac_payload),
    }


def generated_files() -> dict[str, bytes]:
    files: dict[str, bytes] = {".claims-snapshot.lock": b""}
    records: list[dict[str, Any]] = []
    previous_mac = "0" * 64
    record_bytes = 0
    for sequence in range(1, 5):
        current = record(sequence, previous_mac)
        encoded = compact_json(current) + b"\n"
        records.append(current)
        record_bytes += len(encoded)
        previous_mac = current["mac"]
        if sequence <= 3:
            files[f"{sequence:020}.json"] = encoded
        else:
            files[f".record-{sequence:020}-{RECORD_TEMP_NONCE}.tmp"] = encoded

    encoded_head = compact_json(head(4, records[-1]["mac"], record_bytes)) + b"\n"
    files[f".head-{HEAD_TEMP_NONCE}.tmp"] = encoded_head
    return files


def verify_generated_files(files: dict[str, bytes]) -> None:
    previous_mac = "0" * 64
    record_bytes = 0
    records: list[dict[str, Any]] = []
    for sequence in range(1, 5):
        name = (
            f"{sequence:020}.json"
            if sequence <= 3
            else f".record-{sequence:020}-{RECORD_TEMP_NONCE}.tmp"
        )
        encoded = files[name]
        require(encoded.endswith(b"\n"), f"record {sequence} has no final newline")
        parsed = json.loads(encoded)
        require(parsed["identity"] == journal_identity(), f"record {sequence} identity")
        require(parsed["sequence"] == sequence, f"record {sequence} sequence")
        require(parsed["previous_mac"] == previous_mac, f"record {sequence} chain")
        expected_payload = compact_json(
            [
                parsed["version"],
                parsed["identity"],
                parsed["sequence"],
                parsed["previous_mac"],
                parsed["phase"],
                None,
                parsed["payload"],
            ]
        )
        require(
            parsed["mac"] == authentication_tag(RECORD_DOMAIN, expected_payload),
            f"record {sequence} authentication tag",
        )
        previous_mac = parsed["mac"]
        record_bytes += len(encoded)
        records.append(parsed)

    head_name = f".head-{HEAD_TEMP_NONCE}.tmp"
    parsed_head = json.loads(files[head_name])
    require(parsed_head["identity"] == journal_identity(), "head identity")
    require(parsed_head["sequence"] == 4, "head sequence")
    require(parsed_head["last_record_mac"] == records[-1]["mac"], "head chain")
    require(parsed_head["record_bytes"] == record_bytes, "head byte count")
    expected_head_payload = compact_json(
        [
            parsed_head["version"],
            parsed_head["identity"],
            parsed_head["sequence"],
            parsed_head["last_record_mac"],
            parsed_head["record_bytes"],
        ]
    )
    require(
        parsed_head["mac"] == authentication_tag(HEAD_DOMAIN, expected_head_payload),
        "head authentication tag",
    )


def logical_anchor() -> bytes:
    mac_payload = compact_json(["snapshot_initialization", 1, LOGICAL_ID, 1, RUN_ID])
    value = {
        "version": 1,
        "logical_id": LOGICAL_ID,
        "attempt": 1,
        "physical_id": RUN_ID,
        "mac": authentication_tag(LOCATOR_DOMAIN, mac_payload),
    }
    encoded = compact_json(value) + b"\n"
    parsed = json.loads(encoded)
    require(parsed["physical_id"] == RUN_ID, "logical anchor physical identity")
    require(
        parsed["mac"] == authentication_tag(LOCATOR_DOMAIN, mac_payload),
        "logical anchor authentication tag",
    )
    return encoded


def write_fixture(output_root: Path, anchor_synthetic_identity: bool) -> None:
    files = generated_files()
    verify_generated_files(files)
    namespace = output_root / "authenticated-claims-state-v1"
    if namespace.is_symlink():
        namespace.unlink()
    elif namespace.exists():
        shutil.rmtree(namespace)
    journal = namespace / RUN_ID
    journal.mkdir(parents=True)
    if anchor_synthetic_identity:
        (namespace / LOGICAL_ANCHOR_NAME).write_bytes(logical_anchor())

    manifest_lines = []
    for name, contents in sorted(files.items()):
        (journal / name).write_bytes(contents)
        relative = Path("authenticated-claims-state-v1") / RUN_ID / name
        manifest_lines.append(f"{hashlib.sha256(contents).hexdigest()}  {relative.as_posix()}\n")
    (output_root / "authenticated-claims-state-v1.sha256").write_text(
        "".join(manifest_lines), encoding="ascii"
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-root",
        type=Path,
        default=Path(__file__).resolve().parent,
        help="Issue 33 fixture directory to populate (default: generator directory)",
    )
    parser.add_argument(
        "--anchor-synthetic-identity",
        action="store_true",
        help="neuter mode: add a signed logical initialization anchor for the synthetic run",
    )
    args = parser.parse_args()
    args.output_root.mkdir(parents=True, exist_ok=True)
    write_fixture(args.output_root, args.anchor_synthetic_identity)


if __name__ == "__main__":
    main()
