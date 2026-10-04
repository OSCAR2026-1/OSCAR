#!/usr/bin/env python3
"""Verify an OSCAR-Benchmark release archive without extracting it."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import tarfile
from pathlib import Path, PurePosixPath
from typing import Any


ARCHIVE_ROOT = "oscar-benchmark"
FORBIDDEN_JSON_KEYS = {
    "ground_truth_label",
    "impact_label",
    "expected_subtype",
    "annotation_status",
    "included_in_gt",
}
TEST_KEY_SHA256 = "7633ece344af7d6e1e9fecf574ebdbd82bde5124f612058262c2bfd2472972f9"
ALLOWED_TEST_KEYS = {
    f"{ARCHIVE_ROOT}/benchmark/cases/GH-P4-002/assets/github.key_fixed": TEST_KEY_SHA256,
    f"{ARCHIVE_ROOT}/benchmark/cases/GH-P4-002/assets/github.key_vulnerable": TEST_KEY_SHA256,
}


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def walk_json(value: Any, location: str, errors: list[str]) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if str(key).lower() in FORBIDDEN_JSON_KEYS:
                errors.append(f"{location}: evaluator-only JSON key {key!r}")
            walk_json(item, location, errors)
    elif isinstance(value, list):
        for item in value:
            walk_json(item, location, errors)


def read_json(archive: tarfile.TarFile, name: str, errors: list[str]) -> dict[str, Any]:
    try:
        member = archive.getmember(name)
        stream = archive.extractfile(member)
        if stream is None:
            raise ValueError("not a regular file")
        value = json.loads(stream.read().decode("utf-8"))
        walk_json(value, name, errors)
        return value
    except (KeyError, ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        errors.append(f"{name}: {exc}")
        return {}


def verify(archive_path: Path, checksum_path: Path | None = None) -> dict[str, Any]:
    errors: list[str] = []
    actual_checksum = digest(archive_path)
    if checksum_path:
        expected = checksum_path.read_text(encoding="utf-8").split()[0]
        if expected != actual_checksum:
            errors.append("archive checksum mismatch")
    with tarfile.open(archive_path, "r:gz") as archive:
        members = archive.getmembers()
        names = {member.name for member in members}
        for member in members:
            path = PurePosixPath(member.name)
            if path.is_absolute() or ".." in path.parts or not path.parts or path.parts[0] != ARCHIVE_ROOT:
                errors.append(f"unsafe archive member: {member.name}")
            if member.issym() and os.path.isabs(member.linkname) and not member.linkname.startswith("/opt/server/"):
                errors.append(f"unsafe symbolic link target: {member.name}")
            if (
                member.isfile()
                and member.name.startswith(f"{ARCHIVE_ROOT}/benchmark/")
                and member.size <= 16 * 1024 * 1024
            ):
                stream = archive.extractfile(member)
                data = stream.read() if stream else b""
                if "/assets/" not in member.name and b"/home/" in data:
                    errors.append(f"developer workspace path: {member.name}")
                if b"-----BEGIN PRIVATE KEY-----" in data or b"-----BEGIN OPENSSH PRIVATE KEY-----" in data:
                    actual = hashlib.sha256(data).hexdigest()
                    if ALLOWED_TEST_KEYS.get(member.name) != actual:
                        errors.append(f"unapproved private key material: {member.name}")
        required = {
            f"{ARCHIVE_ROOT}/README.md",
            f"{ARCHIVE_ROOT}/LICENSE",
            f"{ARCHIVE_ROOT}/test_set.json",
            f"{ARCHIVE_ROOT}/release/benchmark_manifest.json",
            f"{ARCHIVE_ROOT}/release/container_images.json",
            f"{ARCHIVE_ROOT}/benchmark/readiness.json",
        }
        errors.extend(f"missing required member: {name}" for name in sorted(required - names))
        manifest = read_json(archive, f"{ARCHIVE_ROOT}/release/benchmark_manifest.json", errors)
        containers = read_json(archive, f"{ARCHIVE_ROOT}/release/container_images.json", errors)
        test_set = read_json(archive, f"{ARCHIVE_ROOT}/test_set.json", errors)
        readiness = read_json(archive, f"{ARCHIVE_ROOT}/benchmark/readiness.json", errors)
        if manifest.get("case_count") != 50 or len(manifest.get("cases", [])) != 50:
            errors.append("benchmark manifest does not contain 50 cases")
        if test_set.get("case_count") != 50 or len(test_set.get("cases", [])) != 50:
            errors.append("test set does not contain 50 cases")
        if readiness.get("status") != "READY" or readiness.get("leakage_scan") != "PASS":
            errors.append("embedded readiness contract is not READY/PASS")
        if readiness.get("hidden_input_access_count") != 0:
            errors.append("embedded readiness reports hidden input access")
        if containers.get("images_included") is not False:
            errors.append("container contract must state that images are external")
        for case in manifest.get("cases", []):
            relative = str(case.get("blind_case", ""))
            name = f"{ARCHIVE_ROOT}/{relative}"
            if name not in names:
                errors.append(f"missing case contract: {relative}")
                continue
            value = read_json(archive, name, errors)
            if value.get("case_id") != case.get("case_id"):
                errors.append(f"case identity mismatch: {relative}")
    return {
        "schema_version": "oscar-benchmark-release-verification/v1",
        "status": "PASS" if not errors else "FAIL",
        "archive": str(archive_path.resolve()),
        "archive_sha256": actual_checksum,
        "member_count": len(members),
        "errors": sorted(set(errors)),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--checksum", type=Path)
    args = parser.parse_args()
    report = verify(args.archive, args.checksum)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report["status"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
