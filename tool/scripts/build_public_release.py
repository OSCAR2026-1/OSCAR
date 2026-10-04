#!/usr/bin/env python3
"""Build and audit the label-free OSCAR tool release from tracked files."""

from __future__ import annotations

import argparse
import fnmatch
import gzip
import hashlib
import io
import json
import re
import subprocess
import tarfile
from pathlib import Path
from typing import Any


TOOL_ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = TOOL_ROOT / "release" / "public_manifest.json"
LICENSE_NAMES = ("LICENSE", "LICENSE.txt", "LICENSE.md")
FORBIDDEN_PATH_PARTS = {
    "hidden_gt",
    "canonical_gt",
    "annotations",
    "private_traces",
    "secrets",
}
FORBIDDEN_JSON_KEYS = {
    "ground_truth_label",
    "impact_label",
    "expected_subtype",
    "annotation_status",
    "included_in_gt",
}
TEXT_SUFFIXES = {".cfg", ".ini", ".json", ".jsonl", ".md", ".py", ".toml", ".txt", ".yaml", ".yml"}
ABSOLUTE_WORKSPACE = re.compile(
    r"(?:/" + "home" + r"/[^/\s]+/|[A-Za-z]:[\\/](?:Users|Documents)[\\/])"
)
PRIVATE_KEY = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")
CREDENTIAL_ASSIGNMENT = re.compile(
    r"(?i)\b(?:api[_-]?key|access[_-]?token|auth[_-]?token|password|secret)\b\s*[:=]\s*[\"'][^\"']{8,}[\"']"
)


def _load_manifest() -> dict[str, Any]:
    value = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or value.get("schema_version") != "oscar-public-release/v1":
        raise ValueError("invalid public release manifest")
    return value


def _tracked_files() -> list[str]:
    if not (TOOL_ROOT / ".git").exists():
        return sorted(
            path.relative_to(TOOL_ROOT).as_posix()
            for path in TOOL_ROOT.rglob("*")
            if path.is_file()
            and not any(part in {"__pycache__", "dist", "build"} for part in path.parts)
        )
    result = subprocess.run(
        ["git", "ls-files", "-z"], cwd=TOOL_ROOT, check=True, capture_output=True
    )
    return [item.decode("utf-8") for item in result.stdout.split(b"\0") if item]


def _selected_files(manifest: dict[str, Any]) -> list[str]:
    includes = manifest.get("include", [])
    excludes = manifest.get("exclude", [])
    tracked = _tracked_files()
    selected = sorted(
        path for path in tracked
        if any(fnmatch.fnmatchcase(path, pattern) for pattern in includes)
        and not any(fnmatch.fnmatchcase(path, pattern) for pattern in excludes)
    )
    missing = sorted(set(manifest.get("required", [])) - set(selected))
    if missing:
        raise ValueError("required release files are missing: " + ", ".join(missing))
    return selected


def _walk_json(value: Any, location: str, errors: list[str]) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if str(key).lower() in FORBIDDEN_JSON_KEYS:
                errors.append(f"{location}: forbidden evaluator-only JSON key {key!r}")
            _walk_json(item, location, errors)
    elif isinstance(value, list):
        for item in value:
            _walk_json(item, location, errors)


def audit_files(paths: list[str]) -> list[str]:
    errors: list[str] = []
    for relative in paths:
        path = TOOL_ROOT / relative
        lowered_parts = {part.lower() for part in Path(relative).parts}
        if lowered_parts & FORBIDDEN_PATH_PARTS:
            errors.append(f"{relative}: forbidden release path")
        if path.is_symlink():
            errors.append(f"{relative}: symbolic links are not allowed")
            continue
        if path.suffix.lower() not in TEXT_SUFFIXES:
            continue
        text = path.read_text(encoding="utf-8")
        if ABSOLUTE_WORKSPACE.search(text):
            errors.append(f"{relative}: contains an absolute developer workspace path")
        if PRIVATE_KEY.search(text):
            errors.append(f"{relative}: contains a private key")
        if CREDENTIAL_ASSIGNMENT.search(text):
            errors.append(f"{relative}: contains a credential-like assignment")
        if path.suffix.lower() == ".json" and relative.startswith(("examples/", "tests/fixtures/", "benchmark/")):
            try:
                _walk_json(json.loads(text), relative, errors)
            except json.JSONDecodeError as exc:
                errors.append(f"{relative}: invalid JSON: {exc}")
    return errors


def _build_archive(paths: list[str], output: Path, archive_root: str) -> str:
    output.parent.mkdir(parents=True, exist_ok=True)
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for relative in paths:
            data = (TOOL_ROOT / relative).read_bytes()
            info = tarfile.TarInfo(f"{archive_root}/{relative}")
            info.size = len(data)
            info.mode = 0o755 if relative == "scripts/build_public_release.py" else 0o644
            info.mtime = 0
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            archive.addfile(info, io.BytesIO(data))
    with output.open("wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed:
            compressed.write(buffer.getvalue())
    return hashlib.sha256(output.read_bytes()).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=TOOL_ROOT / "dist" / "oscar-tool.tar.gz")
    parser.add_argument("--verify-only", action="store_true")
    parser.add_argument("--allow-missing-license", action="store_true")
    args = parser.parse_args()

    manifest = _load_manifest()
    paths = _selected_files(manifest)
    license_present = any((TOOL_ROOT / name).is_file() and name in paths for name in LICENSE_NAMES)
    errors = audit_files(paths)
    if not license_present and not args.allow_missing_license:
        errors.append("an OSI-approved LICENSE file is required for a final public release")
    report: dict[str, Any] = {
        "schema_version": "oscar-public-release-audit/v1",
        "status": "PASS" if not errors else "FAIL",
        "file_count": len(paths),
        "license_present": license_present,
        "errors": errors,
    }
    if not errors and not args.verify_only:
        output = args.output.resolve()
        report["archive"] = str(output)
        report["sha256"] = _build_archive(paths, output, str(manifest["archive_root"]))
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if not errors else 2


if __name__ == "__main__":
    raise SystemExit(main())
