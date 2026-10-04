#!/usr/bin/env python3
"""Verify that the immutable benchmark container images are available locally."""

from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--manifest",
        type=Path,
        default=REPO_ROOT / "release" / "container_images.json",
    )
    args = parser.parse_args()
    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    rows = []
    for item in manifest.get("images", []):
        result = subprocess.run(
            ["docker", "image", "inspect", str(item["image"]), "--format", "{{.Id}}"],
            capture_output=True,
            text=True,
            check=False,
        )
        actual = result.stdout.strip() if result.returncode == 0 else None
        rows.append({
            "image": item["image"],
            "expected_image_id": item["image_id"],
            "actual_image_id": actual,
            "status": "OK" if actual == item["image_id"] else "MISSING_OR_MISMATCHED",
        })
    report = {
        "schema_version": "oscar-benchmark-environment-verification/v1",
        "status": "PASS" if rows and all(row["status"] == "OK" for row in rows) else "FAIL",
        "image_count": len(rows),
        "rows": rows,
    }
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report["status"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())

