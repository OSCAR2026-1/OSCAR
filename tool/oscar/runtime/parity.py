"""CLI for checking frozen GT/OSCAR environment manifest parity."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

try:
    from oscar.runtime.environment import compare_environment_manifests
except ImportError:  # pragma: no cover - direct script execution
    from oscar.runtime.environment import compare_environment_manifests


def main() -> int:
    parser = argparse.ArgumentParser(description="Check frozen environment parity")
    parser.add_argument("--gt-manifest", required=True)
    parser.add_argument("--vulveil-manifest", required=True)
    args = parser.parse_args()
    gt = json.loads(Path(args.gt_manifest).read_text(encoding="utf-8"))
    vulveil = json.loads(Path(args.vulveil_manifest).read_text(encoding="utf-8"))
    result = compare_environment_manifests(gt, vulveil)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["status"] == "MATCHED" else 2


if __name__ == "__main__":
    raise SystemExit(main())

