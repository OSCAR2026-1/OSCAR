#!/usr/bin/env python3
"""Verify the integrated OSCAR artifact layout and label separation."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
FORBIDDEN_BENCHMARK_KEYS = {
    "ground_truth_label",
    "impact_label",
    "boundary_label",
    "expected_subtype",
    "annotation_status",
    "included_in_gt",
}


def walk_keys(value: Any, path: Path, errors: list[str]) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if str(key).lower() in FORBIDDEN_BENCHMARK_KEYS:
                errors.append(f"evaluator-only key in benchmark: {path}: {key}")
            walk_keys(item, path, errors)
    elif isinstance(value, list):
        for item in value:
            walk_keys(item, path, errors)


def main() -> int:
    errors: list[str] = []
    required = [
        ROOT / "tool" / "oscar.py",
        ROOT / "tool" / "oscar" / "cli.py",
        ROOT / "benchmark" / "test_set.json",
        ROOT / "benchmark" / "benchmark" / "readiness.json",
        ROOT / "evaluation" / "reference_labels.json",
        ROOT / "evaluation" / "evaluate.py",
    ]
    errors.extend(f"missing required file: {path.relative_to(ROOT)}" for path in required if not path.exists())

    test_set = json.loads((ROOT / "benchmark" / "test_set.json").read_text(encoding="utf-8"))
    cases = test_set.get("cases", [])
    if test_set.get("case_count") != 50 or len(cases) != 50:
        errors.append("benchmark test_set.json must contain 50 cases")
    for item in cases:
        relative = item.get("case")
        path = ROOT / "benchmark" / str(relative)
        if not path.is_file():
            errors.append(f"missing benchmark case: {relative}")

    reference = json.loads((ROOT / "evaluation" / "reference_labels.json").read_text(encoding="utf-8"))
    labels = reference.get("labels", [])
    identities = [str(row.get("case_id", "")) for row in labels]
    if reference.get("case_count") != 50 or len(labels) != 50:
        errors.append("reference_labels.json must contain 50 cases")
    if len(set(identities)) != len(identities) or "" in identities:
        errors.append("reference labels contain missing or duplicate case IDs")
    impact_counts = {
        label: sum(row.get("impact_label") == label for row in labels)
        for label in ("IMPACT_YES", "IMPACT_NO")
    }
    boundary_counts = {
        boundary: sum(row.get("boundary_label") == boundary for row in labels)
        for boundary in ("B_ENV", "B_TOOL", "B_AGENT")
    }
    if impact_counts != {"IMPACT_YES": 28, "IMPACT_NO": 22}:
        errors.append(f"unexpected impact-label distribution: {impact_counts}")
    if boundary_counts != {"B_ENV": 10, "B_TOOL": 8, "B_AGENT": 10}:
        errors.append(f"unexpected boundary-label distribution: {boundary_counts}")

    for path in (ROOT / "benchmark").rglob("*.json"):
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            continue
        walk_keys(value, path.relative_to(ROOT), errors)

    report = {
        "schema_version": "oscar-artifact-verification/v1",
        "status": "PASS" if not errors else "FAIL",
        "tool_present": (ROOT / "tool" / "oscar.py").is_file(),
        "benchmark_case_count": len(cases),
        "reference_case_count": len(labels),
        "impact_distribution": impact_counts,
        "boundary_distribution": boundary_counts,
        "benchmark_label_leakage": not any("evaluator-only key" in error for error in errors),
        "errors": errors,
    }
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report["status"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
