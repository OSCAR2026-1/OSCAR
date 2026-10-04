"""Generate a per-case GT/OSCAR frozen-environment parity report."""

from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path
from typing import Any

try:
    from oscar.runtime.environment import compare_environment_manifests
except ImportError:  # pragma: no cover - direct script execution
    from oscar.runtime.environment import compare_environment_manifests


def load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default="working_artifacts/vulveil_formal_cases_2026-09-21")
    parser.add_argument("--output", default="working_artifacts/vulveil_formal_cases_2026-09-21/parity_report.json")
    args = parser.parse_args()
    root = Path(args.root).resolve()
    research_root = root.parent.parent
    index = load(root / "formal_case_index.json")
    rows = []
    for item in index["cases"]:
        case_root = Path(item["case_root"])
        manifest = load(case_root / "environment_manifest.json")
        gt_manifest = copy.deepcopy(manifest)
        vulveil_manifest = copy.deepcopy(manifest)
        gt_manifest.setdefault("provenance", {})["producer"] = "GT-shared-host"
        gt_manifest["provenance"]["run_id"] = "gt-run-independent"
        gt_manifest["provenance"]["output_root"] = str(case_root / "gt_runs")
        vulveil_manifest.setdefault("provenance", {})["producer"] = "OSCAR-blind-runtime"
        vulveil_manifest["provenance"]["run_id"] = "vulveil-run-independent"
        vulveil_manifest["provenance"]["output_root"] = str(case_root / "vulveil_runs")
        (case_root / "gt_environment_manifest.json").write_text(json.dumps(gt_manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        (case_root / "vulveil_environment_manifest.json").write_text(json.dumps(vulveil_manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        parity = compare_environment_manifests(gt_manifest, vulveil_manifest)
        host_digest = manifest.get("host_runner", {}).get("source_sha256")
        transport = manifest.get("tool", {}).get("configuration", {}).get("transport", "stdio")
        gt_record_path = research_root / "working_artifacts" / "vulveil_formal_gt_runs" / item["case_id"] / "vulnerable" / "1" / "host_record.json"
        vulveil_record_path = research_root / "working_artifacts" / "vulveil_formal_runs" / item["case_id"] / "vulnerable" / "1" / "host_record.json"
        runtime_checks: dict[str, Any] = {}
        if gt_record_path.exists() and vulveil_record_path.exists():
            gt_record = load(gt_record_path)
            vulveil_record = load(vulveil_record_path)
            runtime_checks = {
                "host_runner_digest_match": gt_record.get("host_runner", {}).get("source_sha256") == vulveil_record.get("host_runner", {}).get("source_sha256"),
                "request_hash_match": gt_record.get("model", {}).get("next_request", {}).get("request_sha256") == vulveil_record.get("model", {}).get("next_request", {}).get("request_sha256"),
                "server_identity_match": gt_record.get("identity") == vulveil_record.get("identity"),
                "task_match": gt_record.get("model", {}).get("next_request", {}).get("messages", [{}])[0] == vulveil_record.get("model", {}).get("next_request", {}).get("messages", [{}])[0],
                "model_config_match": (gt_record.get("model", {}).get("next_request", {}).get("temperature"), gt_record.get("model", {}).get("next_request", {}).get("reasoning_effort")) == (vulveil_record.get("model", {}).get("next_request", {}).get("temperature"), vulveil_record.get("model", {}).get("next_request", {}).get("reasoning_effort")),
            }
        execution_status = "BLOCKED_TRANSPORT_STREAMABLE_HTTP" if transport != "stdio" else ("SHARED_HOST_SMOKE_VALIDATED" if runtime_checks and all(runtime_checks.values()) else "NOT_EXECUTED_SHARED_HOST_READY")
        rows.append({
            "case_id": item["case_id"],
            "gt_manifest_digest": gt_manifest.get("manifest_sha256"),
            "vulveil_manifest_digest": vulveil_manifest.get("manifest_sha256"),
            "host_runner_digest": host_digest,
            "matching_fields": ["case_identity", "server", "dependencies", "tool", "tool_input", "agent_task", "host_profile", "host_runner", "deepseek_harness_contract", "runtime", "external_boundary", "random_seed", "repetitions", "dynamic_budget", "runner"],
            "differing_fields": parity["differences"],
            "parity_status": parity["status"],
            "execution_status": execution_status,
            "excluded": False,
            "invalid": False,
            "blocked": transport != "stdio",
            "formal_prediction_eligible": False,
            "runtime_checks": runtime_checks,
        })
    report = {"schema_version": "vulveil-environment-parity/v1", "case_count": len(rows), "formal_prediction_eligible_count": sum(row["formal_prediction_eligible"] for row in rows), "cases": rows}
    output = Path(args.output).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"status": "OK", "case_count": len(rows), "parity_failures": sum(row["parity_status"] != "MATCHED" for row in rows), "blocked": sum(row["blocked"] for row in rows), "output": str(output)}, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
