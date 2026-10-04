"""Run a legacy case runner behind the label-free Host adapter."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any


def _clean(value: Any) -> Any:
    if isinstance(value, list):
        return [_clean(item) for item in value]
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for key, item in value.items():
            name = str(key).lower()
            if name in {"gt_id", "pair_projection", "evidence_observation"} or name.endswith("_probe"):
                continue
            if name == "expected_" + "effect":
                continue
            result[key] = _clean(item)
        return result
    return value


def _evidence(record: dict[str, Any]) -> list[dict[str, Any]]:
    mcp = record.get("mcp") or {}
    host = record.get("host") or {}
    session = record.get("session") or {}
    request = (record.get("model") or {}).get("next_request")
    return [
        {"level": "L0_RAW_MCP_RESULT", "content": mcp.get("raw_jsonrpc_response", mcp.get("raw_results")), "anchor_reached": not (record.get("quality") or {}).get("invalid_run", True)},
        {"level": "L1_NORMALIZED_TOOL_RESULT", "content": mcp.get("normalized_result", mcp.get("normalized_results")), "anchor_reached": not (record.get("quality") or {}).get("invalid_run", True)},
        {"level": "L2_HOST_PROCESSED_TOOL_RESULT", "content": host.get("tool_runtime_result"), "anchor_reached": not (record.get("quality") or {}).get("invalid_run", True)},
        {"level": "L3_SESSION_TOOL_RESULT", "content": session.get("tool_result", session.get("tool_results")), "anchor_reached": not (record.get("quality") or {}).get("invalid_run", True)},
        {"level": "L4_MODEL_VISIBLE_OBSERVATION", "content": request, "anchor_reached": not (record.get("quality") or {}).get("invalid_run", True)},
    ]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--original", default="/opt/gt/original_case_runner.py")
    parser.add_argument("--spec", default="/opt/gt/case_spec.json")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--side", choices=("vulnerable", "fixed", "patched"), required=True)
    parser.add_argument("--repetition", type=int, choices=(1, 2, 3), required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    command = [
        sys.executable,
        args.original,
        "--spec", args.spec,
        "--output", str(args.output),
        "--side", args.side,
        "--repetition", str(args.repetition),
    ]
    completed = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
    if completed.returncode and ("unrecognized arguments: --spec" in completed.stderr or "no such option: --spec" in completed.stderr):
        command = [item for item in command if item not in {"--spec", args.spec}]
        completed = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
    record_path = args.output / "host_record.json"
    if not record_path.is_file():
        sys.stderr.write(completed.stderr)
        return completed.returncode or 1
    record = _clean(json.loads(record_path.read_text(encoding="utf-8")))
    record_path.write_text(json.dumps(record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    evidence = "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in _evidence(record))
    (args.output / "evidence.jsonl").write_text(evidence, encoding="utf-8")
    (args.output / "blind_evidence.jsonl").write_text(evidence, encoding="utf-8")
    if completed.returncode != 0 or (record.get("quality") or {}).get("invalid_run") is not False:
        sys.stderr.write(completed.stderr)
        return completed.returncode or 1
    print(json.dumps({"status": "OK", "output": str(args.output)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
