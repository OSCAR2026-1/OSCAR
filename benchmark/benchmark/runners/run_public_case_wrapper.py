"""Run a legacy case runner behind the label-free Host adapter."""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import traceback
from pathlib import Path
from types import SimpleNamespace
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
    rows = [
        {"level": "L0_RAW_MCP_RESULT", "content": mcp.get("raw_jsonrpc_response", mcp.get("raw_results")), "anchor_reached": not (record.get("quality") or {}).get("invalid_run", True)},
        {"level": "L1_NORMALIZED_TOOL_RESULT", "content": mcp.get("normalized_result", mcp.get("normalized_results")), "anchor_reached": not (record.get("quality") or {}).get("invalid_run", True)},
        {"level": "L2_HOST_PROCESSED_TOOL_RESULT", "content": host.get("tool_runtime_result"), "anchor_reached": not (record.get("quality") or {}).get("invalid_run", True)},
        {"level": "L3_SESSION_TOOL_RESULT", "content": session.get("tool_result", session.get("tool_results")), "anchor_reached": not (record.get("quality") or {}).get("invalid_run", True)},
        {"level": "L4_MODEL_VISIBLE_OBSERVATION", "content": request, "anchor_reached": not (record.get("quality") or {}).get("invalid_run", True)},
    ]
    valid = not (record.get("quality") or {}).get("invalid_run", True)
    boundary = record.get("external_boundary") if isinstance(record.get("external_boundary"), dict) else {}
    declared_oracle = boundary.get("oracle") if isinstance(boundary.get("oracle"), dict) else None
    if declared_oracle is not None:
        oracle = {key: value for key, value in declared_oracle.items() if key != "effect_event"}
        rows.append({
            "level": "SERVER_OR_EXTERNAL_EFFECT", "anchor_reached": valid,
            "event": declared_oracle.get("effect_event"), "oracle": oracle,
        })
    elif boundary.get("boundary") == "container-local-filesystem":
        exists = boundary.get("escape_exists") is True
        rows.append({
            "level": "SERVER_OR_EXTERNAL_EFFECT", "anchor_reached": valid,
            "event": ({
                "resource_id": "container-local-filesystem:escape.png", "operation": "write",
                "location": "container-local-filesystem", "oracle_kind": "filesystem-state-projection/v1",
                "stable_resource_identity": True,
            } if exists else None),
            "oracle": {"kind": "filesystem-state-projection/v1", "complete": True, "resource_exists": exists, "resource_size": boundary.get("escape_size")},
        })
    elif isinstance(boundary.get("requests"), list):
        redirect_requests = [item for item in boundary["requests"] if isinstance(item, dict) and item.get("stage") == "http_redirect_target"]
        authorization_present = any(
            bool((item.get("headers") or {}).get("authorization") or (item.get("headers") or {}).get("Authorization"))
            for item in redirect_requests
        )
        rows.append({
            "level": "SERVER_OR_EXTERNAL_EFFECT", "anchor_reached": valid,
            "event": ({
                "resource_id": "http-redirect-target", "operation": "send",
                "location": "container-local-http-redirect-target", "oracle_kind": "http-redirect-credential-projection/v1",
                "stable_resource_identity": True,
            } if authorization_present else None),
            "oracle": {"kind": "http-redirect-credential-projection/v1", "complete": True, "redirect_request_count": len(redirect_requests), "authorization_present": authorization_present},
        })
    return rows


def _run_runner_map(args: argparse.Namespace) -> SimpleNamespace:
    """Invoke one public case from a legacy runner exposing a RUNNERS map."""
    try:
        spec = json.loads(Path(args.spec).read_text(encoding="utf-8"))
        case_id = spec["case_id"]
        module_spec = importlib.util.spec_from_file_location("vulveil_legacy_runner", args.original)
        if module_spec is None or module_spec.loader is None:
            raise RuntimeError(f"cannot load legacy runner: {args.original}")
        module = importlib.util.module_from_spec(module_spec)
        module_spec.loader.exec_module(module)
        runner = module.RUNNERS[case_id]
        side = "vulnerable" if args.side == "vulnerable" else "patched"
        runner_output = args.output / "original_runner"
        os.environ["VULVEIL_RUN_INPUT_ROOT"] = str(args.output / "runtime_inputs")
        module.OUTPUT_ROOT = runner_output
        runner(module.ROOT, side, args.repetition)
        record_path = runner_output / case_id / side / str(args.repetition) / "host_record.json"
        if not record_path.is_file():
            raise RuntimeError(f"legacy runner did not create {record_path}")
        shutil.copy2(record_path, args.output / "host_record.json")
        return SimpleNamespace(returncode=0, stdout="", stderr="")
    except Exception:
        return SimpleNamespace(returncode=1, stdout="", stderr=traceback.format_exc())


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--original", default="/opt/gt/original_case_runner.py")
    parser.add_argument("--adapter", choices=("standard", "runner-map"), default="standard")
    parser.add_argument("--spec", default="/opt/gt/case_spec.json")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--side", choices=("vulnerable", "fixed", "patched"), required=True)
    parser.add_argument("--repetition", type=int, choices=(1, 2, 3), required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    if args.adapter == "runner-map":
        completed = _run_runner_map(args)
    else:
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
