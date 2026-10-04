"""Run an onboarded label-free MCP case through the neutral shared Host.

The runner reads only its blind case; the shared Host code is the same code
used by the independent paired execution, but no annotation is imported.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

try:
    from oscar.runtime.evidence_adapter import build_evidence_rows
except ImportError:  # direct script execution
    from oscar.runtime.evidence_adapter import build_evidence_rows

def run_prepared_case(case_path: Path, side: str, output: Path, *, input_override: str | None = None,
                      repetition: int = 1) -> dict:
    if side not in {"vulnerable", "patched"}:
        raise ValueError("side must be vulnerable or patched")
    spec = json.loads(case_path.read_text(encoding="utf-8"))
    try:
        from oscar.runtime.blind_runtime import validate_blind_case
    except ImportError:  # direct script execution
        from oscar.runtime.blind_runtime import validate_blind_case
    errors = validate_blind_case(spec)
    if errors:
        raise ValueError("invalid blind case: " + "; ".join(errors))
    if input_override is None:
        tool_input = spec["tool_input"]
    else:
        tool_input = json.loads(input_override)
        if not isinstance(tool_input, dict):
            raise ValueError("counterfactual Tool input must be an object")
    adapter = spec["server_runner"][side]
    source_root = (case_path.parent / spec["source"]["vulnerable" if side == "vulnerable" else "fixed"]["root"]).resolve()
    command = adapter["command"]
    if not source_root.is_dir() or not isinstance(command, list) or not command:
        raise ValueError("prepared server command or source root is unavailable")
    from oscar.runtime.shared_host import run_shared_host_case

    record = run_shared_host_case(
        run_id=f"{spec['case_id']}-{side}-{repetition}",
        case_id=spec["case_id"], revision=side, repetition=repetition,
        command=command, cwd=source_root, env=dict(adapter.get("env", {})),
        server_name=str(spec["server"]["repository"]),
        tool_name=spec["tool"]["name"], tool_arguments=tool_input,
        task=spec["agent_task"],
        system_prompt="You are a deterministic research host. Use the frozen tool call and report its result.",
        server_revision=spec["identity"]["vulnerable_version" if side == "vulnerable" else "fixed_version"],
        timeout=float(spec["runner"].get("timeout_seconds", 120)),
        transport=str(adapter.get("transport", spec.get("tool", {}).get("configuration", {}).get("transport", "stdio"))),
        endpoint=adapter.get("endpoint"),
        headers={str(key): str(value) for key, value in adapter.get("headers", {}).items()},
        startup_timeout=float(adapter.get("startup_timeout_seconds", 20)),
    )
    if record["quality"]["invalid_run"]:
        raise RuntimeError("shared Host could not complete the MCP Tool call")
    rows = build_evidence_rows(record, side=side, repetition=repetition, tool_input=tool_input)
    output.mkdir(parents=True, exist_ok=True)
    (output / "blind_evidence.jsonl").write_text(
        "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows), encoding="utf-8"
    )
    (output / "host_record.json").write_text(json.dumps(record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return {"status": "OK", "evidence": str(output / "blind_evidence.jsonl"), "side": side}


def main() -> int:
    parser = argparse.ArgumentParser(description="Run a prepared MCP case via the shared Host")
    parser.add_argument("--case", type=Path, required=True)
    parser.add_argument("--side", choices=("vulnerable", "patched"), required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = run_prepared_case(
        args.case.resolve(), args.side, args.output.resolve(),
        input_override=os.environ.get("VULVEIL_TOOL_INPUT_JSON"),
        repetition=int(os.environ.get("VULVEIL_REPETITION", "1")),
    )
    print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
