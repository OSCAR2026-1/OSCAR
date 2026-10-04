"""Convert a shared Host record into blind L0-L4 evidence rows.

The adapter is intentionally structural: it copies the exact role=tool content
from the attested next model request and never derives an effect label.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


LEVELS = (
    "L0_RAW_MCP_RESULT",
    "L1_NORMALIZED_TOOL_RESULT",
    "L2_HOST_PROCESSED_TOOL_RESULT",
    "L3_SESSION_TOOL_RESULT",
    "L4_MODEL_VISIBLE_OBSERVATION",
)


def _digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True, default=str, separators=(",", ":")).encode()).hexdigest()


def _tool_content(request: Any) -> Any:
    if not isinstance(request, dict):
        return None
    messages = request.get("messages")
    if not isinstance(messages, list):
        return None
    return [message.get("content") for message in messages if isinstance(message, dict) and message.get("role") == "tool"]


def build_evidence_rows(record: dict[str, Any], *, side: str, repetition: int, tool_input: Any) -> list[dict[str, Any]]:
    """Return five level rows or raise ValueError for an unattested L4."""
    trace_id = str(record.get("trace_id") or record.get("run_id") or f"{side}-{repetition}")
    digest = _digest(tool_input)
    mcp = record.get("mcp", {}) if isinstance(record.get("mcp"), dict) else {}
    host = record.get("host", {}) if isinstance(record.get("host"), dict) else {}
    session = record.get("session", {}) if isinstance(record.get("session"), dict) else {}
    model = record.get("model", {}) if isinstance(record.get("model"), dict) else {}
    request = model.get("next_request") or model.get("next_model_request")
    if not record.get("actual_next_model_request", True) or _tool_content(request) is None:
        raise ValueError("actual_next_model_request with role=tool content is required for L4")
    values = [
        mcp.get("raw_jsonrpc_response", mcp.get("raw_result", mcp.get("raw_results"))),
        mcp.get("normalized_result", mcp.get("normalized_results")),
        host.get("tool_runtime_result", host.get("processed_content")),
        session.get("tool_result", session.get("tool_results")),
        {"messages": [{"role": "tool", "content": content} for content in _tool_content(request)]},
    ]
    rows: list[dict[str, Any]] = []
    for level, value in zip(LEVELS, values):
        rows.append({
            "level": level,
            "side": side,
            "repetition": repetition,
            "trace_id": trace_id,
            "actual_next_model_request": level == "L4_MODEL_VISIBLE_OBSERVATION",
            "tool_input_digest": digest,
            "content": value,
        })
    return rows


def write_blind_evidence(record: dict[str, Any], output: Path, *, side: str, repetition: int, tool_input: Any) -> Path:
    rows = build_evidence_rows(record, side=side, repetition=repetition, tool_input=tool_input)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("a", encoding="utf-8") as stream:
        for row in rows:
            stream.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
    return output
