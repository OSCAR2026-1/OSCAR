"""Label-free shared Host projection used by RQ1 Evaluation replays.

The profile contains only transport/schema projection rules. It deliberately
does not load GT labels, effect tokens, annotations, or candidate metadata.
"""

from __future__ import annotations

import copy
import json
from typing import Any
from host_core import _sanitize as _sanitize_value


PROFILE_ID = "rq1-evaluation-sanitized-projection/v1"


def stable(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def text_blocks(content: Any) -> list[dict[str, Any]]:
    if not isinstance(content, list):
        return []
    return [
        copy.deepcopy(block)
        for block in content
        if isinstance(block, dict) and block.get("type") == "text"
    ]


def _nested_value(payload: Any, path: str) -> Any:
    value = payload
    for part in path.split("."):
        value = value.get(part) if isinstance(value, dict) else None
    return value


def project(normalized: dict[str, Any], profile: dict[str, Any]) -> dict[str, Any]:
    """Apply the declared Host projection to one normalized MCP result."""
    kind = profile["kind"]
    structured = normalized.get("structuredContent")
    content = normalized.get("content", [])

    if kind == "passthrough":
        result = copy.deepcopy(normalized)
        result.setdefault("isError", False)
        return result

    if kind == "credential_redaction":
        result = {
            "content": copy.deepcopy(content),
            "isError": normalized.get("isError") is True,
        }
        if "structuredContent" in normalized:
            result["structuredContent"] = copy.deepcopy(normalized["structuredContent"])
        return _sanitize_value(result)

    if kind == "image_content_to_diagnostic_text":
        return {
            "content": [
                {
                    "type": "text",
                    "text": f"[image unavailable: {block.get('mimeType', 'unknown')}; diagnostic projection]",
                }
                if isinstance(block, dict) and block.get("type") == "image"
                else copy.deepcopy(block)
                for block in content
            ],
            "isError": normalized.get("isError") is True,
        }

    if kind == "array_allowlist_truncation":
        items = structured.get("result", []) if isinstance(structured, dict) else []
        kept = copy.deepcopy(items[: int(profile["keep_items"])])
        result = {
            "content": [{"type": "text", "text": stable(item)} for item in kept],
            "structuredContent": {"result": kept},
            "isError": normalized.get("isError") is True,
        }
        return result

    if kind == "text_prefix_truncation":
        text = "\n".join(block.get("text", "") for block in text_blocks(content))
        result = {
            "content": [{"type": "text", "text": text[: int(profile["max_chars"])]}],
            "isError": normalized.get("isError") is True,
        }
        return result

    if kind == "nested_json_allowlist":
        payload = json.loads(structured["result"])
        allowed: dict[str, Any] = {}
        for path in profile["allow"]:
            parts = path.split(".")
            target = allowed
            for part in parts[:-1]:
                target = target.setdefault(part, {})
            target[parts[-1]] = copy.deepcopy(_nested_value(payload, path))
        value = {"result": allowed}
        return {
            "content": [{"type": "text", "text": stable(allowed)}],
            "structuredContent": value,
            "isError": normalized.get("isError") is True,
        }

    value = copy.deepcopy(structured) if isinstance(structured, dict) else {}
    drop = profile.get("drop")
    if kind == "nested_object_allowlist":
        result_value = value.get("result", {}) if isinstance(value.get("result"), dict) else {}
        value["result"] = {
            key: result_value[key]
            for key in profile["allow"]
            if key in result_value
        }
    elif isinstance(drop, list):
        for key in drop:
            value.pop(key, None)
            if isinstance(value.get("result"), dict):
                value["result"].pop(key, None)
    else:
        value.pop(str(drop), None)
        if isinstance(value.get("result"), dict):
            value["result"].pop(str(drop), None)
    return {
        "content": [{"type": "text", "text": stable(value)}],
        "structuredContent": value,
        "isError": normalized.get("isError") is True,
    }
