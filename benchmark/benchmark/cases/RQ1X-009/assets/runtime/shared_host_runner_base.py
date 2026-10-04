"""Neutral shared Host API used by GT and VulVeil runs.

The implementation is kept behind this module so both workflows use the same
MCP stdio lifecycle and L0-L4 projection. ``host_core.py`` remains a
compatibility module for historical scripts.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from host_core import (  # noqa: F401
    LEVELS,
    StdioMcpClient,
    build_model_request,
    client_context,
    extract_text,
    field_digest,
    host_project,
    load_host_profile,
    normalize_result,
    sha256,
    stable_json,
)
from host_core import run_host_case as _legacy_run_host_case


SHARED_HOST_RUNNER_VERSION = "shared-research-host/v1"
SHARED_HOST_RUNNER_FILE = Path(__file__).resolve()
SHARED_HOST_CORE_FILE = SHARED_HOST_RUNNER_FILE.with_name("host_core.py")
_host_digest = hashlib.sha256()
for _source_file in (SHARED_HOST_RUNNER_FILE, SHARED_HOST_CORE_FILE):
    _host_digest.update(_source_file.name.encode("utf-8"))
    _host_digest.update(_source_file.read_bytes())
SHARED_HOST_RUNNER_SHA256 = _host_digest.hexdigest()


def run_shared_host_case(
    *,
    run_id: str,
    case_id: str,
    revision: str,
    repetition: int,
    command: list[str],
    cwd: Path,
    env: dict[str, str],
    server_name: str,
    tool_name: str,
    tool_arguments: dict[str, Any],
    tool_calls: list[dict[str, Any]] | None = None,
    task: str,
    system_prompt: str,
    server_revision: str | None = None,
    timeout: float = 30.0,
    gt_id: str | None = None,
    transport: str = "stdio",
    endpoint: str | None = None,
    headers: dict[str, str] | None = None,
    startup_timeout: float = 20.0,
    stateless: bool = False,
    host_profile: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Run one deterministic MCP Host case with optional GT-only provenance."""
    effective_profile = load_host_profile(host_profile)
    if not tool_calls:
        record = _legacy_run_host_case(
        run_id=run_id,
        gt_id=gt_id or "",
        case_id=case_id,
        revision=revision,
        repetition=repetition,
        command=command,
        cwd=cwd,
        env=env,
        server_name=server_name,
        tool_name=tool_name,
        tool_arguments=tool_arguments,
        task=task,
        system_prompt=system_prompt,
        server_revision=server_revision,
            timeout=timeout,
            transport=transport,
            endpoint=endpoint,
            headers=headers,
            startup_timeout=startup_timeout,
            stateless=stateless,
            host_profile=effective_profile,
        )
    else:
        record = _run_shared_tool_sequence(
            run_id=run_id,
            case_id=case_id,
            revision=revision,
            repetition=repetition,
            command=command,
            cwd=cwd,
            env=env,
            server_name=server_name,
            tool_calls=tool_calls,
            task=task,
            system_prompt=system_prompt,
            server_revision=server_revision,
            timeout=timeout,
            transport=transport,
            endpoint=endpoint,
            headers=headers,
            startup_timeout=startup_timeout,
            stateless=stateless,
            host_profile=effective_profile,
        )
    if gt_id is None:
        record.pop("gt_id", None)
    _set_deterministic_final_response(record)
    record["host_runner"] = {
        "implementation": SHARED_HOST_RUNNER_VERSION,
        "source_sha256": SHARED_HOST_RUNNER_SHA256,
        "transport": transport,
        "model_provider": "cli-mock",
        "model": "cli-mock",
        "temperature": 0,
        "reasoning_effort": "disabled",
    }
    if effective_profile:
        record["host_profile"] = {
            "profile_id": effective_profile.get("profile_id"),
            "profile_sha256": hashlib.sha256(stable_json(effective_profile).encode("utf-8")).hexdigest(),
        }
        record.setdefault("host", {})["transformation"] = {
            "policy": effective_profile.get("transformation", {}).get("id"),
            "boundary": "L1_NORMALIZED_TOOL_RESULT -> L2_HOST_PROCESSED_TOOL_RESULT",
            "replacement": effective_profile.get("transformation", {}).get("replacement"),
            "structured_content_policy": "recursive_same_policy",
        }
    return record


def _set_deterministic_final_response(record: dict[str, Any]) -> None:
    projected = record.get("host", {}).get("tool_runtime_result", {})
    content = projected.get("content", []) if isinstance(projected, dict) else []
    text = extract_text(content if isinstance(content, list) else [])
    structured = projected.get("structuredContent") if isinstance(projected, dict) else None
    structured_text = "none" if structured is None else json.dumps(structured, ensure_ascii=False, sort_keys=True)
    final_text = f"MCP result text={text}; structured={structured_text}"
    record.setdefault("model", {})["final_response"] = {
        "role": "assistant",
        "content": [{"type": "text", "text": final_text}],
    }
    record.setdefault("observation", {})["final_model_text"] = final_text


# Compatibility name for GT adapters that already use a Host runner function.
run_host_case = run_shared_host_case


def _run_shared_tool_sequence(
    *,
    run_id: str,
    case_id: str,
    revision: str,
    repetition: int,
    command: list[str],
    cwd: Path,
    env: dict[str, str],
    server_name: str,
    tool_calls: list[dict[str, Any]],
    task: str,
    system_prompt: str,
    server_revision: str | None,
    timeout: float,
    transport: str,
    endpoint: str | None,
    headers: dict[str, str] | None,
    startup_timeout: float,
    stateless: bool,
    host_profile: dict[str, Any],
) -> dict[str, Any]:
    import time

    started = time.time()
    record: dict[str, Any] = {
        "schema_version": "agent-observation-record/v1",
        "run_id": run_id,
        "case_id": case_id,
        "revision": revision,
        "repetition": repetition,
        "identity": {"server_name": server_name, "server_revision": server_revision, "transport": transport, "command": command, "endpoint": endpoint, "tool_name": [call["name"] for call in tool_calls]},
        "quality": {"invalid_run": False, "unexpected_exception": None, "timeout": False, "retries": 0, "reconnects": 0},
        "evidence_levels": {level: "not_observed" for level in LEVELS},
    }
    try:
        with client_context(transport=transport, command=command, cwd=cwd, env=env, timeout=timeout,
                            endpoint=endpoint, headers=headers, startup_timeout=startup_timeout,
                            stateless=stateless) as client:
            initialize = client.request("initialize", {"protocolVersion": client.protocol_version, "capabilities": {}, "clientInfo": {"name": "agent-observation-research-host", "version": "1"}})
            client.notify("notifications/initialized")
            tools = client.request("tools/list", {})
            assistant_calls = []
            tool_messages = []
            raw_results = []
            normalized_results = []
            projected_results = []
            resolved_calls = []
            for index, item in enumerate(tool_calls, start=1):
                call_arguments = _resolve_runtime_placeholders(item.get("arguments", {}), projected_results)
                call = {"id": f"det-call-{index}", "name": item["name"], "arguments": call_arguments}
                resolved_calls.append(call)
                raw_result = client.request("tools/call", {"name": call["name"], "arguments": call["arguments"]}, allow_error=True)
                normalized = normalize_result(raw_result)
                projected = host_project(normalized, host_profile)
                assistant_calls.append({"id": call["id"], "type": "function", "function": {"name": call["name"], "arguments": stable_json(call["arguments"])}})
                tool_messages.append({"role": "tool", "tool_call_id": call["id"], "content": projected.get("content", []), "isError": bool(projected.get("isError", False))})
                raw_results.append(raw_result)
                normalized_results.append(normalized)
                projected_results.append(projected)
            tool_calls = resolved_calls
            messages = [
                {"role": "user", "content": [{"type": "text", "text": task}]},
                {"role": "assistant", "content": [], "tool_calls": assistant_calls},
                *tool_messages,
            ]
            request = {"system": system_prompt, "tools": tools.get("tools", []) if isinstance(tools, dict) else [], "messages": messages, "temperature": 0, "reasoning_effort": "disabled"}
            request["request_sha256"] = sha256(request)
            last_projected = projected_results[-1] if projected_results else {"content": [], "isError": True}
            record.update({"mcp": {"transport": transport, "endpoint": endpoint, "initialize": initialize, "tools_list": tools, "raw_results": raw_results, "normalized_results": normalized_results, "raw_jsonrpc_requests": [item["message"] for item in client.wire if item["direction"] == "request"], "raw_jsonrpc_responses": [item["message"] for item in client.wire if item["direction"] == "response"], "wire_log": client.wire, "stderr": "".join(client.stderr)}, "host": {"tool_runtime_result": last_projected, "processed_content": last_projected.get("content", []), "external_state_before": {}, "external_state_after": {}}, "session": {"tool_calls": [{"type": "tool/call", "turn": 1, "step": index + 1, "callId": f"det-call-{index}", "name": call["name"], "arguments": stable_json(call["arguments"])} for index, call in enumerate(tool_calls)], "tool_results": tool_messages, "request_header": {"system_prompt": system_prompt, "tools": tools.get("tools", []) if isinstance(tools, dict) else [], "temperature": 0, "reasoning_effort": "disabled"}}, "model": {"adapter": "deterministic", "initial_tool_calls": assistant_calls, "next_request": request, "final_response": {"role": "assistant", "content": [{"type": "text", "text": "Deterministic host completed the scripted tool call."}]}}, "observation": {"tool_client_visible": last_projected, "model_visible_request": request}, "finished_at": time.time()})
            record["evidence_levels"].update({level: "observed" for level in LEVELS})
    except TimeoutError as exc:
        record["quality"].update({"invalid_run": True, "timeout": True, "unexpected_exception": str(exc)})
    except Exception as exc:  # noqa: BLE001
        record["quality"].update({"invalid_run": True, "unexpected_exception": f"{type(exc).__name__}: {exc}"})
    record.setdefault("mcp", {"raw_jsonrpc_requests": [], "raw_jsonrpc_responses": [], "wire_log": []})
    record.setdefault("host", {"tool_runtime_result": None, "processed_content": [], "external_state_before": {}, "external_state_after": {}})
    record.setdefault("session", {"tool_calls": [], "tool_results": [], "request_header": None})
    record.setdefault("model", {"adapter": "deterministic", "initial_tool_calls": [], "next_request": None, "final_response": None})
    record.setdefault("observation", {"tool_client_visible": None, "model_visible_request": None})
    record["field_digests"] = {"record": field_digest(record)}
    _set_deterministic_final_response(record)
    record["field_digests"] = {"record": field_digest(record)}
    record["duration_ms"] = round((time.time() - started) * 1000)
    return record


def _resolve_runtime_placeholders(value: Any, projected_results: list[dict[str, Any]]) -> Any:
    """Resolve data-only values produced by an earlier scripted Tool result."""
    if isinstance(value, str):
        if value != "{FLOW_ID_FROM_LAST_RESULT}":
            return value
        if not projected_results:
            raise ValueError("FLOW_ID_FROM_LAST_RESULT requires a preceding Tool result")
        for projected in reversed(projected_results):
            text = extract_text(projected.get("content", []))
            try:
                payload = json.loads(text)
            except json.JSONDecodeError:
                continue
            candidates = payload if isinstance(payload, list) else [payload]
            for candidate in candidates:
                if isinstance(candidate, dict) and candidate.get("id"):
                    return str(candidate["id"])
        raise ValueError("preceding Tool results contain no flow id")
    if isinstance(value, list):
        return [_resolve_runtime_placeholders(item, projected_results) for item in value]
    if isinstance(value, dict):
        return {key: _resolve_runtime_placeholders(item, projected_results) for key, item in value.items()}
    return value


def evidence_rows(record: dict[str, Any]) -> list[dict[str, Any]]:
    """Project a full Host record into the blind L0-L4 evidence contract."""
    mcp = record.get("mcp", {})
    host = record.get("host", {})
    session = record.get("session", {})
    model = record.get("model", {})
    request = model.get("next_request", {})
    final_text = json.dumps(request, ensure_ascii=False, sort_keys=True)
    rows = [
        {"level": "L0_RAW_MCP_RESULT", "content": mcp.get("raw_jsonrpc_response", mcp.get("raw_results")), "anchor_reached": record.get("quality", {}).get("invalid_run") is False},
        {"level": "L1_NORMALIZED_TOOL_RESULT", "content": mcp.get("normalized_result", mcp.get("normalized_results")), "anchor_reached": record.get("quality", {}).get("invalid_run") is False},
        {"level": "L2_HOST_PROCESSED_TOOL_RESULT", "content": host.get("tool_runtime_result"), "anchor_reached": record.get("quality", {}).get("invalid_run") is False},
        {"level": "L3_SESSION_TOOL_RESULT", "content": session.get("tool_result", session.get("tool_results")), "anchor_reached": record.get("quality", {}).get("invalid_run") is False},
        {"level": "L4_MODEL_VISIBLE_OBSERVATION", "text": final_text, "content": model.get("next_request"), "anchor_reached": record.get("quality", {}).get("invalid_run") is False},
    ]
    # External/resource witnesses are declared by a case runner's neutral
    # runtime oracle.  Preserve only the oracle contract and its event; secret
    # values and evaluator annotations never enter the blind evidence.
    boundary = record.get("external_boundary")
    oracle = boundary.get("oracle") if isinstance(boundary, dict) else None
    if isinstance(oracle, dict):
        rows.append({
            "level": "SERVER_OR_EXTERNAL_EFFECT",
            "anchor_reached": record.get("quality", {}).get("invalid_run") is False,
            "event": oracle.get("effect_event"),
            "oracle": {key: value for key, value in oracle.items() if key != "effect_event"},
        })
    return rows
