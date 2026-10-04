"""Research-side MCP Host with explicit L0-L4 evidence recording."""

from __future__ import annotations

import hashlib
import json
import os
import queue
import re
import subprocess
import threading
import time
from pathlib import Path
from typing import Any

LEVELS = ("L0_RAW_MCP_RESULT", "L1_NORMALIZED_TOOL_RESULT", "L2_HOST_PROCESSED_TOOL_RESULT", "L3_SESSION_TOOL_RESULT", "L4_MODEL_VISIBLE_OBSERVATION")


def stable_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def sha256(value: Any) -> str:
    data = value if isinstance(value, bytes) else stable_json(value).encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def field_digest(value: Any) -> dict[str, Any]:
    encoded = stable_json(value).encode("utf-8")
    return {"bytes": len(encoded), "sha256": hashlib.sha256(encoded).hexdigest()}


def extract_text(content: list[Any]) -> str:
    parts: list[str] = []
    for block in content:
        if isinstance(block, dict) and block.get("type") == "text" and isinstance(block.get("text"), str):
            parts.append(block["text"])
        elif isinstance(block, dict) and block.get("type") == "resource_link":
            parts.append(f"[resource link: {block.get('name', '')} {block.get('uri', '')}]".strip())
        elif isinstance(block, dict) and block.get("type") == "resource":
            parts.append("[embedded resource unsupported; raw resource remains in L0]")
        elif isinstance(block, dict) and block.get("type") == "image":
            parts.append(f"[image unavailable: {block.get('mimeType', 'unknown')}; diagnostic projection]")
        elif isinstance(block, dict) and block.get("type") == "audio":
            parts.append(f"[audio unavailable: {block.get('mimeType', 'unknown')}; diagnostic projection]")
        else:
            parts.append("[malformed or unsupported MCP content block]")
    return "\n".join(parts) or "(tool returned no model-visible content)"


def normalize_result(result: Any) -> dict[str, Any]:
    if not isinstance(result, dict):
        return {"content": [{"type": "text", "text": f"[invalid MCP result: {type(result).__name__}]"}], "isError": True}
    if "__jsonrpc_error__" in result:
        error = result["__jsonrpc_error__"]
        return {
            "content": [{"type": "text", "text": json.dumps({"jsonrpc_error": error}, ensure_ascii=False)}],
            "isError": True,
            "jsonrpc_error": error,
        }
    content = result.get("content")
    if not isinstance(content, list):
        content = [{"type": "text", "text": json.dumps(result.get("toolResult", "(no output)"), ensure_ascii=False)}]
    normalized: dict[str, Any] = {"content": content}
    if "structuredContent" in result:
        normalized["structuredContent"] = result["structuredContent"]
    if result.get("isError") is True:
        normalized["isError"] = True
    return normalized


_AUTH_VALUE = re.compile(r"(?i)\b(?:basic|bearer)\s+[A-Za-z0-9._~+/=-]{8,}")
_NAMED_SECRET = re.compile(
    r"(?i)(\b(?:authorization|proxy-authorization|password|passwd|token|secret|credential|api[_-]?key)\b\s*[:=]\s*)([^\s<;,\"']+)"
)
_SENSITIVE_FIELD = re.compile(
    r"(?i)^(?:authorization|proxy-authorization|password|passwd|token|secret|credential|api[_-]?key)$"
)
_WORK14_READBACK = re.compile(
    r"\b(?:GT|GH|P[0-9]+|ORCHARD)(?:_[A-Z0-9]+)*_"
    r"(?:READBACK|SECRET|TOKEN|PASSWORD|CREDENTIAL|PRIVATE|VALUE)(?:_[A-Z0-9]+)*\b"
)
_WORK14_DATA_URI = re.compile(r"data:[^,\s;]+(?:;[^,\s]*)*;base64,[A-Za-z0-9+/=]+")
_WORK14_IMAGE_DATA = re.compile(r'("(?:image_data|data_uri)"\s*:\s*")[A-Za-z0-9+/=]+(")')
_WORK14_URL = re.compile(r"https?://[^\s'\"<>]+")


def load_host_profile(explicit: dict[str, Any] | None = None) -> dict[str, Any]:
    """Load the shared Host profile without consulting GT metadata."""
    if explicit is not None:
        return explicit
    profile_path = os.environ.get("SHARED_HOST_PROFILE", "")
    if not profile_path:
        return {}
    path = Path(profile_path)
    if not path.is_file():
        raise FileNotFoundError(f"shared Host profile is missing: {profile_path}")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("shared Host profile must be an object")
    return value


def _sanitize_text(value: str) -> str:
    value = _AUTH_VALUE.sub("[REDACTED]", value)
    return _NAMED_SECRET.sub(r"\1[REDACTED]", value)


def _work14_sanitize_text(value: str) -> str:
    value = _AUTH_VALUE.sub("[REDACTED]", value)
    value = _WORK14_DATA_URI.sub("[REDACTED_BINARY]", value)
    value = _WORK14_IMAGE_DATA.sub(r"\1[REDACTED_BINARY]\2", value)
    value = _WORK14_URL.sub("[URL_FILTERED]", value)
    return _WORK14_READBACK.sub("[REDACTED]", value)


def _sanitize(value: Any) -> Any:
    if isinstance(value, str):
        return _sanitize_text(value)
    if isinstance(value, list):
        return [_sanitize(item) for item in value]
    if isinstance(value, dict):
        return {
            key: "[REDACTED]" if _SENSITIVE_FIELD.fullmatch(str(key)) and isinstance(item, str) else _sanitize(item)
            for key, item in value.items()
        }
    return value


def _work14_sanitize(value: Any) -> Any:
    if isinstance(value, str):
        return _work14_sanitize_text(value)
    if isinstance(value, list):
        return [_work14_sanitize(item) for item in value]
    if isinstance(value, dict):
        return {
            key: "[REDACTED]"
            if _SENSITIVE_FIELD.fullmatch(str(key)) and isinstance(item, str)
            else _work14_sanitize(item)
            for key, item in value.items()
        }
    return value


def host_project(normalized: dict[str, Any], host_profile: dict[str, Any] | None = None) -> dict[str, Any]:
    content = normalized.get("content", [])
    text = extract_text(content if isinstance(content, list) else [])
    result: dict[str, Any] = {"content": [{"type": "text", "text": text}], "isError": normalized.get("isError") is True}
    if "structuredContent" in normalized:
        result["structuredContent"] = normalized["structuredContent"]
    profile = load_host_profile(host_profile)
    transformation = profile.get("transformation", {}) if isinstance(profile, dict) else {}
    if transformation.get("id") == "redact_basic_bearer_and_named_credential_values":
        return _sanitize(result)
    if transformation.get("id") == "work14_tool_result_sanitizing":
        return _work14_sanitize(result)
    return result


class StdioMcpClient:
    """Minimal newline-delimited JSON-RPC client with raw wire recording."""

    transport = "stdio"
    protocol_version = "2025-06-18"

    def __init__(self, command: list[str], cwd: Path, env: dict[str, str], timeout: float = 30.0) -> None:
        self.command, self.cwd, self.env, self.timeout = command, cwd, env, timeout
        self.proc: subprocess.Popen[str] | None = None
        self.next_id = 1
        self.responses: queue.Queue[dict[str, Any] | BaseException] = queue.Queue()
        self.stderr: list[str] = []
        self.wire: list[dict[str, Any]] = []
        self.reader_threads: list[threading.Thread] = []

    def __enter__(self) -> "StdioMcpClient":
        env = os.environ.copy()
        env.update(self.env)
        self.proc = subprocess.Popen(self.command, cwd=self.cwd, env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8", errors="replace", bufsize=1)
        self.reader_threads = [
            threading.Thread(target=self._read_stdout, daemon=True),
            threading.Thread(target=self._read_stderr, daemon=True),
        ]
        for thread in self.reader_threads:
            thread.start()
        return self

    def __exit__(self, *_: object) -> None:
        if self.proc is None:
            return
        # Close the JSON-RPC input first. Docker-backed stdio servers may keep
        # the CLI alive while stdin remains open, even after the server has
        # finished the last response.
        if self.proc.stdin is not None and not self.proc.stdin.closed:
            self.proc.stdin.close()
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=2)
        for thread in self.reader_threads:
            thread.join(timeout=2)
        for stream in (self.proc.stdout, self.proc.stderr):
            if stream is not None and not stream.closed:
                stream.close()

    def _read_stdout(self) -> None:
        assert self.proc and self.proc.stdout
        try:
            for line in self.proc.stdout:
                if line.strip():
                    value = json.loads(line)
                    self.wire.append({"direction": "response", "message": value, "time": time.time()})
                    self.responses.put(value)
        except BaseException as exc:
            self.responses.put(exc)

    def _read_stderr(self) -> None:
        assert self.proc and self.proc.stderr
        for line in self.proc.stderr:
            self.stderr.append(line)

    def _send(self, message: dict[str, Any]) -> None:
        assert self.proc and self.proc.stdin
        self.wire.append({"direction": "request", "message": message, "time": time.time()})
        self.proc.stdin.write(json.dumps(message, separators=(",", ":")) + "\n")
        self.proc.stdin.flush()

    def notify(self, method: str) -> None:
        self._send({"jsonrpc": "2.0", "method": method})

    def request(self, method: str, params: dict[str, Any] | None = None, *, allow_error: bool = False) -> Any:
        request_id = self.next_id
        self.next_id += 1
        message: dict[str, Any] = {"jsonrpc": "2.0", "id": request_id, "method": method}
        if params is not None:
            message["params"] = params
        self._send(message)
        deadline = time.monotonic() + self.timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(f"MCP timeout: {method}")
            item = self.responses.get(timeout=remaining)
            if isinstance(item, BaseException):
                raise RuntimeError(str(item))
            if item.get("id") != request_id:
                continue
            if "error" in item:
                if allow_error:
                    return {"__jsonrpc_error__": item["error"]}
                raise RuntimeError(json.dumps(item["error"], ensure_ascii=False))
            return item.get("result")


def build_model_request(system_prompt: str, tools: list[dict[str, Any]], task: str, call: dict[str, Any], tool_result: dict[str, Any]) -> dict[str, Any]:
    messages = [
        {"role": "user", "content": [{"type": "text", "text": task}]},
        {"role": "assistant", "content": [], "tool_calls": [{"id": call["id"], "type": "function", "function": {"name": call["name"], "arguments": stable_json(call["arguments"])}}]},
        {"role": "tool", "tool_call_id": call["id"], "content": tool_result.get("content", []), "isError": bool(tool_result.get("isError", False))},
    ]
    request = {"system": system_prompt, "tools": tools, "messages": messages, "temperature": 0, "reasoning_effort": "disabled"}
    request["request_sha256"] = sha256(request)
    return request


def client_context(*, transport: str, command: list[str], cwd: Path, env: dict[str, str],
                   timeout: float, endpoint: str | None = None,
                   headers: dict[str, str] | None = None, startup_timeout: float = 20.0,
                   stateless: bool = False) -> Any:
    if transport == "stdio":
        if endpoint is not None or headers:
            raise ValueError("stdio transport does not accept endpoint or HTTP headers")
        return StdioMcpClient(command, cwd, env, timeout=timeout)
    if not endpoint:
        raise ValueError(f"{transport} transport requires endpoint")
    from oscar.runtime.mcp_http_transport import LegacySseMcpClient, ManagedHttpMcpClient
    if transport == "streamable-http":
        return ManagedHttpMcpClient(command, cwd, env, endpoint, headers, timeout, startup_timeout, stateless)
    if transport == "sse":
        return LegacySseMcpClient(command, cwd, env, endpoint, headers, timeout, startup_timeout)
    raise ValueError(f"unsupported MCP transport: {transport}")


def run_host_case(*, run_id: str, gt_id: str, case_id: str, revision: str, repetition: int,
                  command: list[str], cwd: Path, env: dict[str, str], server_name: str,
                  tool_name: str, tool_arguments: dict[str, Any], task: str,
                  system_prompt: str, expected_effect: str | None = None,
                  server_revision: str | None = None, timeout: float = 30.0,
                  transport: str = "stdio", endpoint: str | None = None,
                  headers: dict[str, str] | None = None, startup_timeout: float = 20.0,
                  stateless: bool = False,
                  host_profile: dict[str, Any] | None = None) -> dict[str, Any]:
    started = time.time()
    call = {"id": "det-call-1", "name": tool_name, "arguments": tool_arguments}
    record: dict[str, Any] = {"schema_version": "agent-observation-record/v1", "run_id": run_id, "gt_id": gt_id, "case_id": case_id, "revision": revision, "repetition": repetition, "identity": {"server_name": server_name, "server_revision": server_revision, "transport": transport, "command": command, "endpoint": endpoint, "tool_name": tool_name}, "quality": {"invalid_run": False, "unexpected_exception": None, "timeout": False, "retries": 0, "reconnects": 0}, "evidence_levels": {level: "not_observed" for level in LEVELS}}
    try:
        with client_context(transport=transport, command=command, cwd=cwd, env=env, timeout=timeout,
                            endpoint=endpoint, headers=headers, startup_timeout=startup_timeout,
                            stateless=stateless) as client:
            initialize = client.request("initialize", {"protocolVersion": client.protocol_version, "capabilities": {}, "clientInfo": {"name": "agent-observation-research-host", "version": "1"}})
            client.notify("notifications/initialized")
            tools = client.request("tools/list", {})
            raw_result = client.request("tools/call", {"name": tool_name, "arguments": tool_arguments}, allow_error=True)
            normalized = normalize_result(raw_result)
            projected = host_project(normalized, host_profile)
            session_call = {"type": "tool/call", "turn": 1, "step": 1, "callId": call["id"], "name": tool_name, "arguments": stable_json(tool_arguments)}
            session_result = {"type": "tool/result", "turn": 1, "step": 1, "callId": call["id"], "message": {"role": "tool", "tool_call_id": call["id"], "content": projected["content"], "isError": projected["isError"]}}
            if "structuredContent" in projected:
                session_result["message"]["structuredContent"] = projected["structuredContent"]
            model_request = build_model_request(system_prompt, tools.get("tools", []) if isinstance(tools, dict) else [], task, call, projected)
            record.update({"mcp": {"transport": transport, "endpoint": endpoint, "initialize": initialize, "tools_list": tools, "raw_jsonrpc_requests": [item["message"] for item in client.wire if item["direction"] == "request"], "raw_jsonrpc_responses": [item["message"] for item in client.wire if item["direction"] == "response"], "raw_jsonrpc_response": raw_result, "normalized_result": normalized, "isError": bool(normalized.get("isError", False)), "content": normalized.get("content", []), "structuredContent": normalized.get("structuredContent"), "wire_log": client.wire, "stderr": "".join(client.stderr)}, "host": {"tool_runtime_result": projected, "processed_content": projected["content"], "external_state_before": {}, "external_state_after": {}, "expected_effect": expected_effect}, "session": {"tool_call": session_call, "tool_result": session_result, "request_header": {"system_prompt": system_prompt, "tools": tools.get("tools", []) if isinstance(tools, dict) else [], "temperature": 0, "reasoning_effort": "disabled"}}, "model": {"adapter": "deterministic", "initial_tool_call": call, "next_request": model_request, "final_response": {"role": "assistant", "content": [{"type": "text", "text": "Deterministic host completed the scripted tool call."}]}}, "observation": {"tool_client_visible": projected, "model_visible_request": model_request, "agent_level_triggered": False, "agent_level_status": "not_triggered_without_vulnerability_derived_state_in_L4", "vulnerability_derived_state_in_L4": False}, "finished_at": time.time()})
            record["evidence_levels"].update({level: "observed" for level in LEVELS})
    except TimeoutError as exc:
        record["quality"].update({"invalid_run": True, "timeout": True, "unexpected_exception": str(exc)})
    except Exception as exc:  # noqa: BLE001
        record["quality"].update({"invalid_run": True, "unexpected_exception": f"{type(exc).__name__}: {exc}"})
    record.setdefault("mcp", {"raw_jsonrpc_requests": [], "raw_jsonrpc_responses": [], "wire_log": []})
    record.setdefault("host", {"tool_runtime_result": None, "processed_content": [], "external_state_before": {}, "external_state_after": {}})
    record.setdefault("session", {"tool_call": None, "tool_result": None, "request_header": None})
    record.setdefault("model", {"adapter": "deterministic", "initial_tool_call": call, "next_request": None, "final_response": None})
    record.setdefault("observation", {"tool_client_visible": None, "model_visible_request": None, "agent_level_triggered": False, "agent_level_status": "invalid_run", "vulnerability_derived_state_in_L4": False})
    record["field_digests"] = {"record": field_digest(record)}
    record["duration_ms"] = round((time.time() - started) * 1000)
    return record
