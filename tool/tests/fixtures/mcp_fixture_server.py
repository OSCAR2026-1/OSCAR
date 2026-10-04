"""Line-delimited JSON-RPC MCP fixture covering result projection cases."""

from __future__ import annotations

import base64
import json
import os
import sys
import time


PNG = base64.b64encode(b"\x89PNG\r\nfixture").decode("ascii")
WIRE_LOG = os.environ.get("OBSERVATION_FIXTURE_WIRE_LOG")


def log_wire(direction: str, message: object) -> None:
    if WIRE_LOG is None:
        return
    with open(WIRE_LOG, "a", encoding="utf-8") as stream:
        stream.write(json.dumps({"direction": direction, "message": message}, ensure_ascii=False) + "\n")


def response(request_id: object, result: object = None, error: object = None) -> dict[str, object]:
    value: dict[str, object] = {"jsonrpc": "2.0", "id": request_id}
    if error is not None:
        value["error"] = error
    else:
        value["result"] = result
    return value


def main() -> int:
    mode = sys.argv[1] if len(sys.argv) > 1 else "text"
    for line in sys.stdin:
        if not line.strip():
            continue
        request = json.loads(line)
        log_wire("request", request)
        method = request.get("method")
        request_id = request.get("id")
        if method == "initialize":
            result = {"protocolVersion": "2025-06-18", "capabilities": {}, "serverInfo": {"name": "observation-fixture", "version": "1"}}
        elif method == "tools/list":
            result = {"tools": [{"name": "probe", "description": f"fixture mode {mode}", "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False}}]}
        elif method == "tools/call":
            if mode in {"timeout", "cancel"}:
                time.sleep(5)
            elif mode == "structured":
                result = {"content": [{"type": "text", "text": "plain-result"}], "structuredContent": {"secret": "structured-value", "count": 1}}
            elif mode == "error":
                result = {"content": [{"type": "text", "text": "fixture failure"}], "isError": True}
            elif mode == "image":
                result = {"content": [{"type": "image", "mimeType": "image/png", "data": PNG}]}
            elif mode == "resource_link":
                result = {"content": [{"type": "resource_link", "name": "report", "uri": "file:///sandbox/report.json"}]}
            elif mode == "embedded_resource":
                result = {"content": [{"type": "resource", "resource": {"uri": "file:///sandbox/report.json", "text": "secret"}}]}
            elif mode == "malformed":
                result = {"content": [{"text": "missing-type"}]}
            else:
                result = {"content": [{"type": "text", "text": "plain-result"}]}
        else:
            if request_id is None:
                continue
            value = response(request_id, error={"code": -32601, "message": "method not found"})
            log_wire("response", value)
            sys.stdout.write(json.dumps(value, ensure_ascii=False) + "\n")
            sys.stdout.flush()
            continue
        if request_id is not None:
            value = response(request_id, result)
            log_wire("response", value)
            sys.stdout.write(json.dumps(value, ensure_ascii=False) + "\n")
            sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
