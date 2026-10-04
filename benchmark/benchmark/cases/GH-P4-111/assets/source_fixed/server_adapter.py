from __future__ import annotations

import asyncio
import json
import sys

sys.path.insert(0, "/workspace/source")

from tools.definitions.read_contract import read_contract, TOOL
from tools._internals._rpc_semaphore import init_rpc_semaphore


def result_text(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)


def reply(request_id: object, result: object) -> None:
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": request_id, "result": result}, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def main() -> int:
    init_rpc_semaphore(1)
    for line in sys.stdin:
        if not line.strip():
            continue
        message = json.loads(line)
        method = message.get("method")
        request_id = message.get("id")
        if method == "initialize":
            reply(request_id, {"protocolVersion": "2025-06-18", "capabilities": {"tools": {"listChanged": False}}, "serverInfo": {"name": "Teardrop", "version": "source-31c944b"}})
        elif method == "notifications/initialized":
            continue
        elif method == "tools/list":
            reply(request_id, {"tools": [{"name": TOOL.name, "description": TOOL.description, "inputSchema": TOOL.input_schema.model_json_schema()}]})
        elif method == "tools/call":
            arguments = (message.get("params") or {}).get("arguments") or {}
            try:
                value = asyncio.run(read_contract(**arguments))
                reply(request_id, {"content": [{"type": "text", "text": result_text(value)}], "structuredContent": value})
            except Exception as exc:  # The fixed side is expected to fail closed here.
                reply(request_id, {"content": [{"type": "text", "text": result_text({"error": type(exc).__name__, "detail": str(exc)})}], "isError": True})
        else:
            if request_id is not None:
                sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": request_id, "error": {"code": -32601, "message": "Method not found"}}) + "\n")
                sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
